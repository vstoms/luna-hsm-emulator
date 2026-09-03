"""Partition lifecycle and role-state persistence."""

import json

from pkcs11.constants import PKCS11Error, CKR_ACTION_PROHIBITED, CKR_TOKEN_NOT_PRESENT

PARTITION_PPSO = "PPSO"
PARTITION_LEGACY = "LEGACY"
VALID_PARTITION_TYPES = {PARTITION_PPSO, PARTITION_LEGACY}
ROLES = ("SO", "CO", "CU")


class PartitionLifecycleManager:
    """Tracks state not represented by the legacy partitions SQL schema."""

    META_KEY = "partition_lifecycle"

    def __init__(self, storage):
        self.storage = storage

    def _load(self) -> dict:
        raw = self.storage.get_meta(self.META_KEY)
        if raw:
            try:
                return json.loads(raw)
            except (TypeError, json.JSONDecodeError):
                pass
        return {}

    def _save(self, state: dict):
        self.storage.set_meta(self.META_KEY, json.dumps(state))

    def register(self, slot_id: int, partition_type: str = PARTITION_PPSO):
        partition_type = partition_type.upper()
        if partition_type not in VALID_PARTITION_TYPES:
            raise PKCS11Error(CKR_ACTION_PROHIBITED,
                              "Partition type must be PPSO or legacy")
        state = self._load()
        state[str(slot_id)] = {
            "type": partition_type,
            "active": True,
            "domain_initialized": True,
            "roles": {role: {"active": False} for role in ROLES},
        }
        self._save(state)

    def remove(self, slot_id: int):
        state = self._load()
        state.pop(str(slot_id), None)
        self._save(state)

    def _entry(self, slot_id: int) -> dict:
        partition = self.storage.get_partition(slot_id)
        if partition is None:
            raise PKCS11Error(CKR_TOKEN_NOT_PRESENT, f"Slot {slot_id} not found")
        state = self._load()
        key = str(slot_id)
        if key not in state:
            # Existing databases predate lifecycle metadata and behave as PPSO.
            state[key] = {
                "type": PARTITION_PPSO,
                "active": True,
                "domain_initialized": True,
                "roles": {role: {"active": bool(partition.get(f"{role.lower()}_pin_hash"))}
                          for role in ROLES},
            }
            self._save(state)
        return state[key]

    def partition_type(self, slot_id: int) -> str:
        return self._entry(slot_id)["type"]

    def set_partition_initialized(self, slot_id: int):
        entry = self._entry(slot_id)
        state = self._load()
        state[str(slot_id)] = entry
        self._save(state)

    def set_partition_active(self, slot_id: int, active: bool):
        entry = self._entry(slot_id)
        entry["active"] = bool(active)
        state = self._load()
        state[str(slot_id)] = entry
        self._save(state)

    def set_domain_initialized(self, slot_id: int, initialized: bool = True):
        entry = self._entry(slot_id)
        entry["domain_initialized"] = bool(initialized)
        state = self._load()
        state[str(slot_id)] = entry
        self._save(state)

    def set_role_active(self, slot_id: int, role: str, active: bool):
        role = role.upper()
        entry = self._entry(slot_id)
        entry["roles"].setdefault(role, {})["active"] = bool(active)
        state = self._load()
        state[str(slot_id)] = entry
        self._save(state)

    def role_active(self, slot_id: int, role: str) -> bool:
        return bool(self._entry(slot_id)["roles"].get(role.upper(), {}).get("active"))

    def status(self, slot_id: int) -> dict:
        partition = self.storage.get_partition(slot_id)
        if partition is None:
            raise PKCS11Error(CKR_TOKEN_NOT_PRESENT, f"Slot {slot_id} not found")
        entry = self._entry(slot_id)
        ptype = entry["type"]
        roles = {}
        for role in ROLES:
            prefix = role.lower()
            # Legacy partitions have no independent Partition SO identity.
            supported = not (ptype == PARTITION_LEGACY and role == "SO")
            initialized = supported and bool(partition.get(f"{prefix}_pin_hash"))
            locked = supported and bool(partition.get(f"{prefix}_locked", 0))
            active = initialized and bool(entry["roles"].get(role, {}).get("active"))
            if not supported:
                role_state = "NOT_APPLICABLE"
            elif not initialized:
                role_state = "UNINITIALIZED"
            elif locked:
                role_state = "LOCKED"
            elif not active:
                role_state = "DEACTIVATED"
            else:
                role_state = "ACTIVE"
            roles[role] = {
                "supported": supported,
                "initialized": initialized,
                "active": active,
                "locked": locked,
                "failed_attempts": partition.get(f"{prefix}_login_attempts", 0),
                "state": role_state,
            }

        if not partition["initialized"]:
            lifecycle_state = "UNINITIALIZED"
        elif not entry.get("active", True):
            lifecycle_state = "DEACTIVATED"
        else:
            required = ("CO",) if ptype == PARTITION_LEGACY else ("SO", "CO")
            lifecycle_state = ("READY" if all(roles[r]["initialized"] for r in required)
                               and entry.get("domain_initialized", False)
                               else "INITIALIZED_ROLES_PENDING")
        return {
            "state": lifecycle_state,
            "type": ptype,
            "active": bool(entry.get("active", True)),
            "domain_initialized": bool(entry.get("domain_initialized", False)),
            "roles": roles,
        }
