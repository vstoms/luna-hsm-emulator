"""Token / partition management for the Luna 7 HSM emulator.

A "token" in PKCS#11 terms corresponds to a Luna "partition" — a
logical container on the HSM that holds keys and objects with its own
authentication, storage quotas, and audit log.
"""

import time
import os
import hashlib
from typing import Optional

from storage.db import Storage
from pkcs11.constants import (
    PKCS11Error, CKR_TOKEN_NOT_PRESENT, CKR_TOKEN_WRITE_PROTECTED,
    CKR_TOKEN_NOT_RECOGNIZED, CKR_SESSION_READ_ONLY,
    CKF_TOKEN_INITIALIZED, CKF_LOGIN_REQUIRED, CKF_RNG,
)
from hsm.auth import AuthManager, ROLE_CO, ROLE_CU, ROLE_SO

# Luna 7 simulated firmware/model info
HSM_MODEL = "Luna Network HSM 7"
HSM_FIRMWARE = "7.13.0"
HSM_SERIAL_PREFIX = "L7"
HSM_MAX_PARTITIONS = 100


class TokenManager:
    """Manages partitions (slots) on the emulated HSM."""

    def __init__(self, storage: Storage, auth: AuthManager):
        self.storage = storage
        self.auth = auth
        self._next_slot = 1

    def _generate_serial(self) -> str:
        """Generate a deterministic serial from the DB path."""
        h = hashlib.sha256(self.storage.db_path.encode()).hexdigest()[:8].upper()
        return f"{HSM_SERIAL_PREFIX}-{h}"

    def get_hsm_info(self) -> dict:
        """Return HSM-level information."""
        return {
            "model": HSM_MODEL,
            "firmware": HSM_FIRMWARE,
            "serial": self._generate_serial(),
            "max_partitions": HSM_MAX_PARTITIONS,
            "partition_count": len(self.storage.get_all_partitions()),
        }

    def list_slots(self) -> list:
        """Return a list of all slot IDs."""
        return [p["slot_id"] for p in self.storage.get_all_partitions()]

    def get_slot_info(self, slot_id: int) -> dict:
        """Return slot-level info."""
        p = self.storage.get_partition(slot_id)
        if p is None:
            raise PKCS11Error(CKR_TOKEN_NOT_PRESENT, f"Slot {slot_id} not found")
        return {
            "slot_id": slot_id,
            "description": f"Luna Partition {p['name']}",
            "manufacturer": "Thales",
            "hardware": "Luna 7",
            "firmware": HSM_FIRMWARE,
            "flags": 7,  # CKF_TOKEN_PRESENT | CKF_HW_SLOT | CKF_REMOVABLE_DEVICE
        }

    def get_token_info(self, slot_id: int) -> dict:
        """Return token (partition) info."""
        p = self.storage.get_partition(slot_id)
        if p is None:
            raise PKCS11Error(CKR_TOKEN_NOT_PRESENT, f"Slot {slot_id} not found")
        flags = 0
        if p["initialized"]:
            flags |= CKF_TOKEN_INITIALIZED
        flags |= CKF_LOGIN_REQUIRED
        flags |= CKF_RNG
        obj_count = self.storage.count_objects(slot_id)
        return {
            "label": p.get("label") or p["name"],
            "manufacturer": "Thales",
            "model": HSM_MODEL,
            "serial": self._generate_serial(),
            "flags": flags,
            "max_session_count": 16,
            "session_count": 0,
            "max_rw_session_count": 8,
            "rw_session_count": 0,
            "max_pin_len": 32,
            "min_pin_len": 4,
            "total_public_memory": p["max_storage"],
            "free_public_memory": p["max_storage"] - (obj_count * 256),
            "total_private_memory": p["max_storage"],
            "free_private_memory": p["max_storage"] - (obj_count * 256),
            "hardware_version": HSM_FIRMWARE,
            "firmware_version": HSM_FIRMWARE,
            "object_count": obj_count,
            "max_objects": p["max_objects"],
        }

    def create_partition(self, name: str, label: str = None,
                         max_objects: int = 1024,
                         max_storage: int = 1048576,
                         max_login_attempts: int = 10) -> int:
        """Create a new partition. Returns the slot ID."""
        if self.storage.get_partition_by_name(name):
            raise PKCS11Error(CKR_TOKEN_NOT_RECOGNIZED,
                              f"Partition '{name}' already exists")
        partitions = self.storage.get_all_partitions()
        if len(partitions) >= HSM_MAX_PARTITIONS:
            raise PKCS11Error(CKR_TOKEN_NOT_PRESENT, "Maximum partition count reached")
        # Find next available slot ID
        used_slots = {p["slot_id"] for p in partitions}
        slot_id = 1
        while slot_id in used_slots:
            slot_id += 1
        self.storage.insert_partition(
            slot_id=slot_id, name=name, label=label or name,
            max_objects=max_objects, max_storage=max_storage,
            max_login_attempts=max_login_attempts,
        )
        return slot_id

    def delete_partition(self, name: str):
        """Delete a partition by name."""
        p = self.storage.get_partition_by_name(name)
        if p is None:
            raise PKCS11Error(CKR_TOKEN_NOT_PRESENT, f"Partition '{name}' not found")
        self.storage.delete_partition(p["slot_id"])

    def init_token(self, slot_id: int, so_pin: str, label: str = None):
        """Initialize a token (partition) — sets the SO PIN and label."""
        p = self.storage.get_partition(slot_id)
        if p is None:
            raise PKCS11Error(CKR_TOKEN_NOT_PRESENT, f"Slot {slot_id} not found")
        self.auth.set_pin(slot_id, ROLE_SO, so_pin)
        updates = {"initialized": 1}
        if label:
            updates["label"] = label
        self.storage.update_partition(slot_id, **updates)

    def init_pin(self, slot_id: int, user_pin: str, role: str = ROLE_CO):
        """Initialize the PIN for a user role (CO or CU)."""
        p = self.storage.get_partition(slot_id)
        if p is None:
            raise PKCS11Error(CKR_TOKEN_NOT_PRESENT)
        if role not in (ROLE_CO, ROLE_CU):
            raise PKCS11Error(CKR_TOKEN_NOT_RECOGNIZED, "InitPIN only for CO or CU roles")
        self.auth.set_pin(slot_id, role, user_pin)

    def show_partition_info(self, slot_id: int) -> str:
        """Return a formatted string with partition details."""
        p = self.storage.get_partition(slot_id)
        if p is None:
            return f"  Slot {slot_id}: No partition present"
        obj_count = self.storage.count_objects(slot_id)
        info = self.get_token_info(slot_id)
        lines = [
            f"  Slot ID:          {slot_id}",
            f"  Partition Name:   {p['name']}",
            f"  Label:            {p.get('label', '')}",
            f"  Initialized:      {'Yes' if p['initialized'] else 'No'}",
            f"  Object Count:     {obj_count} / {p['max_objects']}",
            f"  Storage Used:     ~{obj_count * 256} bytes / {p['max_storage']} bytes",
            f"  Max Login Attempts: {p['max_login_attempts']}",
            f"  SO Locked:        {'Yes' if p['so_locked'] else 'No'}",
            f"  CO Locked:        {'Yes' if p['co_locked'] else 'No'}",
            f"  CU Locked:        {'Yes' if p['cu_locked'] else 'No'}",
            f"  Created:          {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(p['created_at']))}",
        ]
        return "\n".join(lines)

    def list_partitions(self) -> str:
        """Return a formatted list of all partitions."""
        partitions = self.storage.get_all_partitions()
        if not partitions:
            return "  No partitions configured. Use 'partition create' to create one."
        lines = [
            f"  {'Slot':<6} {'Name':<20} {'Label':<20} {'Init':<6} {'Objects':<10} {'SO':<4} {'CO':<4} {'CU':<4}",
            "  " + "-" * 80,
        ]
        for p in partitions:
            obj_count = self.storage.count_objects(p["slot_id"])
            init = "Yes" if p["initialized"] else "No"
            so = "L" if p["so_locked"] else "-"
            co = "L" if p["co_locked"] else "-"
            cu = "L" if p["cu_locked"] else "-"
            lines.append(
                f"  {p['slot_id']:<6} {p['name']:<20} {p.get('label', ''):<20} "
                f"{init:<6} {obj_count:<10} {so:<4} {co:<4} {cu:<4}"
            )
        return "\n".join(lines)

    def factory_reset(self):
        """Reset the HSM to factory defaults — delete all partitions and objects."""
        for p in self.storage.get_all_partitions():
            self.storage.delete_partition(p["slot_id"])
        self.storage.clear_audit_logs()
