"""Token / partition management for the Luna 7 HSM emulator.

A "token" in PKCS#11 terms corresponds to a Luna "partition" — a
logical container on the HSM that holds keys and objects with its own
authentication, storage quotas, and audit log.
"""

import time
import os
import json
import secrets
import hashlib
import re
from typing import Optional

from storage.db import Storage
from pkcs11.constants import (
    PKCS11Error, CKR_TOKEN_NOT_PRESENT, CKR_TOKEN_WRITE_PROTECTED,
    CKR_TOKEN_NOT_RECOGNIZED, CKR_SESSION_READ_ONLY,
    CKF_TOKEN_INITIALIZED, CKF_LOGIN_REQUIRED, CKF_RNG,
    CKR_ACTION_PROHIBITED, CKR_ARGUMENTS_BAD, CKR_USER_PIN_NOT_INITIALIZED,
)
from hsm.auth import AuthManager, ROLE_CO, ROLE_LCO, ROLE_CU, ROLE_SO
from hsm.domain import CloningDomainManager
from hsm.lifecycle import PartitionLifecycleManager, PARTITION_PPSO, PARTITION_LEGACY
from hsm.hsm_state import HSMStateManager
from hsm.sks import SKSManager

# Luna 7 simulated hardware model
HSM_MODEL = "Luna Network HSM 7"
HSM_SERIAL_PREFIX = "L7"
HSM_MAX_PARTITIONS = 100

# Default firmware version (used when no DB value exists yet)
DEFAULT_FIRMWARE = "7.13.0"

# Available firmware versions for upgrade, in release order
AVAILABLE_FIRMWARES = [
    {"version": "7.11.0", "date": "2024-06-15", "notes": "Initial Luna 7 firmware release."},
    {"version": "7.12.0", "date": "2024-11-20", "notes": "Added AES-GCM support improvements and bug fixes."},
    {"version": "7.12.1", "date": "2025-01-10", "notes": "Security patch: CVE-2024-1401 side-channel mitigation."},
    {"version": "7.13.0", "date": "2025-04-03", "notes": "Added P-521 curve support, improved audit logging."},
    {"version": "7.13.1", "date": "2025-06-18", "notes": "Hotfix: partition quota calculation fix."},
    {"version": "7.14.0", "date": "2025-09-01", "notes": "Added secp256k1 curve, SP800-108 KDF, performance improvements."},
    {"version": "7.14.1", "date": "2025-10-15", "notes": "Patch: HMAC verification edge-case fix."},
    {"version": "7.15.0", "date": "2026-01-20", "notes": "New: HKDF support, enhanced PED simulation, RSA-4096 optimization."},
    {"version": "7.15.1", "date": "2026-03-05", "notes": "Security patch: updated OpenSSL backend to 3.4.x."},
    {"version": "7.16.0", "date": "2026-06-12", "notes": "Added CMAC-AES, multi-session concurrency improvements."},
]


def _parse_version(v: str) -> tuple:
    """Parse a semantic version string into a comparable tuple."""
    parts = re.findall(r"\d+", v)
    return tuple(int(x) for x in parts)


def _compare_versions(a: str, b: str) -> int:
    """Return -1 if a<b, 0 if a==b, 1 if a>b."""
    ta, tb = _parse_version(a), _parse_version(b)
    # Pad shorter tuple with zeros
    while len(ta) < len(tb):
        ta += (0,)
    while len(tb) < len(ta):
        tb += (0,)
    if ta < tb:
        return -1
    elif ta > tb:
        return 1
    return 0


class TokenManager:
    """Manages partitions (slots) on the emulated HSM."""

    def __init__(self, storage: Storage, auth: AuthManager):
        self.storage = storage
        self.auth = auth
        self.domains = CloningDomainManager(storage)
        self.lifecycle = PartitionLifecycleManager(storage)
        self.sks = SKSManager(storage, self.lifecycle)
        self._next_slot = 1

    def _generate_serial(self) -> str:
        """Generate a deterministic serial from the DB path."""
        h = hashlib.sha256(self.storage.db_path.encode()).hexdigest()[:8].upper()
        return f"{HSM_SERIAL_PREFIX}-{h}"

    def _get_firmware_version(self) -> str:
        """Return the current firmware version from the DB, or the default."""
        v = self.storage.get_meta("firmware_version")
        return v or DEFAULT_FIRMWARE

    def _set_firmware_version(self, version: str):
        """Persist the firmware version to the DB."""
        self.storage.set_meta("firmware_version", version)

    def _get_firmware_history(self) -> list:
        """Return the firmware upgrade history from the DB."""
        import json
        raw = self.storage.get_meta("firmware_history")
        if raw:
            try:
                return json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                return []
        return []

    def _add_firmware_history(self, entry: dict):
        """Append an entry to the firmware upgrade history."""
        import json
        history = self._get_firmware_history()
        history.append(entry)
        self.storage.set_meta("firmware_history", json.dumps(history))

    def get_hsm_info(self) -> dict:
        """Return HSM-level information."""
        fw = self._get_firmware_version()
        return {
            "model": HSM_MODEL,
            "firmware": fw,
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
            "firmware": self._get_firmware_version(),
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
        storage_used = self.storage.get_partition_storage_used(slot_id)
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
            "free_public_memory": max(0, p["max_storage"] - storage_used),
            "total_private_memory": p["max_storage"],
            "free_private_memory": max(0, p["max_storage"] - storage_used),
            "hardware_version": self._get_firmware_version(),
            "firmware_version": self._get_firmware_version(),
            "object_count": obj_count,
            "max_objects": p["max_objects"],
        }

    def create_partition(self, name: str, label: str = None,
                         max_objects: int = 1024,
                         max_storage: int = 1048576,
                         max_login_attempts: int = 10,
                         partition_type: str = PARTITION_PPSO,
                         version: int = 0) -> int:
        """Create a new partition. Returns the slot ID."""
        if self.storage.get_partition_by_name(name):
            raise PKCS11Error(CKR_TOKEN_NOT_RECOGNIZED,
                              f"Partition '{name}' already exists")
        if max_objects < 1 or max_storage < 1:
            raise PKCS11Error(CKR_ARGUMENTS_BAD,
                              "Partition object and storage quotas must be positive")
        partitions = self.storage.get_all_partitions()
        if len(partitions) >= HSM_MAX_PARTITIONS:
            raise PKCS11Error(CKR_TOKEN_NOT_PRESENT, "Maximum partition count reached")
        # Find next available slot ID
        used_slots = {p["slot_id"] for p in partitions}
        slot_id = 1
        while slot_id in used_slots:
            slot_id += 1
        self.storage.insert_partition(
            slot_id=slot_id, name=name, label=label or "",
            max_objects=max_objects, max_storage=max_storage,
            max_login_attempts=max_login_attempts,
        )
        if version not in (0, 1):
            raise PKCS11Error(CKR_ARGUMENTS_BAD, "Partition version must be 0 or 1")
        self.lifecycle.register(slot_id, partition_type, version)
        return slot_id

    def delete_partition(self, name: str, hsm_so_authorized: bool = False,
                         audit=None, session_id: int = 0):
        """Delete a partition; explicit HSM SO authorization is mandatory."""
        if not hsm_so_authorized:
            raise PKCS11Error(CKR_ACTION_PROHIBITED,
                              "HSM Security Officer authorization required for partition deletion")
        p = self.storage.get_partition_by_name(name)
        if p is None:
            raise PKCS11Error(CKR_TOKEN_NOT_PRESENT, f"Partition '{name}' not found")
        self.storage.delete_partition(p["slot_id"])
        self.lifecycle.remove(p["slot_id"])
        if audit:
            audit.log(session_id, "HSO", "PartitionDelete", success=True,
                      detail=f"slot={p['slot_id']}, name={name}")

    def init_token(self, slot_id: int, so_pin: str, label: str = None,
                   domain: str = None):
        """Initialize the partition PO and its independent cloning domain."""
        p = self.storage.get_partition(slot_id)
        if p is None:
            raise PKCS11Error(CKR_TOKEN_NOT_PRESENT, f"Slot {slot_id} not found")
        initial_role = (ROLE_CO if self.lifecycle.partition_type(slot_id) == PARTITION_LEGACY
                        else ROLE_SO)
        self.auth.activation.invalidate(slot_id, forget=True)
        self.auth.set_pin(slot_id, initial_role, so_pin)
        updates = {"initialized": 1}
        if label:
            updates["label"] = label
        self.storage.update_partition(slot_id, **updates)
        # API callers that omit a domain receive a unique domain. CLI callers
        # prompt for one, matching the real partition-init ceremony.
        domain_id = self.domains.domain_from_secret(domain or secrets.token_hex(16))
        self.domains.set_partition_domain(slot_id, domain_id=domain_id, inherit=False)
        self.lifecycle.set_domain_initialized(slot_id, True)
        if self.lifecycle.status(slot_id)["version"] == 1:
            self.storage.set_partition_policy(slot_id, 41, 1)
            self.storage.set_partition_policy(slot_id, 40, 1)
            self.sks.ensure_smk(slot_id)

    def init_pin(self, slot_id: int, user_pin: str, role: str = ROLE_CO):
        """Initialize the PIN for a user role (CO or CU)."""
        p = self.storage.get_partition(slot_id)
        if p is None:
            raise PKCS11Error(CKR_TOKEN_NOT_PRESENT)
        if role not in (ROLE_CO, ROLE_LCO, ROLE_CU):
            raise PKCS11Error(CKR_TOKEN_NOT_RECOGNIZED, "InitPIN only for CO, LCO, or CU roles")
        self.auth.set_pin(slot_id, role, user_pin)

    def show_partition_info(self, slot_id: int) -> str:
        """Return a formatted string with partition details."""
        p = self.storage.get_partition(slot_id)
        if p is None:
            return f"  Slot {slot_id}: No partition present"
        obj_count = self.storage.count_objects(slot_id)
        storage_used = self.storage.get_partition_storage_used(slot_id)
        lifecycle = self.lifecycle.status(slot_id)
        domain = self.domains.get_partition_domain(slot_id)
        lines = [
            f"  Slot ID:             {slot_id}",
            f"  Partition Name:      {p['name']}",
            f"  Label:               {p.get('label', '')}",
            f"  Partition Type:      {lifecycle['type']}",
            f"  Lifecycle State:     {lifecycle['state']}",
            f"  Partition Active:    {'Yes' if lifecycle['active'] else 'No'}",
            f"  Initialized:         {'Yes' if p['initialized'] else 'No'}",
            f"  Cloning Domain:      {domain['fingerprint']} ({domain['source']})",
            f"  Domain Initialized:  {'Yes' if lifecycle['domain_initialized'] else 'No'}",
            f"  Object Quota:        {obj_count} / {p['max_objects']}",
            f"  Storage Quota:       {storage_used} / {p['max_storage']} bytes",
            f"  Max Login Attempts:  {p['max_login_attempts']}",
            "  Roles:",
        ]
        for role in ("SO", "CO", "LCO", "CU"):
            state = lifecycle["roles"][role]
            attempts = f", failures={state['failed_attempts']}/{p['max_login_attempts']}" if state["supported"] else ""
            display_role = "PO" if role == "SO" else role
            lines.append(f"    {display_role:<3} {state['state']}{attempts}")
        lines.append(f"  Created:             {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(p['created_at']))}")
        return "\n".join(lines)

    def list_partitions(self) -> str:
        """Return a formatted list of all partitions."""
        partitions = self.storage.get_all_partitions()
        if not partitions:
            return "  No partitions configured. Use 'partition create' to create one."
        lines = [
            f"  {'Slot':<6} {'Name':<18} {'Version':<8} {'State':<28} {'Objects':<10} {'PO':<14} {'CO':<14} {'CU':<14}",
            "  " + "-" * 120,
        ]
        for p in partitions:
            obj_count = self.storage.count_objects(p["slot_id"])
            lifecycle = self.lifecycle.status(p["slot_id"])
            lines.append(
                f"  {p['slot_id']:<6} {p['name']:<18} {'V' + str(lifecycle['version']):<8} "
                f"{lifecycle['state']:<28} {obj_count:<10} "
                f"{lifecycle['roles']['SO']['state']:<14} "
                f"{lifecycle['roles']['CO']['state']:<14} "
                f"{lifecycle['roles']['CU']['state']:<14}"
            )
        return "\n".join(lines)

    def _erase_application_partitions(self):
        for partition in self.storage.get_all_partitions():
            self.storage.delete_partition(partition["slot_id"])
        self.storage.set_meta(CloningDomainManager.PARTITION_META, "{}")
        self.storage.set_meta(PartitionLifecycleManager.META_KEY, "{}")
        self.storage.set_meta(SKSManager.META_KEY, "{}")

    def zeroize(self):
        """Zeroize user material while preserving policies, RPV, and Auditor."""
        self._erase_application_partitions()
        from hsm.ped import PEDManager
        PEDManager(self.storage).zeroize()
        HSMStateManager(self.storage).mark_zeroized()

    def factory_reset(self):
        """Reset HSM identities and policies without rolling back firmware."""
        self._erase_application_partitions()
        self.storage.clear_audit_logs()
        from hsm.ped import PEDManager
        PEDManager(self.storage).factory_reset()
        HSMStateManager(self.storage).factory_reset()
        self.storage.set_meta(CloningDomainManager.HSM_META, "")
        self.storage.set_meta("hsm_policies", "{}")

    # ------------------------------------------------------------------
    # Firmware management
    # ------------------------------------------------------------------

    def list_available_firmwares(self) -> list:
        """Return all available firmware versions with metadata."""
        current = self._get_firmware_version()
        result = []
        for fw in AVAILABLE_FIRMWARES:
            entry = dict(fw)
            entry["installed"] = _compare_versions(fw["version"], current) == 0
            entry["upgradeable"] = _compare_versions(fw["version"], current) > 0
            entry["downgradable"] = _compare_versions(fw["version"], current) < 0
            result.append(entry)
        return result

    def get_firmware_info(self) -> dict:
        """Return detailed info about the current firmware and upgrade status."""
        current = self._get_firmware_version()
        available = self.list_available_firmwares()
        latest = AVAILABLE_FIRMWARES[-1]["version"]
        history = self._get_firmware_history()
        return {
            "current_version": current,
            "latest_version": latest,
            "update_available": _compare_versions(latest, current) > 0,
            "available_count": len(available),
            "history": history,
            "model": HSM_MODEL,
        }

    def check_firmware_upgrade(self, target_version: str) -> dict:
        """Run pre-upgrade checks for a target firmware version.

        Returns a dict with:
          - can_upgrade: bool
          - target_version: str
          - current_version: str
          - checks: list of (name, passed, detail) tuples
          - warnings: list of str
        """
        current = self._get_firmware_version()
        checks = []
        warnings = []

        # Check 1: target version exists
        target_fw = None
        for fw in AVAILABLE_FIRMWARES:
            if fw["version"] == target_version:
                target_fw = fw
                break
        if target_fw is None:
            checks.append(("version_exists", False, f"Firmware {target_version} is not available."))
            return {"can_upgrade": False, "target_version": target_version,
                    "current_version": current, "checks": checks, "warnings": warnings}
        checks.append(("version_exists", True, f"Firmware {target_version} found in catalog."))

        # Check 2: target is different from current
        if _compare_versions(target_version, current) == 0:
            checks.append(("version_differs", False, f"Target {target_version} is already installed."))
            return {"can_upgrade": False, "target_version": target_version,
                    "current_version": current, "checks": checks, "warnings": warnings}
        checks.append(("version_differs", True, f"Current: {current}, Target: {target_version}"))

        # Check 3: no active sessions
        # (In a real HSM, active sessions would block firmware upgrade)
        checks.append(("no_active_sessions", True, "No active PKCS#11 sessions detected."))

        # Check 4: partitions are initialized (or warn if not)
        partitions = self.storage.get_all_partitions()
        uninit = [p for p in partitions if not p.get("initialized")]
        if uninit:
            warnings.append(f"{len(uninit)} uninitialized partition(s) will be preserved but may need re-initialization after upgrade.")
        checks.append(("partition_check", True, f"{len(partitions)} partition(s) present, {len(uninit)} uninitialized."))

        # Check 5: audit chain integrity
        chain_ok = self.storage.verify_audit_chain()
        if not chain_ok:
            checks.append(("audit_chain", False, "Audit chain integrity is BROKEN. Cannot upgrade."))
            return {"can_upgrade": False, "target_version": target_version,
                    "current_version": current, "checks": checks, "warnings": warnings}
        checks.append(("audit_chain", True, "Audit chain integrity verified."))

        # Check 6: upgrade direction
        direction = "upgrade" if _compare_versions(target_version, current) > 0 else "downgrade"
        if direction == "downgrade":
            warnings.append("Downgrading firmware may cause compatibility issues with keys created on newer versions.")
        checks.append(("upgrade_direction", True, f"Operation: {direction} ({current} -> {target_version})"))

        can_upgrade = all(c[1] for c in checks)
        return {"can_upgrade": can_upgrade, "target_version": target_version,
                "current_version": current, "checks": checks, "warnings": warnings,
                "target_info": target_fw}

    def perform_firmware_upgrade(self, target_version: str, audit=None) -> dict:
        """Execute the firmware upgrade process.

        Returns a dict with:
          - success: bool
          - previous_version: str
          - new_version: str
          - stages: list of (stage_name, status) tuples
          - error: str or None
        """
        current = self._get_firmware_version()

        # Run pre-checks
        pre = self.check_firmware_upgrade(target_version)
        if not pre["can_upgrade"]:
            failed_checks = [c[0] for c in pre["checks"] if not c[1]]
            if audit:
                audit.log(0, "HSO", "FirmwareUpgrade", success=False,
                          detail=f"Pre-check failed: {', '.join(failed_checks)} ({current} -> {target_version})")
            return {"success": False, "previous_version": current, "new_version": current,
                    "stages": [("pre_check", "FAILED")],
                    "error": f"Pre-check failed: {', '.join(failed_checks)}"}

        stages = []

        # Stage 1: Backup current state
        stages.append(("backup", "OK"))

        # Stage 2: Download firmware image (simulated)
        stages.append(("download", "OK"))

        # Stage 3: Verify firmware signature (simulated)
        stages.append(("verify_signature", "OK"))

        # Stage 4: Enter maintenance mode
        stages.append(("maintenance_mode", "OK"))

        # Stage 5: Flash firmware
        stages.append(("flash", "OK"))

        # Stage 6: Reboot HSM (simulated)
        stages.append(("reboot", "OK"))

        # Stage 7: Post-upgrade verification
        self._set_firmware_version(target_version)
        new_version = self._get_firmware_version()
        if new_version == target_version:
            stages.append(("post_verify", "OK"))
        else:
            stages.append(("post_verify", "FAILED"))
            if audit:
                audit.log(0, "HSO", "FirmwareUpgrade", success=False,
                          detail=f"Post-verify failed: expected {target_version}, got {new_version}")
            return {"success": False, "previous_version": current, "new_version": new_version,
                    "stages": stages, "error": "Post-upgrade verification failed"}

        # Record history
        target_info = pre.get("target_info", {})
        history_entry = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "from_version": current,
            "to_version": target_version,
            "direction": "upgrade" if _compare_versions(target_version, current) > 0 else "downgrade",
            "release_date": target_info.get("date", ""),
            "notes": target_info.get("notes", ""),
        }
        self._add_firmware_history(history_entry)

        if audit:
            audit.log(0, "HSO", "FirmwareUpgrade", success=True,
                      detail=f"{current} -> {target_version}")

        return {"success": True, "previous_version": current, "new_version": target_version,
                "stages": stages, "error": None}

    def rollback_firmware(self, audit=None) -> dict:
        """Roll back to the previous firmware version.

        Returns a dict with:
          - success: bool
          - previous_version: str
          - new_version: str
          - error: str or None
        """
        history = self._get_firmware_history()
        if not history:
            return {"success": False, "previous_version": self._get_firmware_version(),
                    "new_version": self._get_firmware_version(),
                    "error": "No firmware history available for rollback."}

        last_entry = history[-1]
        target_version = last_entry["from_version"]
        current = self._get_firmware_version()

        if target_version == current:
            return {"success": False, "previous_version": current, "new_version": current,
                    "error": f"Previous firmware ({target_version}) is the same as current."}

        # Perform the rollback as a special upgrade
        result = self.perform_firmware_upgrade(target_version, audit=audit)
        if result["success"]:
            # Update the history entry to note it was a rollback
            history = self._get_firmware_history()
            if history:
                history[-1]["rollback"] = True
                import json
                self.storage.set_meta("firmware_history", json.dumps(history))

        return result

    def show_firmware_history(self) -> str:
        """Return a formatted table of firmware upgrade history."""
        history = self._get_firmware_history()
        if not history:
            return "  No firmware upgrades have been performed."

        lines = [
            f"  {'#':<4} {'Timestamp':<21} {'From':<10} {'To':<10} {'Direction':<10} {'Rollback':<8} {'Notes':<40}",
            "  " + "-" * 110,
        ]
        for i, entry in enumerate(history):
            rollback = "Yes" if entry.get("rollback") else "No"
            notes = entry.get("notes", "")[:40]
            lines.append(
                f"  {i + 1:<4} {entry['timestamp']:<21} {entry['from_version']:<10} "
                f"{entry['to_version']:<10} {entry['direction']:<10} {rollback:<8} {notes}"
            )
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Cloning domains and secure partition-to-partition cloning
    # ------------------------------------------------------------------

    def show_cloning_domain(self, slot_id: int) -> dict:
        return self.domains.get_partition_domain(slot_id)

    def set_cloning_domain(self, slot_id: int, domain_id: str = None,
                           inherit: bool = False, force: bool = False,
                           audit=None, session_id: int = 0) -> dict:
        result = self.domains.set_partition_domain(slot_id, domain_id, inherit, force)
        if audit:
            audit.log(session_id, "SO", "PartitionDomainSet", success=True,
                      detail=f"slot={slot_id}, fingerprint={result['fingerprint']}, "
                             f"source={result['source']}, deleted={result['objects_deleted']}")
        return result

    def clone_partition(self, source_slot: int, destination_slot: int,
                        labels: list = None, audit=None, session_id: int = 0) -> dict:
        try:
            result = self.domains.clone_objects(source_slot, destination_slot, labels)
        except Exception as exc:
            if audit:
                audit.log(session_id, "SO", "PartitionClone", success=False,
                          detail=f"source={source_slot}, destination={destination_slot}, error={exc}")
            raise
        if audit:
            audit.log(session_id, "SO", "PartitionClone", success=True,
                      detail=f"source={source_slot}, destination={destination_slot}, "
                             f"objects={len(result['cloned'])}, domain={result['domain_fingerprint']}")
        return result

    # ------------------------------------------------------------------
    # Partition operations (matching real LunaCM commands)
    # ------------------------------------------------------------------

    def init_partition(self, slot_id: int, so_pin: str, label: str = None,
                       domain: str = None, audit=None, session_id: int = 0):
        """Initialize an application partition (partition init).

        On a real Luna 7, this is done from lunash (server-side), not lunacm.
        We simulate it here for educational purposes.
        """
        p = self.storage.get_partition(slot_id)
        if p is None:
            raise PKCS11Error(CKR_TOKEN_NOT_PRESENT, f"Slot {slot_id} not found")
        if p.get("initialized"):
            raise PKCS11Error(CKR_TOKEN_WRITE_PROTECTED,
                              "Partition is already initialized. Use 'hsm factoryreset' first.")
        self.init_token(slot_id, so_pin, label, domain)
        if audit:
            audit.log(session_id, ROLE_SO, "PartitionInit", success=True,
                       detail=f"slot={slot_id}, label={label or p['name']}")

    def change_partition_label(self, slot_id: int, new_label: str,
                                audit=None, session_id: int = 0):
        """Change a partition's label (partition changelabel)."""
        p = self.storage.get_partition(slot_id)
        if p is None:
            raise PKCS11Error(CKR_TOKEN_NOT_PRESENT, f"Slot {slot_id} not found")
        old_label = p.get("label", "")
        self.storage.update_partition(slot_id, label=new_label)
        if audit:
            audit.log(session_id, "CO", "PartitionChangeLabel", success=True,
                       detail=f"slot={slot_id}, '{old_label}' -> '{new_label}'")

    def clear_partition(self, slot_id: int, audit=None, session_id: int = 0):
        """Delete all token objects on a partition (partition clear)."""
        p = self.storage.get_partition(slot_id)
        if p is None:
            raise PKCS11Error(CKR_TOKEN_NOT_PRESENT, f"Slot {slot_id} not found")
        objs = self.storage.get_all_objects(slot_id)
        count = len(objs)
        for obj, _ in objs:
            self.storage.delete_object(obj.handle)
        if audit:
            audit.log(session_id, "CO", "PartitionClear", success=True,
                       detail=f"slot={slot_id}, deleted {count} objects")
        return count

    def show_partition_contents(self, slot_id: int) -> str:
        """Show the contents of a partition (partition contents)."""
        p = self.storage.get_partition(slot_id)
        if p is None:
            return f"  Slot {slot_id}: No partition present"
        objs = self.storage.get_all_objects(slot_id)
        if not objs:
            return f"  Partition '{p['name']}' (slot {slot_id}) is empty."
        lines = [
            f"  Partition: {p['name']}  (slot {slot_id})",
            f"  Label:     {p.get('label', '')}",
            f"  Objects:   {len(objs)}",
            "",
            f"  {'Handle':<12} {'Label':<25} {'Class':<18} {'Key Type':<12} {'State':<12}",
            "  " + "-" * 80,
        ]
        from pkcs11.constants import cko_name, ckk_name, cks_name, CKA_KEY_TYPE
        for obj, km in objs:
            cls = cko_name(obj.object_class())
            kt = ckk_name(obj.key_type()) if obj.has(CKA_KEY_TYPE) else "N/A"
            state = cks_name(obj.state) if hasattr(obj, "state") else "N/A"
            lines.append(f"  0x{obj.handle:08X}   {obj.label():<25} {cls:<18} {kt:<12} {state:<12}")
        return "\n".join(lines)

    def show_mechanisms(self, slot_id: int) -> str:
        """Show all available mechanisms on a partition (partition showmechanism)."""
        from pkcs11.mechanisms import MECHANISMS, MF_GENERATE, MF_GENERATE_KEY_PAIR, MF_ENCRYPT, MF_DECRYPT, MF_SIGN, MF_VERIFY, MF_DIGEST, MF_WRAP, MF_UNWRAP, MF_DERIVE
        from pkcs11.constants import ckm_name

        flag_names = [
            (MF_GENERATE, "gen"), (MF_GENERATE_KEY_PAIR, "genpair"),
            (MF_ENCRYPT, "enc"), (MF_DECRYPT, "dec"),
            (MF_SIGN, "sign"), (MF_VERIFY, "verify"),
            (MF_DIGEST, "digest"), (MF_WRAP, "wrap"),
            (MF_UNWRAP, "unwrap"), (MF_DERIVE, "derive"),
        ]

        lines = [
            f"  Available mechanisms for slot {slot_id}:",
            "",
            f"  {'Mechanism':<30} {'KeyRange':<16} {'Flags'}",
            "  " + "-" * 75,
        ]
        for mech_id in sorted(MECHANISMS.keys()):
            info = MECHANISMS[mech_id]
            name = ckm_name(mech_id)
            if info.min_key_size and info.max_key_size:
                kr = f"{info.min_key_size}-{info.max_key_size}"
            else:
                kr = "N/A"
            flags = " ".join(fn for fval, fn in flag_names if info.supports(fval))
            lines.append(f"  {name:<30} {kr:<16} {flags}")
        return "\n".join(lines)

    def _hsm_policy_values(self) -> dict:
        from hsm.policies import get_default_hsm_policies
        values = get_default_hsm_policies()
        raw = self.storage.get_meta("hsm_policies")
        if raw:
            try:
                values.update({int(key): value for key, value in json.loads(raw).items()})
            except (TypeError, ValueError, json.JSONDecodeError):
                pass
        return values

    def show_hsm_policies(self, verbose: bool = False) -> str:
        from hsm.policies import HSM_POLICY_CATALOG, format_policies_table
        return "  HSM Policies:\n" + format_policies_table(
            self._hsm_policy_values(), verbose=verbose, catalog=HSM_POLICY_CATALOG)

    def change_hsm_policy(self, policy_name, value, force: bool = False,
                          audit=None, session_id: int = 0):
        from hsm.policies import get_hsm_policy, validate_policy_change
        policy = get_hsm_policy(policy_name)
        if policy is None:
            raise PKCS11Error(CKR_TOKEN_NOT_RECOGNIZED,
                              f"HSM policy '{policy_name}' was not found")
        values = self._hsm_policy_values()
        old_value = values[policy.policy_id]
        new_value = int(value) if str(value).isdigit() else (
            1 if str(value).lower() in ("on", "true", "yes") else 0)
        valid, error, destructive = validate_policy_change(policy, old_value, new_value)
        if not valid:
            raise PKCS11Error(CKR_ACTION_PROHIBITED, error)
        if destructive and not force:
            raise PKCS11Error(CKR_ACTION_PROHIBITED,
                              "Destructive HSM policy change requires confirmation")
        values[policy.policy_id] = new_value
        self.storage.set_meta("hsm_policies", json.dumps(values))
        if destructive and old_value != new_value:
            self._erase_application_partitions()
        if audit:
            audit.log(session_id, "HSO", "HSMChangePolicy", success=True,
                      detail=f"policy={policy.policy_id}, value={old_value}->{new_value}")

    def show_policies(self, slot_id: int, verbose: bool = False) -> str:
        """Show partition policies (partition showpolicies).

        Displays all partition capabilities and their corresponding policy
        settings. With verbose=True, shows full descriptions and
        destructiveness information.
        """
        from hsm.policies import POLICY_CATALOG, format_policies_table
        p = self.storage.get_partition(slot_id)
        if p is None:
            return f"  Slot {slot_id}: No partition present"

        stored = self.storage.get_partition_policies(slot_id)
        policies = {}
        for pol in POLICY_CATALOG:
            policies[pol.policy_id] = stored.get(pol.policy_id, pol.default_value)

        header = f"  Partition Policies for '{p['name']}' (slot {slot_id}):\n"
        return header + format_policies_table(policies, verbose=verbose)

    def change_policy(self, slot_id: int, policy_name: str, value,
                      audit=None, session_id: int = 0, force: bool = False):
        """Change a partition policy value (partition changepolicy).

        On a real Luna 7, this is done with:
          lunacm:> partition changepolicy -policy <id> -value <value>

        Some policy changes are destructive (delete all objects on the
        partition). The caller must confirm by passing force=True.
        """
        from hsm.policies import get_policy, get_policy_by_name, validate_policy_change, check_mutual_exclusion, check_firmware_support
        p = self.storage.get_partition(slot_id)
        if p is None:
            raise PKCS11Error(CKR_TOKEN_NOT_PRESENT, f"Slot {slot_id} not found")

        # Look up policy by name or numeric ID
        policy = None
        if isinstance(policy_name, int) or policy_name.isdigit():
            policy = get_policy(int(policy_name))
        else:
            policy = get_policy_by_name(policy_name)

        if policy is None:
            raise PKCS11Error(CKR_TOKEN_NOT_RECOGNIZED,
                              f"Policy '{policy_name}' not found. Use 'partition showpolicies' to see available policies.")

        # Check firmware support
        current_fw = self._get_firmware_version()
        if not check_firmware_support(policy, current_fw):
            raise PKCS11Error(CKR_ACTION_PROHIBITED,
                              f"Policy '{policy.name}' requires firmware {policy.firmware_min} or newer. Current: {current_fw}")

        # Get current value
        stored = self.storage.get_partition_policies(slot_id)
        old_value = stored.get(policy.policy_id, policy.default_value)

        # Parse value
        if policy.value_type == "integer":
            new_value = int(value)
        else:
            new_value = int(value) if isinstance(value, (int, str)) and str(value).isdigit() else (1 if str(value).lower() in ("on", "1", "true", "yes") else 0)

        # Validate the change
        is_valid, err_msg, is_destructive = validate_policy_change(policy, old_value, new_value)
        if not is_valid:
            raise PKCS11Error(CKR_ACTION_PROHIBITED, err_msg)

        # Check mutual exclusion using effective values (with defaults)
        all_policies = {}
        from hsm.policies import POLICY_CATALOG
        for pol in POLICY_CATALOG:
            all_policies[pol.policy_id] = stored.get(pol.policy_id, pol.default_value)
        all_policies[policy.policy_id] = new_value
        valid, err = check_mutual_exclusion(all_policies, policy.policy_id, new_value)
        if not valid:
            raise PKCS11Error(CKR_ACTION_PROHIBITED, err)

        # Check destructiveness
        if is_destructive and not force:
            raise PKCS11Error(CKR_ACTION_PROHIBITED,
                              f"Changing policy '{policy.name}' is DESTRUCTIVE — it will delete all objects on the partition. "
                              f"Pass force=True to confirm.")

        # Apply the change
        self.storage.set_partition_policy(slot_id, policy.policy_id, new_value)
        if policy.policy_id == 20:
            self.storage.update_partition(slot_id, max_login_attempts=new_value)
        if policy.policy_id == 44 and old_value == 1 and new_value == 0:
            settings = self.domains._get_partition_settings()
            setting = settings.get(str(slot_id), {})
            if setting.get("domains"):
                original = next((item for item in setting["domains"]
                                 if item.get("original")), setting["domains"][0])
                original["primary"] = True
                original["original"] = True
                setting["domains"] = [original]
                setting["domain_id"] = original["domain_id"]
                self.domains._save_partition_settings(settings)

        # If destructive, clear all objects
        if is_destructive:
            objs = self.storage.get_all_objects(slot_id)
            for obj, _ in objs:
                self.storage.delete_object(obj.handle)

        if audit:
            audit.log(session_id, "SO", "PartitionChangePolicy", success=True,
                       detail=f"slot={slot_id}, policy={policy.name}({policy.policy_id}), "
                              f"value={old_value}->{new_value}"
                              f"{', DESTRUCTIVE' if is_destructive else ''}")

    def get_policy_value(self, slot_id: int, policy_name: str) -> int:
        """Get the current value of a partition policy."""
        from hsm.policies import get_policy, get_policy_by_name, POLICY_CATALOG
        policy = None
        if isinstance(policy_name, int) or str(policy_name).isdigit():
            policy = get_policy(int(policy_name))
        else:
            policy = get_policy_by_name(policy_name)
        if policy is None:
            raise PKCS11Error(CKR_TOKEN_NOT_RECOGNIZED,
                              f"Policy '{policy_name}' not found.")
        stored = self.storage.get_partition_policies(slot_id)
        return stored.get(policy.policy_id, policy.default_value)

    def is_cloning_allowed(self, slot_id: int) -> bool:
        """Check if private key cloning is allowed on this partition."""
        return self.get_policy_value(slot_id, "ALLOW_PRIVATE_KEY_CLONING") == 1

    def is_secret_key_cloning_allowed(self, slot_id: int) -> bool:
        """Check if secret key cloning is allowed on this partition."""
        return self.get_policy_value(slot_id, "ALLOW_SECRET_KEY_CLONING") == 1

    def is_wrapping_allowed(self, slot_id: int) -> bool:
        """Check if private key wrapping is allowed on this partition."""
        return self.get_policy_value(slot_id, "ALLOW_PRIVATE_KEY_WRAPPING") == 1

    def is_secret_key_wrapping_allowed(self, slot_id: int) -> bool:
        """Check if secret key wrapping is allowed on this partition."""
        return self.get_policy_value(slot_id, "ALLOW_SECRET_KEY_WRAPPING") == 1

    def is_unwrapping_allowed(self, slot_id: int) -> bool:
        """Check if private key unwrapping is allowed on this partition."""
        return self.get_policy_value(slot_id, "ALLOW_PRIVATE_KEY_UNWRAPPING") == 1

    def is_secret_key_unwrapping_allowed(self, slot_id: int) -> bool:
        """Check if secret key unwrapping is allowed on this partition."""
        return self.get_policy_value(slot_id, "ALLOW_SECRET_KEY_UNWRAPPING") == 1

    def is_multipurpose_keys_allowed(self, slot_id: int) -> bool:
        """Check if multipurpose keys are allowed on this partition."""
        return self.get_policy_value(slot_id, "ALLOW_MULTIPURPOSE_KEYS") == 1

    def is_raw_rsa_allowed(self, slot_id: int) -> bool:
        """Check if raw RSA operations are allowed on this partition."""
        return self.get_policy_value(slot_id, "ALLOW_RAW_RSA_OPERATIONS") == 1

    def is_digest_key_allowed(self, slot_id: int) -> bool:
        """Check if DigestKey is allowed on this partition."""
        return self.get_policy_value(slot_id, "ALLOW_DIGEST_KEY") == 1

    def get_min_pin_length(self, slot_id: int) -> int:
        """Get the minimum PIN length for this partition."""
        return 255 - self.get_policy_value(slot_id, "MIN_PIN_LENGTH")

    def get_max_login_attempts(self, slot_id: int) -> int:
        """Get the max login attempts for this partition."""
        return self.get_policy_value(slot_id, "MAX_LOGIN_ATTEMPTS")

    # ------------------------------------------------------------------
    # Partition Policy Templates (PPT)
    # ------------------------------------------------------------------

    def list_policy_templates(self) -> list:
        """List all available PPT templates (predefined + custom)."""
        from hsm.policies import list_predefined_templates
        templates = list_predefined_templates()
        # Add custom templates from storage
        custom = self.storage.get_all_ppt_templates()
        for name, data in custom.items():
            templates.append({
                "name": name,
                "description": data.get("description", ""),
                "policy_count": len(data.get("policies", {})),
                "custom": True,
            })
        return templates

    def get_policy_template(self, name: str) -> Optional[dict]:
        """Get a PPT template by name (predefined or custom)."""
        from hsm.policies import get_predefined_template
        # Check predefined first
        predef = get_predefined_template(name)
        if predef:
            return {"description": predef["description"],
                    "policies": predef["policies"], "predefined": True}
        # Check custom
        custom = self.storage.get_ppt_template(name)
        if custom:
            return {"description": custom.get("description", ""),
                    "policies": custom.get("policies", {}), "predefined": False}
        return None

    def create_policy_template(self, name: str, description: str,
                               policies: dict, audit=None, session_id: int = 0):
        """Create a custom PPT template."""
        from hsm.policies import validate_template
        current_fw = self._get_firmware_version()
        valid, errors = validate_template(policies, current_fw)
        if not valid:
            raise PKCS11Error(CKR_ARGUMENTS_BAD,
                              "Template validation failed: " + "; ".join(errors))
        self.storage.save_ppt_template(name, description, policies)
        if audit:
            audit.log(session_id, "SO", "CreatePolicyTemplate", success=True,
                       detail=f"name={name}, policies={len(policies)}")

    def delete_policy_template(self, name: str, audit=None, session_id: int = 0):
        """Delete a custom PPT template."""
        from hsm.policies import PREDEFINED_TEMPLATES
        if name.upper() in PREDEFINED_TEMPLATES:
            raise PKCS11Error(CKR_ACTION_PROHIBITED,
                              f"Cannot delete predefined template '{name}'.")
        deleted = self.storage.delete_ppt_template(name)
        if not deleted:
            raise PKCS11Error(CKR_TOKEN_NOT_RECOGNIZED,
                              f"Template '{name}' not found.")
        if audit:
            audit.log(session_id, "SO", "DeletePolicyTemplate", success=True,
                       detail=f"name={name}")

    def apply_policy_template(self, slot_id: int, template_name: str,
                               audit=None, session_id: int = 0, force: bool = False):
        """Apply a PPT template to a partition.

        On a real Luna 7, this is done during partition initialization:
          lunacm:> partition init -policytemplate <name>
        """
        from hsm.policies import apply_template_to_policies, validate_template, POLICY_CATALOG, validate_policy_change_safe
        p = self.storage.get_partition(slot_id)
        if p is None:
            raise PKCS11Error(CKR_TOKEN_NOT_PRESENT, f"Slot {slot_id} not found")

        template = self.get_policy_template(template_name)
        if template is None:
            raise PKCS11Error(CKR_TOKEN_NOT_RECOGNIZED,
                              f"Template '{template_name}' not found.")

        template_policies = template["policies"]
        current_fw = self._get_firmware_version()
        valid, errors = validate_template(template_policies, current_fw)
        if not valid:
            raise PKCS11Error(CKR_ARGUMENTS_BAD,
                              "Template validation failed: " + "; ".join(errors))

        current = self.storage.get_partition_policies(slot_id)
        new_policies = apply_template_to_policies(template_policies, current)

        # Check if any changes are destructive
        any_destructive = False
        for pid, val in template_policies.items():
            policy = POLICY_CATALOG[pid] if pid < len(POLICY_CATALOG) else None
            if policy is None:
                continue
            old_val = current.get(pid, policy.default_value)
            _, _, is_destr = validate_policy_change_safe(policy, old_val, val)
            if is_destr:
                any_destructive = True

        if any_destructive and not force:
            raise PKCS11Error(CKR_ACTION_PROHIBITED,
                              "Applying this template is DESTRUCTIVE — it will delete all objects on the partition. "
                              "Pass force=True to confirm.")

        self.storage.set_partition_policies(slot_id, new_policies)

        if any_destructive:
            objs = self.storage.get_all_objects(slot_id)
            for obj, _ in objs:
                self.storage.delete_object(obj.handle)

        if audit:
            audit.log(session_id, "SO", "ApplyPolicyTemplate", success=True,
                       detail=f"slot={slot_id}, template={template_name}"
                              f"{', DESTRUCTIVE' if any_destructive else ''}")

    # ------------------------------------------------------------------
    # Role operations (matching real LunaCM commands)
    # ------------------------------------------------------------------

    def list_roles(self, slot_id: int) -> str:
        """List roles on a partition (role list)."""
        p = self.storage.get_partition(slot_id)
        if p is None:
            return f"  Slot {slot_id}: No partition present"

        lifecycle = self.lifecycle.status(slot_id)
        descriptions = {"SO": "Partition Security Officer", "CO": "Crypto Officer",
                        "LCO": "Limited Crypto Officer", "CU": "Crypto User"}
        lines = [
            f"  Roles on partition '{p['name']}' (slot {slot_id}, {lifecycle['type']}):",
            "",
            f"  {'Role':<6} {'Description':<25} {'Initialized':<14} {'Status'}",
            "  " + "-" * 65,
        ]
        for name in ("SO", "CO", "LCO", "CU"):
            role = lifecycle["roles"][name]
            display_name = "PO" if name == "SO" else name
            init = "Yes" if role["initialized"] else "No"
            lines.append(f"  {display_name:<6} {descriptions[name]:<25} {init:<14} {role['state']}")
        return "\n".join(lines)

    def show_role(self, slot_id: int, role_name: str) -> str:
        """Show state of a role (role show)."""
        p = self.storage.get_partition(slot_id)
        if p is None:
            return f"  Slot {slot_id}: No partition present"

        role_name = role_name.upper()
        role_name = "SO" if role_name == "PO" else role_name
        role_map = {"SO": ("so", "Partition Security Officer"),
                    "CO": ("co", "Crypto Officer"),
                    "LCO": ("lco", "Limited Crypto Officer"),
                    "CU": ("cu", "Crypto User")}

        if role_name not in role_map:
            return f"  Unknown role: {role_name}. Valid: PO, CO, LCO, CU"

        prefix, desc = role_map[role_name]
        role = self.lifecycle.status(slot_id)["roles"][role_name]
        max_attempts = p.get("max_login_attempts", 10)

        lines = [
            f"  Role: {role_name} ({desc})",
            f"  Partition: {p['name']} (slot {slot_id})",
            f"  PIN Initialized: {'Yes' if role['initialized'] else 'No'}",
            f"  Status: {role['state']}",
            f"  Failed Login Attempts: {role['failed_attempts']} / {max_attempts}",
        ]
        return "\n".join(lines)

    def init_role(self, slot_id: int, role_name: str, pin: str,
                  audit=None, session_id: int = 0, actor_role: str = ROLE_SO):
        """Initialize a role on a partition (role init).

        This is used to initialize the CU role or re-initialize CO.
        Requires SO to be logged in on a real HSM.
        """
        p = self.storage.get_partition(slot_id)
        if p is None:
            raise PKCS11Error(CKR_TOKEN_NOT_PRESENT, f"Slot {slot_id} not found")

        role_name = role_name.upper()
        if role_name not in ("CO", "LCO", "CU"):
            raise PKCS11Error(CKR_TOKEN_NOT_RECOGNIZED,
                              "Only CO, LCO, and CU roles can be initialized with 'role init'")
        if role_name == "LCO" and self.lifecycle.status(slot_id)["version"] != 1:
            raise PKCS11Error(CKR_ACTION_PROHIBITED, "LCO is available only on V1 partitions")
        ptype = self.lifecycle.partition_type(slot_id)
        superior = ROLE_SO if ptype == PARTITION_PPSO else ROLE_CO
        if actor_role != superior:
            raise PKCS11Error(CKR_ACTION_PROHIBITED,
                              f"{superior} authorization required")
        if p.get(f"{role_name.lower()}_pin_hash"):
            raise PKCS11Error(CKR_ACTION_PROHIBITED,
                              f"{role_name} is already initialized; use role resetpw or changepw")

        self.auth.set_pin(slot_id, role_name, pin)
        if audit:
            audit.log(session_id, "SO", "RoleInit", success=True,
                       detail=f"slot={slot_id}, role={role_name}")

    def deactivate_role(self, slot_id: int, role_name: str,
                        audit=None, session_id: int = 0,
                        actor_role: str = ROLE_SO):
        """Deactivate CO/CU login while retaining its credential for reactivation."""
        p = self.storage.get_partition(slot_id)
        if p is None:
            raise PKCS11Error(CKR_TOKEN_NOT_PRESENT, f"Slot {slot_id} not found")

        role_name = role_name.upper()
        if role_name not in ("CO", "LCO", "CU"):
            raise PKCS11Error(CKR_TOKEN_NOT_RECOGNIZED,
                              "Only CO, LCO, and CU roles can be deactivated")

        if self.auth.ped.get_auth_mode() == "ped":
            self.auth.activation.deactivate(slot_id, role_name, actor_role)
            return
        ptype = self.lifecycle.partition_type(slot_id)
        superior = (ROLE_SO if ptype == PARTITION_PPSO else
                    ("HSO" if role_name == "CO" else ROLE_CO))
        if actor_role != superior:
            raise PKCS11Error(CKR_ACTION_PROHIBITED, f"{superior} authorization required")
        self.lifecycle.set_role_active(slot_id, role_name, False)
        if audit:
            audit.log(session_id, "SO", "RoleDeactivate", success=True,
                       detail=f"slot={slot_id}, role={role_name}")

    def activate_role(self, slot_id: int, role_name: str,
                      audit=None, session_id: int = 0,
                      actor_role: str = ROLE_SO):
        """Reactivate an initialized CO or CU role; requires Partition SO."""
        role_name = role_name.upper()
        p = self.storage.get_partition(slot_id)
        if p is None:
            raise PKCS11Error(CKR_TOKEN_NOT_PRESENT, f"Slot {slot_id} not found")
        if role_name not in ("CO", "LCO", "CU"):
            raise PKCS11Error(CKR_TOKEN_NOT_RECOGNIZED, "Only CO, LCO, and CU can be activated")
        ptype = self.lifecycle.partition_type(slot_id)
        superior = (ROLE_SO if ptype == PARTITION_PPSO else
                    ("HSO" if role_name == "CO" else ROLE_CO))
        if actor_role != superior:
            raise PKCS11Error(CKR_ACTION_PROHIBITED, f"{superior} authorization required")
        if not p.get(f"{role_name.lower()}_pin_hash"):
            raise PKCS11Error(CKR_USER_PIN_NOT_INITIALIZED, f"{role_name} is not initialized")
        self.lifecycle.set_role_active(slot_id, role_name, True)
        if audit:
            audit.log(session_id, "SO", "RoleActivate", success=True,
                      detail=f"slot={slot_id}, role={role_name}")

    def reset_pin(self, slot_id: int, role_name: str, new_pin: str,
                  audit=None, session_id: int = 0,
                  actor_role: str = ROLE_SO):
        """Reset a role's PIN (role resetpw).

        On a real HSM, this requires SO authentication. It sets a new
        PIN without requiring the old one.
        """
        p = self.storage.get_partition(slot_id)
        if p is None:
            raise PKCS11Error(CKR_TOKEN_NOT_PRESENT, f"Slot {slot_id} not found")

        role_name = role_name.upper()
        if role_name == "SO":
            if actor_role != "HSO":
                raise PKCS11Error(CKR_ACTION_PROHIBITED,
                                  "Only the HSM SO can reset the Partition SO")
        elif role_name in ("CO", "LCO", "CU"):
            ptype = self.lifecycle.partition_type(slot_id)
            superior = (ROLE_SO if ptype == PARTITION_PPSO else
                        ("HSO" if role_name == "CO" else ROLE_CO))
            if actor_role != superior:
                raise PKCS11Error(CKR_ACTION_PROHIBITED,
                                  f"{superior} authorization required")
        else:
            raise PKCS11Error(CKR_TOKEN_NOT_RECOGNIZED, "Unknown role")

        self.auth.set_pin(slot_id, role_name, new_pin)
        if audit:
            audit.log(session_id, actor_role, "RoleResetPW", success=True,
                       detail=f"slot={slot_id}, role={role_name}")
