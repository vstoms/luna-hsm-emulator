"""Token / partition management for the Luna 7 HSM emulator.

A "token" in PKCS#11 terms corresponds to a Luna "partition" — a
logical container on the HSM that holds keys and objects with its own
authentication, storage quotas, and audit log.
"""

import time
import os
import hashlib
import re
from typing import Optional

from storage.db import Storage
from pkcs11.constants import (
    PKCS11Error, CKR_TOKEN_NOT_PRESENT, CKR_TOKEN_WRITE_PROTECTED,
    CKR_TOKEN_NOT_RECOGNIZED, CKR_SESSION_READ_ONLY,
    CKF_TOKEN_INITIALIZED, CKF_LOGIN_REQUIRED, CKF_RNG,
)
from hsm.auth import AuthManager, ROLE_CO, ROLE_CU, ROLE_SO

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
            "hardware_version": self._get_firmware_version(),
            "firmware_version": self._get_firmware_version(),
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
        self.storage.set_meta("firmware_version", DEFAULT_FIRMWARE)
        self.storage.set_meta("firmware_history", "[]")

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
