"""Luna Backup HSM 7 emulation.

The Luna Backup HSM 7 is a USB-connected HSM used to store backup copies
of cryptographic objects from Luna Network HSM 7 application partitions.
Backup and restore operations use the cloning protocol, which requires
that the source and destination share a common cloning domain.

This module emulates:
  - Backup HSM initialization (set SO PIN, create backup partitions)
  - Backup HSM login / logout
  - Backup (clone objects from a source partition to a backup partition)
  - Restore (clone objects from a backup partition back to a source partition)
  - Backup HSM status and listing
  - Secure Transport Mode (STM) simulation
  - Firmware management for the backup HSM
"""

import os
import time
import hashlib
import json
from typing import Optional

from storage.db import Storage
from pkcs11.constants import (
    PKCS11Error, CKR_TOKEN_NOT_PRESENT, CKR_TOKEN_NOT_RECOGNIZED,
    CKR_TOKEN_WRITE_PROTECTED, CKR_PIN_INCORRECT, CKR_PIN_LOCKED,
    CKR_PIN_LEN_RANGE, CKR_USER_NOT_LOGGED_IN, CKR_USER_PIN_NOT_INITIALIZED,
    CKR_ACTION_PROHIBITED, CKR_FUNCTION_FAILED,
)
from hsm.auth import AuthManager, ROLE_SO

BACKUP_HSM_MODEL = "Luna Backup HSM 7"
BACKUP_HSM_DEFAULT_FW = "7.13.0"
BACKUP_MAX_PARTITIONS = 10
BACKUP_MAX_STORAGE = 10 * 1024 * 1024  # 10 MB simulated

STM_STATE_SECURE = "secure_transport"
STM_STATE_INITIALIZED = "initialized"
STM_STATE_ACTIVE = "active"


class BackupPartition:
    """A partition on the backup HSM that stores cloned objects."""

    def __init__(self, partition_id: int, domain: str, label: str = "",
                 created_at: float = None):
        self.partition_id = partition_id
        self.domain = domain
        self.label = label
        self.created_at = created_at or time.time()
        self.objects = []  # list of (label, object_data, key_material_hex)

    def to_dict(self) -> dict:
        return {
            "partition_id": self.partition_id,
            "domain": self.domain,
            "label": self.label,
            "created_at": self.created_at,
            "objects": self.objects,
        }

    @classmethod
    def from_dict(cls, d: dict):
        bp = cls(d["partition_id"], d["domain"], d.get("label", ""),
                 d.get("created_at"))
        bp.objects = d.get("objects", [])
        return bp


class BackupHSM:
    """Emulates a Luna Backup HSM 7 connected via USB.

    The backup HSM has its own SO PIN, firmware version, and set of
    backup partitions. Objects are cloned to/from partitions using
    the shared cloning domain concept.
    """

    def __init__(self, storage: Storage):
        self.storage = storage
        self.auth = AuthManager(storage)
        self._connected = False
        self._serial = None
        self._login_session = None  # session_id of logged-in SO

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------

    def connect(self) -> dict:
        """Simulate connecting a Luna Backup HSM 7 via USB.

        On a real Luna 7, the backup HSM appears as a slot in LunaCM.
        We simulate this by marking it as connected and generating a
        serial number.
        """
        if self._connected:
            return {"serial": self._serial, "already_connected": True}

        self._connected = True
        self._serial = self._get_or_create_serial()
        self._ensure_state()

        return {
            "serial": self._serial,
            "model": BACKUP_HSM_MODEL,
            "firmware": self._get_firmware_version(),
            "stm_state": self._get_stm_state(),
            "already_connected": False,
        }

    def disconnect(self):
        """Simulate disconnecting the backup HSM."""
        self._connected = False
        self._login_session = None

    def is_connected(self) -> bool:
        return self._connected

    def _ensure_state(self):
        """Initialize backup HSM metadata if not present."""
        if not self.storage.get_meta("backup_hsm_serial"):
            self.storage.set_meta("backup_hsm_serial", self._serial)
        if not self.storage.get_meta("backup_hsm_firmware"):
            self.storage.set_meta("backup_hsm_firmware", BACKUP_HSM_DEFAULT_FW)
        if not self.storage.get_meta("backup_hsm_stm_state"):
            self.storage.set_meta("backup_hsm_stm_state", STM_STATE_SECURE)
        if not self.storage.get_meta("backup_hsm_partitions"):
            self.storage.set_meta("backup_hsm_partitions", "[]")
        if not self.storage.get_meta("backup_hsm_so_pin_hash"):
            # SO PIN not set yet — backup HSM is in secure transport mode
            pass

    def _get_or_create_serial(self) -> str:
        serial = self.storage.get_meta("backup_hsm_serial")
        if serial:
            return serial
        serial = "B7" + hashlib.sha256(os.urandom(8)).hexdigest()[:8].upper()
        return serial

    def _get_firmware_version(self) -> str:
        return self.storage.get_meta("backup_hsm_firmware") or BACKUP_HSM_DEFAULT_FW

    def _get_stm_state(self) -> str:
        return self.storage.get_meta("backup_hsm_stm_state") or STM_STATE_SECURE

    def _set_stm_state(self, state: str):
        self.storage.set_meta("backup_hsm_stm_state", state)

    # ------------------------------------------------------------------
    # Secure Transport Mode
    # ------------------------------------------------------------------

    def stm_recover(self, random_user_string: str, audit=None, session_id: int = 0) -> dict:
        """Recover the backup HSM from Secure Transport Mode.

        On a real Luna 7, this verifies a random user string that was
        set during manufacturing. We simulate this by accepting any
        non-empty string and transitioning to initialized state.
        """
        if not self._connected:
            raise PKCS11Error(CKR_TOKEN_NOT_PRESENT, "Backup HSM not connected")
        if self._get_stm_state() != STM_STATE_SECURE:
            raise PKCS11Error(CKR_ACTION_PROHIBITED,
                              "Backup HSM is not in Secure Transport Mode")
        if not random_user_string or len(random_user_string) < 4:
            raise PKCS11Error(CKR_FUNCTION_FAILED,
                              "Random user string must be at least 4 characters")

        self._set_stm_state(STM_STATE_INITIALIZED)
        if audit:
            audit.log(session_id, "HSO", "BackupSTMRecover", success=True,
                       detail=f"serial={self._serial}")
        return {"success": True, "stm_state": STM_STATE_INITIALIZED}

    def stm_show(self) -> dict:
        """Show Secure Transport Mode status."""
        return {
            "serial": self._serial,
            "stm_state": self._get_stm_state(),
            "description": {
                STM_STATE_SECURE: "Secure Transport Mode — HSM has not been initialized",
                STM_STATE_INITIALIZED: "Initialized — SO PIN set, ready for use",
                STM_STATE_ACTIVE: "Active — HSM is operational",
            }.get(self._get_stm_state(), "Unknown"),
        }

    # ------------------------------------------------------------------
    # Initialization
    # ------------------------------------------------------------------

    def initialize(self, so_pin: str, audit=None, session_id: int = 0) -> dict:
        """Initialize the backup HSM by setting the SO PIN.

        This transitions from STM_STATE_INITIALIZED to STM_STATE_ACTIVE.
        On a real Luna 7, this is done with 'token backup init'.
        """
        if not self._connected:
            raise PKCS11Error(CKR_TOKEN_NOT_PRESENT, "Backup HSM not connected")
        if self._get_stm_state() == STM_STATE_SECURE:
            raise PKCS11Error(CKR_ACTION_PROHIBITED,
                              "Backup HSM is in Secure Transport Mode. Use 'backup stm recover' first.")
        if self._get_stm_state() == STM_STATE_ACTIVE:
            raise PKCS11Error(CKR_TOKEN_WRITE_PROTECTED,
                              "Backup HSM is already initialized")

        if len(so_pin) < 4 or len(so_pin) > 32:
            raise PKCS11Error(CKR_PIN_LEN_RANGE,
                              "SO PIN must be 4-32 characters")

        pin_hash, pin_salt = self.storage.hash_pin(so_pin)
        self.storage.set_meta("backup_hsm_so_pin_hash", pin_hash)
        self.storage.set_meta("backup_hsm_so_pin_salt", pin_salt)
        self._set_stm_state(STM_STATE_ACTIVE)

        if audit:
            audit.log(session_id, "HSO", "BackupHSMInit", success=True,
                       detail=f"serial={self._serial}")
        return {"success": True, "stm_state": STM_STATE_ACTIVE}

    # ------------------------------------------------------------------
    # Login / Logout
    # ------------------------------------------------------------------

    def login(self, so_pin: str, audit=None, session_id: int = 0) -> dict:
        """Log in to the backup HSM as SO.

        On a real Luna 7: 'token backup login -serial <serial>'
        """
        if not self._connected:
            raise PKCS11Error(CKR_TOKEN_NOT_PRESENT, "Backup HSM not connected")
        if self._get_stm_state() != STM_STATE_ACTIVE:
            raise PKCS11Error(CKR_ACTION_PROHIBITED,
                              "Backup HSM not initialized. Use 'backup init' first.")

        stored_hash = self.storage.get_meta("backup_hsm_so_pin_hash")
        stored_salt = self.storage.get_meta("backup_hsm_so_pin_salt")
        if not stored_hash or not stored_salt:
            raise PKCS11Error(CKR_USER_PIN_NOT_INITIALIZED,
                              "Backup HSM SO PIN not set")

        if not self.storage.verify_pin(so_pin, stored_hash, stored_salt):
            if audit:
                audit.log(session_id, "SO", "BackupHSMLogin", success=False,
                           detail=f"serial={self._serial}")
            raise PKCS11Error(CKR_PIN_INCORRECT, "Backup HSM SO PIN incorrect")

        self._login_session = session_id
        if audit:
            audit.log(session_id, "SO", "BackupHSMLogin", success=True,
                       detail=f"serial={self._serial}")
        return {"success": True, "serial": self._serial}

    def logout(self, audit=None, session_id: int = 0):
        """Log out from the backup HSM."""
        self._login_session = None
        if audit:
            audit.log(session_id, "SO", "BackupHSMLogout", success=True,
                       detail=f"serial={self._serial}")

    def is_logged_in(self) -> bool:
        return self._login_session is not None

    def _require_login(self):
        if not self.is_logged_in():
            raise PKCS11Error(CKR_USER_NOT_LOGGED_IN,
                              "Not logged in to backup HSM. Use 'backup login' first.")

    # ------------------------------------------------------------------
    # Backup partitions
    # ------------------------------------------------------------------

    def _get_backup_partitions(self) -> list:
        raw = self.storage.get_meta("backup_hsm_partitions") or "[]"
        try:
            data = json.loads(raw)
            return [BackupPartition.from_dict(d) for d in data]
        except (json.JSONDecodeError, TypeError):
            return []

    def _save_backup_partitions(self, partitions: list):
        data = json.dumps([p.to_dict() for p in partitions])
        self.storage.set_meta("backup_hsm_partitions", data)

    def create_backup_partition(self, domain: str, label: str = "",
                                 audit=None, session_id: int = 0) -> dict:
        """Create a backup partition with a cloning domain.

        On a real Luna 7, backup partitions are created implicitly when
        you clone objects to the backup HSM with a specific domain.
        """
        self._require_login()
        partitions = self._get_backup_partitions()
        if len(partitions) >= BACKUP_MAX_PARTITIONS:
            raise PKCS11Error(CKR_TOKEN_NOT_PRESENT,
                              "Backup HSM partition limit reached")

        next_id = max([p.partition_id for p in partitions], default=0) + 1
        bp = BackupPartition(next_id, domain, label)
        partitions.append(bp)
        self._save_backup_partitions(partitions)

        if audit:
            audit.log(session_id, "SO", "BackupCreatePartition", success=True,
                       detail=f"domain={domain}, label={label}")
        return {"partition_id": next_id, "domain": domain, "label": label}

    def list_backup_partitions(self) -> list:
        """List all backup partitions on the backup HSM."""
        self._require_login()
        partitions = self._get_backup_partitions()
        result = []
        for p in partitions:
            result.append({
                "partition_id": p.partition_id,
                "domain": p.domain,
                "label": p.label,
                "object_count": len(p.objects),
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S",
                                            time.localtime(p.created_at)),
            })
        return result

    # ------------------------------------------------------------------
    # Backup (clone objects to backup HSM)
    # ------------------------------------------------------------------

    def backup_objects(self, source_slot_id: int, domain: str,
                       labels: list = None, audit=None,
                       session_id: int = 0) -> dict:
        """Clone objects from a source partition to the backup HSM.

        On a real Luna 7: 'partition clone -slot <src> -domain <dom>'
        Objects must be clonable (CKA_EXTRACTABLE=TRUE) and the domain
        must match between source and backup partition.

        Args:
            source_slot_id: The slot ID of the source partition
            domain: The cloning domain (must match on backup partition)
            labels: Optional list of specific object labels to back up.
                    If None, backs up all extractable objects.
        """
        self._require_login()

        # Get source objects
        source_partition = self.storage.get_partition(source_slot_id)
        if source_partition is None:
            raise PKCS11Error(CKR_TOKEN_NOT_PRESENT,
                              f"Source slot {source_slot_id} not found")

        all_objects = self.storage.get_all_objects(source_slot_id)

        # Filter by labels if specified
        if labels:
            all_objects = [(obj, km) for obj, km in all_objects
                           if obj.label() in labels]

        # Filter to clonable objects only
        from pkcs11.constants import CKA_EXTRACTABLE
        clonable = []
        skipped = []
        for obj, km in all_objects:
            if obj.is_extractable():
                clonable.append((obj, km))
            else:
                skipped.append(obj.label())

        if not clonable:
            raise PKCS11Error(CKR_ACTION_PROHIBITED,
                              "No clonable objects found on source partition. "
                              "Objects must have CKA_EXTRACTABLE=TRUE to be backed up.")

        # Find or create a backup partition with matching domain
        partitions = self._get_backup_partitions()
        target_bp = None
        for bp in partitions:
            if bp.domain == domain:
                target_bp = bp
                break
        if target_bp is None:
            # Create a new backup partition for this domain
            next_id = max([p.partition_id for p in partitions], default=0) + 1
            target_bp = BackupPartition(next_id, domain, f"domain_{domain}")
            partitions.append(target_bp)

        # Clone objects
        backed_up = []
        for obj, km in clonable:
            obj_data = json.dumps(obj.to_dict())
            km_hex = km.hex() if km else None
            # Check if object already exists in backup (update vs new)
            existing = None
            for i, (lbl, od, kmh) in enumerate(target_bp.objects):
                if lbl == obj.label():
                    existing = i
                    break
            entry = (obj.label(), obj_data, km_hex)
            if existing is not None:
                target_bp.objects[existing] = entry
            else:
                target_bp.objects.append(entry)
            backed_up.append(obj.label())

        self._save_backup_partitions(partitions)

        if audit:
            audit.log(session_id, "SO", "BackupObjects", success=True,
                       detail=f"src_slot={source_slot_id}, domain={domain}, "
                              f"backed_up={len(backed_up)}, skipped={len(skipped)}")

        return {
            "backed_up": backed_up,
            "skipped_non_extractable": skipped,
            "domain": domain,
            "partition_id": target_bp.partition_id,
        }

    # ------------------------------------------------------------------
    # Restore (clone objects from backup HSM to a partition)
    # ------------------------------------------------------------------

    def restore_objects(self, dest_slot_id: int, domain: str,
                        labels: list = None, audit=None,
                        session_id: int = 0) -> dict:
        """Restore objects from the backup HSM to a destination partition.

        On a real Luna 7: 'partition clone -slot <dest> -domain <dom>'
        (cloning from backup to destination)

        Args:
            dest_slot_id: The slot ID of the destination partition
            domain: The cloning domain (must match backup partition)
            labels: Optional list of specific object labels to restore.
                    If None, restores all objects in the matching backup partition.
        """
        self._require_login()

        dest_partition = self.storage.get_partition(dest_slot_id)
        if dest_partition is None:
            raise PKCS11Error(CKR_TOKEN_NOT_PRESENT,
                              f"Destination slot {dest_slot_id} not found")

        # Find backup partition with matching domain
        partitions = self._get_backup_partitions()
        source_bp = None
        for bp in partitions:
            if bp.domain == domain:
                source_bp = bp
                break
        if source_bp is None:
            raise PKCS11Error(CKR_TOKEN_NOT_RECOGNIZED,
                              f"No backup partition with domain '{domain}' found")

        # Filter by labels if specified
        objects_to_restore = source_bp.objects
        if labels:
            objects_to_restore = [o for o in source_bp.objects if o[0] in labels]

        if not objects_to_restore:
            raise PKCS11Error(CKR_TOKEN_NOT_PRESENT,
                              "No objects to restore from backup partition")

        # Restore objects to destination partition
        from pkcs11.objects import CKObject
        restored = []
        for label, obj_data, km_hex in objects_to_restore:
            obj_dict = json.loads(obj_data)
            obj = CKObject.from_dict(obj_dict)
            km = bytes.fromhex(km_hex) if km_hex else None

            # Check if object already exists on destination (update vs new)
            existing_obj, _ = self.storage.get_object_by_label(dest_slot_id, label)
            if existing_obj is not None:
                self.storage.update_object(existing_obj.handle, obj, km)
            else:
                handle = self.storage.get_max_handle() + 1
                obj.handle = handle
                self.storage.insert_object(handle, dest_slot_id, label, obj, km)
            restored.append(label)

        if audit:
            audit.log(session_id, "SO", "RestoreObjects", success=True,
                       detail=f"dest_slot={dest_slot_id}, domain={domain}, "
                              f"restored={len(restored)}")

        return {
            "restored": restored,
            "domain": domain,
            "partition_id": source_bp.partition_id,
        }

    # ------------------------------------------------------------------
    # Status and info
    # ------------------------------------------------------------------

    def get_status(self) -> dict:
        """Return comprehensive backup HSM status."""
        partitions = self._get_backup_partitions()
        total_objects = sum(len(p.objects) for p in partitions)
        return {
            "connected": self._connected,
            "serial": self._serial,
            "model": BACKUP_HSM_MODEL,
            "firmware": self._get_firmware_version(),
            "stm_state": self._get_stm_state(),
            "logged_in": self.is_logged_in(),
            "partition_count": len(partitions),
            "total_objects": total_objects,
            "max_partitions": BACKUP_MAX_PARTITIONS,
            "max_storage": BACKUP_MAX_STORAGE,
        }

    def show_info(self) -> str:
        """Return formatted backup HSM info."""
        s = self.get_status()
        lines = [
            f"  Model:            {s['model']}",
            f"  Serial:           {s['serial'] or 'N/A'}",
            f"  Firmware:         {s['firmware']}",
            f"  Connected:        {'Yes' if s['connected'] else 'No'}",
            f"  STM State:        {s['stm_state']}",
            f"  Logged In:        {'Yes' if s['logged_in'] else 'No'}",
            f"  Partitions:       {s['partition_count']} / {s['max_partitions']}",
            f"  Total Objects:    {s['total_objects']}",
            f"  Max Storage:      {s['max_storage']} bytes",
        ]
        return "\n".join(lines)

    def list_backups(self) -> str:
        """Return formatted list of backup partitions and their objects."""
        self._require_login()
        partitions = self._get_backup_partitions()
        if not partitions:
            return "  No backup partitions on the backup HSM."

        lines = [
            f"  {'ID':<6} {'Domain':<25} {'Label':<25} {'Objects':<10} {'Created'}",
            "  " + "-" * 95,
        ]
        for p in partitions:
            created = time.strftime("%Y-%m-%d %H:%M:%S",
                                    time.localtime(p.created_at))
            lines.append(
                f"  {p.partition_id:<6} {p.domain:<25} {p.label:<25} "
                f"{len(p.objects):<10} {created}"
            )

        lines.append("")
        for p in partitions:
            if p.objects:
                lines.append(f"  Partition {p.partition_id} (domain: {p.domain}):")
                for label, _, _ in p.objects:
                    lines.append(f"    - {label}")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Firmware management
    # ------------------------------------------------------------------

    def get_firmware_info(self) -> dict:
        """Return backup HSM firmware info."""
        current = self._get_firmware_version()
        from hsm.token import AVAILABLE_FIRMWARES, _compare_versions
        latest = AVAILABLE_FIRMWARES[-1]["version"]
        return {
            "current_version": current,
            "latest_version": latest,
            "update_available": _compare_versions(latest, current) > 0,
            "model": BACKUP_HSM_MODEL,
            "serial": self._serial,
        }

    def upgrade_firmware(self, target_version: str, audit=None,
                         session_id: int = 0) -> dict:
        """Upgrade backup HSM firmware.

        On a real Luna 7: 'hsm updatefw -fuf <file> -authcode <file>'
        The previous firmware is stored in reserve for rollback.
        """
        if not self._connected:
            raise PKCS11Error(CKR_TOKEN_NOT_PRESENT, "Backup HSM not connected")
        self._require_login()

        from hsm.token import AVAILABLE_FIRMWARES, _compare_versions
        current = self._get_firmware_version()

        # Validate target version exists
        target_fw = None
        for fw in AVAILABLE_FIRMWARES:
            if fw["version"] == target_version:
                target_fw = fw
                break
        if target_fw is None:
            raise PKCS11Error(CKR_TOKEN_NOT_RECOGNIZED,
                              f"Firmware {target_version} not available")

        if _compare_versions(target_version, current) == 0:
            raise PKCS11Error(CKR_ACTION_PROHIBITED,
                              f"Firmware {target_version} is already installed")

        # Store previous version for rollback
        self.storage.set_meta("backup_hsm_prev_firmware", current)

        # Apply upgrade
        self.storage.set_meta("backup_hsm_firmware", target_version)

        if audit:
            audit.log(session_id, "HSO", "BackupHSMFirmwareUpgrade",
                       success=True, detail=f"{current} -> {target_version}")

        return {
            "success": True,
            "previous_version": current,
            "new_version": target_version,
        }

    def rollback_firmware(self, audit=None, session_id: int = 0) -> dict:
        """Roll back backup HSM firmware to the previous version.

        On a real Luna 7: 'hsm rollbackfw'
        CAUTION: This is destructive — all backups are erased.

        On a real Luna 7, rollback zeroizes the HSM. We simulate this
        by clearing all backup partitions but keeping the metadata.
        """
        if not self._connected:
            raise PKCS11Error(CKR_TOKEN_NOT_PRESENT, "Backup HSM not connected")
        self._require_login()

        prev = self.storage.get_meta("backup_hsm_prev_firmware")
        current = self._get_firmware_version()
        if not prev:
            raise PKCS11Error(CKR_ACTION_PROHIBITED,
                              "No previous firmware version available for rollback")

        if prev == current:
            raise PKCS11Error(CKR_ACTION_PROHIBITED,
                              "Previous firmware is the same as current")

        # Destructive: clear all backup partitions (zeroize)
        self._save_backup_partitions([])

        # Roll back firmware
        self.storage.set_meta("backup_hsm_firmware", prev)
        self.storage.set_meta("backup_hsm_prev_firmware", "")

        if audit:
            audit.log(session_id, "HSO", "BackupHSMFirmwareRollback",
                       success=True, detail=f"{current} -> {prev}")

        return {
            "success": True,
            "previous_version": current,
            "new_version": prev,
            "warning": "All backup partitions were erased (zeroized) during rollback.",
        }

    # ------------------------------------------------------------------
    # Factory reset
    # ------------------------------------------------------------------

    def factory_reset(self, audit=None, session_id: int = 0):
        """Reset the backup HSM to factory defaults."""
        if not self._connected:
            raise PKCS11Error(CKR_TOKEN_NOT_PRESENT, "Backup HSM not connected")

        self._save_backup_partitions([])
        self.storage.set_meta("backup_hsm_firmware", BACKUP_HSM_DEFAULT_FW)
        self.storage.set_meta("backup_hsm_prev_firmware", "")
        self.storage.set_meta("backup_hsm_stm_state", STM_STATE_SECURE)
        self.storage.set_meta("backup_hsm_so_pin_hash", "")
        self.storage.set_meta("backup_hsm_so_pin_salt", "")
        self._login_session = None

        if audit:
            audit.log(session_id, "HSO", "BackupHSMFactoryReset",
                       success=True, detail=f"serial={self._serial}")
