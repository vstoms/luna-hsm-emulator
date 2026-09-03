"""Role-based authentication for the Luna 7 HSM emulator.

Roles:
  - HSO  (HSM Security Officer)  — full administrative access
  - SO   (Partition Security Officer) — partition-level admin
  - CO   (Crypto Officer)         — key management
  - CU   (Crypto User)            — cryptographic operations only

PIN-based authentication with configurable lockout (default 10 attempts).
"""

from typing import Optional

from storage.db import Storage
from hsm.ped import PEDManager, PEDError
from hsm.lifecycle import PartitionLifecycleManager
from pkcs11.constants import (
    PKCS11Error, CKR_PIN_INCORRECT, CKR_PIN_LOCKED, CKR_PIN_LEN_RANGE,
    CKR_USER_NOT_LOGGED_IN, CKR_USER_ALREADY_LOGGED_IN,
    CKR_USER_ANOTHER_ALREADY_LOGGED_IN, CKR_USER_PIN_NOT_INITIALIZED,
)

# Role constants
ROLE_HSO = "HSO"
ROLE_SO = "SO"
ROLE_CO = "CO"
ROLE_CU = "CU"

MIN_PIN_LEN = 4
MAX_PIN_LEN = 32

# Maps CLI role names to internal role
ROLE_MAP = {
    "hso": ROLE_HSO,
    "so": ROLE_SO,
    "co": ROLE_CO,
    "cu": ROLE_CU,
}


class AuthManager:
    """Manages authentication state and PIN verification per partition."""

    def __init__(self, storage: Storage):
        self.storage = storage
        self.ped = PEDManager(storage)
        self.lifecycle = PartitionLifecycleManager(storage)
        # session_id -> (slot_id, role)
        self._sessions: dict = {}

    def login(self, session_id: int, slot_id: int, role: str, pin: str):
        """Authenticate *session_id* as *role* on partition *slot_id*."""
        partition = self.storage.get_partition(slot_id)
        if partition is None:
            raise PKCS11Error(CKR_USER_NOT_LOGGED_IN, "Partition not found")

        if not partition.get("initialized"):
            raise PKCS11Error(CKR_USER_PIN_NOT_INITIALIZED,
                              "Partition is uninitialized")
        if not self.lifecycle.status(slot_id)["active"]:
            raise PKCS11Error(CKR_USER_NOT_LOGGED_IN, "Partition is deactivated")
        if not self.lifecycle.role_active(slot_id, role):
            raise PKCS11Error(CKR_USER_NOT_LOGGED_IN,
                              f"{role} role is uninitialized or deactivated")

        # Check if already logged in on this session
        if session_id in self._sessions:
            raise PKCS11Error(CKR_USER_ALREADY_LOGGED_IN)

        # Check for conflicting logins on same partition
        for sid, (slid, r) in self._sessions.items():
            if slid == slot_id and r != role:
                raise PKCS11Error(CKR_USER_ANOTHER_ALREADY_LOGGED_IN)

        # PED-authenticated partitions accept a presentation string in the
        # form "SERIAL1,SERIAL2|optional shared secret".  This keeps C_Login's
        # PKCS#11-compatible signature while allowing quorum training.
        if self.ped.get_auth_mode() == "ped":
            serial_text, separator, shared_secret = (pin or "").partition("|")
            serials = [value.strip() for value in serial_text.split(",") if value.strip()]
            key_type = {ROLE_SO: "blue", ROLE_CO: "black", ROLE_CU: "gray"}.get(role)
            try:
                self.ped.authenticate(key_type, serials,
                                      shared_secret if separator else None,
                                      scope=str(slot_id))
            except PEDError as exc:
                raise PKCS11Error(CKR_PIN_INCORRECT, str(exc)) from exc
            self._sessions[session_id] = (slot_id, role)
            return

        # Validate PIN length
        if len(pin) < MIN_PIN_LEN or len(pin) > MAX_PIN_LEN:
            raise PKCS11Error(CKR_PIN_LEN_RANGE,
                              f"PIN must be {MIN_PIN_LEN}-{MAX_PIN_LEN} characters")

        # Check lockout
        lock_key = f"{role.lower()}_locked"
        if partition.get(lock_key, 0):
            raise PKCS11Error(CKR_PIN_LOCKED,
                              f"{role} role is locked due to too many failed attempts")

        # Get stored PIN hash
        pin_hash_key = f"{role.lower()}_pin_hash"
        pin_salt_key = f"{role.lower()}_pin_salt"
        stored_hash = partition.get(pin_hash_key)
        stored_salt = partition.get(pin_salt_key)

        if not stored_hash or not stored_salt:
            raise PKCS11Error(CKR_USER_PIN_NOT_INITIALIZED,
                              f"{role} PIN not initialized for this partition")

        # Verify PIN
        if not self.storage.verify_pin(pin, stored_hash, stored_salt):
            attempts_key = f"{role.lower()}_login_attempts"
            attempts = partition.get(attempts_key, 0) + 1
            max_attempts = partition.get("max_login_attempts", 10)
            updates = {attempts_key: attempts}
            if attempts >= max_attempts:
                updates[lock_key] = 1
            self.storage.update_partition(slot_id, **updates)
            if attempts >= max_attempts:
                raise PKCS11Error(CKR_PIN_LOCKED,
                                  f"PIN incorrect. {role} role now LOCKED after {attempts} failed attempts.")
            remaining = max_attempts - attempts
            raise PKCS11Error(CKR_PIN_INCORRECT,
                              f"PIN incorrect. {remaining} attempt(s) remaining before lockout.")

        # Reset attempts on success
        self.storage.update_partition(slot_id, **{
            f"{role.lower()}_login_attempts": 0,
        })
        self._sessions[session_id] = (slot_id, role)

    def logout(self, session_id: int):
        """Log out the current session."""
        if session_id not in self._sessions:
            raise PKCS11Error(CKR_USER_NOT_LOGGED_IN)
        del self._sessions[session_id]

    def get_role(self, session_id: int) -> Optional[str]:
        """Return the role of the logged-in session, or None."""
        entry = self._sessions.get(session_id)
        return entry[1] if entry else None

    def get_slot_id(self, session_id: int) -> Optional[int]:
        """Return the slot the session is logged into, or None."""
        entry = self._sessions.get(session_id)
        return entry[0] if entry else None

    def is_logged_in(self, session_id: int) -> bool:
        return session_id in self._sessions

    def set_pin(self, slot_id: int, role: str, pin: str):
        """Set or change the PIN for a role on a partition."""
        if len(pin) < MIN_PIN_LEN or len(pin) > MAX_PIN_LEN:
            raise PKCS11Error(CKR_PIN_LEN_RANGE)
        pin_hash, pin_salt = self.storage.hash_pin(pin)
        self.storage.update_partition(slot_id, **{
            f"{role.lower()}_pin_hash": pin_hash,
            f"{role.lower()}_pin_salt": pin_salt,
            f"{role.lower()}_login_attempts": 0,
            f"{role.lower()}_locked": 0,
        })
        self.lifecycle.set_role_active(slot_id, role, True)

    def change_pin(self, slot_id: int, role: str, old_pin: str, new_pin: str):
        """Change the PIN for a role, verifying the old PIN first."""
        partition = self.storage.get_partition(slot_id)
        if partition is None:
            raise PKCS11Error(CKR_USER_NOT_LOGGED_IN, "Partition not found")
        stored_hash = partition.get(f"{role.lower()}_pin_hash")
        stored_salt = partition.get(f"{role.lower()}_pin_salt")
        if not stored_hash or not stored_salt:
            raise PKCS11Error(CKR_USER_PIN_NOT_INITIALIZED)
        if not self.storage.verify_pin(old_pin, stored_hash, stored_salt):
            raise PKCS11Error(CKR_PIN_INCORRECT, "Old PIN is incorrect")
        self.set_pin(slot_id, role, new_pin)

    def clear_session(self, session_id: int):
        """Remove a session from auth tracking (called on session close)."""
        self._sessions.pop(session_id, None)
