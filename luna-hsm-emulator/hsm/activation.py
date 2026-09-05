"""PED activation, challenge secrets and simulated battery-backed cache lifetime.

Only a protected quorum-proof identifier is cached: PED key cryptography is
not emulated. Challenge secrets are salted hashes, never plaintext metadata.
Client exit is not an HSM power event; explicit poweroff/reboot/tamper is.
"""
import base64
import json
import math
import time

from hsm.ped import PEDManager, PEDError
from hsm.lifecycle import PartitionLifecycleManager
from pkcs11.constants import (
    PKCS11Error, CKR_ACTION_PROHIBITED, CKR_PIN_INCORRECT, CKR_PIN_LOCKED,
    CKR_PIN_LEN_RANGE, CKR_USER_PIN_NOT_INITIALIZED, CKR_DEVICE_ERROR,
)


class ActivationManager:
    META_KEY = "ped_activation"
    AUTO_ACTIVATION_SECONDS = 2 * 60 * 60
    ROLES = ("CO", "LCO", "CU")

    def __init__(self, storage):
        self.storage = storage

    def _load(self):
        raw = self.storage.get_meta(self.META_KEY)
        state = json.loads(raw) if raw else {}
        for key, value in {"roles": {}, "power": "on", "off_since": None,
                           "tampered": False, "epoch": 0}.items():
            state.setdefault(key, value)
        return state

    def _save(self, state):
        self.storage.set_meta(self.META_KEY, json.dumps(state))

    def policy(self, slot, number):
        from hsm.policies import get_policy
        return self.storage.get_partition_policies(slot).get(number, get_policy(number).default_value)

    @staticmethod
    def _key(slot, role):
        return f"{slot}:{role.upper()}"

    def device_status(self):
        state = self._load()
        return {key: state[key] for key in ("power", "off_since", "tampered", "epoch")}

    def require_online(self):
        state = self._load()
        if state["power"] != "on" or state["tampered"]:
            raise PKCS11Error(CKR_DEVICE_ERROR, "HSM is powered off or has an uncleared tamper")

    def _require_role(self, slot, role):
        self.require_online()
        if PEDManager(self.storage).get_auth_mode() != "ped" or role not in self.ROLES:
            raise PKCS11Error(CKR_ACTION_PROHIBITED, "Activation requires a PED CO/LCO/CU role")
        if not PartitionLifecycleManager(self.storage).role_active(slot, role):
            raise PKCS11Error(CKR_USER_PIN_NOT_INITIALIZED, "Initialize the role first")
        if not self.policy(slot, 22):
            raise PKCS11Error(CKR_ACTION_PROHIBITED, "Enable partition policy 22 first")

    def _validate_secret(self, slot, secret):
        if not isinstance(secret, str) or not (255 - self.policy(slot, 25) <= len(secret) <= self.policy(slot, 26)):
            raise PKCS11Error(CKR_PIN_LEN_RANGE, "Challenge secret does not meet partition PIN length policy")
        allowed = "!#$%'()*+,-./0123456789:=? @ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_abcdefghijklmnopqrstuvwxyz{}~"
        if secret.startswith(" ") or any(c not in allowed for c in secret):
            raise PKCS11Error(CKR_ACTION_PROHIBITED, "Invalid challenge-secret characters")

    def create_challenge(self, slot, role, secret, actor_role, reset=False):
        role = role.upper()
        self._require_role(slot, role)
        superior = "SO" if role == "CO" else "CO"
        if actor_role != superior:
            raise PKCS11Error(CKR_ACTION_PROHIBITED, f"{superior} authorization required")
        state = self._load()
        key = self._key(slot, role)
        if key in state["roles"] and not reset:
            raise PKCS11Error(CKR_ACTION_PROHIBITED, "Challenge already exists; change or reset it")
        self._validate_secret(slot, secret)
        digest, salt = self.storage.hash_pin(secret)
        state["roles"][key] = {"hash": digest, "salt": salt, "cache": None,
                                "auto_armed": False, "attempts": 0, "locked": False}
        self._save(state)
        self._audit("CreateChallenge" if not reset else "ResetChallenge", slot, role)

    def _verify(self, state, slot, role, secret):
        entry = state["roles"][self._key(slot, role)]
        if entry["locked"]:
            raise PKCS11Error(CKR_PIN_LOCKED, "Challenge secret is locked; superior role must reset it")
        if not self.storage.verify_pin(secret or "", entry["hash"], entry["salt"]):
            if not self.policy(slot, 15):
                entry["attempts"] += 1
                entry["locked"] = entry["attempts"] >= self.policy(slot, 20)
                if entry["locked"]:
                    entry["cache"] = None
                    entry["auto_armed"] = False
            self._save(state)
            raise PKCS11Error(CKR_PIN_LOCKED if entry["locked"] else CKR_PIN_INCORRECT,
                              "Incorrect challenge secret")
        entry["attempts"] = 0

    def change_challenge(self, slot, role, old_secret, new_secret, actor_role):
        role = role.upper()
        self._require_role(slot, role)
        if actor_role != role:
            raise PKCS11Error(CKR_ACTION_PROHIBITED, "Log in as the role whose challenge is changing")
        state = self._load()
        if self._key(slot, role) not in state["roles"]:
            raise PKCS11Error(CKR_USER_PIN_NOT_INITIALIZED, "No challenge secret")
        self._verify(state, slot, role, old_secret)
        self._validate_secret(slot, new_secret)
        entry = state["roles"][self._key(slot, role)]
        entry["hash"], entry["salt"] = self.storage.hash_pin(new_secret)
        self._save(state)
        self._audit("ChangeChallenge", slot, role)

    def status(self, slot, role):
        role = role.upper()
        state = self._load()
        entry = state["roles"].get(self._key(slot, role), {})
        enabled = role in self.ROLES and bool(self.policy(slot, 22))
        cached = bool(entry.get("cache")) and enabled and not state["tampered"] and state["power"] == "on"
        return {"challenge_configured": bool(entry), "activation_enabled": enabled,
                "activated": cached, "auto_activation_enabled": enabled and bool(self.policy(slot, 23)),
                "auto_activation_armed": cached and entry.get("auto_armed", False),
                "locked": entry.get("locked", False), "failed_attempts": entry.get("attempts", 0)}

    def authenticate(self, slot, role, challenge, ped_keys=None, ped_secret=None):
        self._require_role(slot, role)
        state = self._load()
        if self._key(slot, role) not in state["roles"]:
            raise PKCS11Error(CKR_USER_PIN_NOT_INITIALIZED, "No challenge secret")
        self._verify(state, slot, role, challenge)
        entry = state["roles"][self._key(slot, role)]
        if not entry["cache"]:
            color = "gray" if role == "CU" else "black"
            try:
                proof = PEDManager(self.storage).authenticate(color, ped_keys or [], ped_secret, str(slot))
            except PEDError as error:
                raise PKCS11Error(CKR_PIN_INCORRECT, str(error)) from error
            entry["cache"] = base64.b64encode(
                self.storage.encrypt_blob(proof.key_set_id.encode())).decode()
        entry["auto_armed"] = bool(self.policy(slot, 23))
        self._save(state)
        self._audit("PEDActivate", slot, role)

    def deactivate(self, slot, role, actor_role):
        role = role.upper()
        if role not in self.ROLES or actor_role not in ("SO", "CO", "LCO", "CU"):
            raise PKCS11Error(CKR_ACTION_PROHIBITED, "PO/CO/LCO/CU authorization required")
        self.invalidate(slot, role)
        self._audit("PEDDeactivate", slot, role)

    def invalidate(self, slot=None, role=None, forget=False):
        state = self._load()
        for key, entry in list(state["roles"].items()):
            entry_slot, entry_role = key.split(":")
            if slot is not None and entry_slot != str(slot):
                continue
            if role is not None and entry_role != role.upper():
                continue
            if forget:
                del state["roles"][key]
            else:
                entry["cache"] = None
                entry["auto_armed"] = False
        self._save(state)

    def policy_changed(self, slot):
        state = self._load()
        for key, entry in state["roles"].items():
            if not key.startswith(f"{slot}:"):
                continue
            if not self.policy(slot, 22):
                entry["cache"] = None
            if not self.policy(slot, 22) or not self.policy(slot, 23):
                entry["auto_armed"] = False
        self._save(state)

    def poweroff(self):
        state = self._load()
        if state["power"] == "off":
            return self.device_status()
        state["power"] = "off"
        state["off_since"] = time.time()
        state["epoch"] += 1
        for key, entry in state["roles"].items():
            slot = int(key.split(":")[0])
            if not (entry["auto_armed"] and self.policy(slot, 22) and self.policy(slot, 23)):
                entry["cache"] = None
        self._save(state)
        return self.device_status()

    def reboot(self, downtime_seconds=0):
        if not isinstance(downtime_seconds, (int, float)) or not math.isfinite(downtime_seconds) or downtime_seconds < 0:
            raise ValueError("Downtime must be a finite non-negative number of seconds")
        state = self._load()
        elapsed = max(downtime_seconds, time.time() - state["off_since"]) if state["off_since"] is not None else downtime_seconds
        for key, entry in state["roles"].items():
            slot = int(key.split(":")[0])
            keep = (not state["tampered"] and entry["auto_armed"] and
                    self.policy(slot, 22) and self.policy(slot, 23) and
                    elapsed <= self.AUTO_ACTIVATION_SECONDS)
            if not keep:
                entry["cache"] = None
                entry["auto_armed"] = False
        state.update(power="on", off_since=None, epoch=state["epoch"] + 1)
        self._save(state)
        self._audit("HSMReboot", 0, "HSO")
        return self.device_status()

    def tamper(self):
        self.invalidate()
        state = self._load()
        state["tampered"] = True
        state["epoch"] += 1
        self._save(state)
        self._audit("HSMTamper", 0, "HSO")

    def clear_tamper(self):
        state = self._load()
        state["tampered"] = False
        state["epoch"] += 1
        self._save(state)
        self._audit("HSMClearTamper", 0, "HSO")

    def _audit(self, operation, slot, role):
        from hsm.audit import AuditLogger
        AuditLogger(self.storage).log(0, role, operation, detail=f"slot={slot}, role={role}")
