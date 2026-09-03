"""Luna PED and PED-key quorum simulation.

The implementation models PED keys as persistent training artifacts.  It does
not attempt to reproduce the cryptography or physical security of a real PED.
"""

import json
import secrets
from dataclasses import dataclass
from typing import Optional


PED_KEY_TYPES = {
    "blue": {"color": "Blue", "identity": "HSM/Partition Security Officer", "role": "SO"},
    "black": {"color": "Black", "identity": "Crypto Officer", "role": "CO"},
    "gray": {"color": "Gray", "identity": "Crypto User", "role": "CU"},
    "red": {"color": "Red", "identity": "Cloning Domain", "role": "DOMAIN"},
    "orange": {"color": "Orange", "identity": "Remote PED Vector", "role": "REMOTE"},
    "white": {"color": "White", "identity": "Audit Identity", "role": "AUDIT"},
}


class PEDError(Exception):
    """A PED operation failed with a stable, Luna-like error code."""

    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


@dataclass
class PEDAuthResult:
    key_set_id: str
    key_type: str
    shares_presented: int
    threshold: int
    domain_id: Optional[str] = None


class PEDManager:
    """Persist and validate local/remote PED state and M-of-N key sets."""

    META_KEY = "ped_state"

    def __init__(self, storage):
        self.storage = storage

    def _default_state(self) -> dict:
        return {
            "auth_mode": "password",
            "hsm_label": "",
            "connection": {"state": "disconnected", "mode": None, "host": None},
            "key_sets": [],
        }

    def _load(self) -> dict:
        raw = self.storage.get_meta(self.META_KEY)
        if not raw:
            return self._default_state()
        try:
            state = json.loads(raw)
        except (TypeError, json.JSONDecodeError):
            return self._default_state()
        default = self._default_state()
        default.update(state)
        return default

    def _save(self, state: dict):
        self.storage.set_meta(self.META_KEY, json.dumps(state))

    def configure_hsm(self, label: str, auth_mode: str):
        mode = auth_mode.lower()
        if mode not in ("password", "ped"):
            raise PEDError("PED_INVALID_AUTH_MODE", "Authentication mode must be password or PED")
        state = self._load()
        state["hsm_label"] = label
        state["auth_mode"] = mode
        if mode == "password":
            state["connection"] = {"state": "disconnected", "mode": None, "host": None}
        self._save(state)

    def get_auth_mode(self) -> str:
        return self._load()["auth_mode"]

    def factory_reset(self):
        """Erase all PED vectors, key sets, and connection state."""
        self._save(self._default_state())

    def connect(self, remote_host: str = None, orange_serials: list = None,
                shared_secret: str = None) -> dict:
        state = self._load()
        if remote_host:
            orange_sets = [s for s in state["key_sets"] if s["type"] == "orange"]
            if not orange_sets:
                raise PEDError("PED_REMOTE_VECTOR_REQUIRED",
                               "Remote PED requires an initialized Orange Remote PED key")
            if not orange_serials:
                raise PEDError("PED_REMOTE_VECTOR_REQUIRED",
                               "Present the Orange PED key quorum for remote PED connection")
            self._authenticate(state, "orange", orange_serials, shared_secret,
                               "hsm", require_connection=False)
            state["connection"] = {"state": "connected", "mode": "remote", "host": remote_host}
        else:
            state["connection"] = {"state": "connected", "mode": "local", "host": None}
        self._save(state)
        return state["connection"]

    def disconnect(self):
        state = self._load()
        state["connection"] = {"state": "disconnected", "mode": None, "host": None}
        self._save(state)

    def status(self) -> dict:
        state = self._load()
        result = dict(state["connection"])
        result["auth_mode"] = state["auth_mode"]
        result["hsm_label"] = state["hsm_label"]
        result["key_set_count"] = len(state["key_sets"])
        return result

    @staticmethod
    def _normalize_scope(scope) -> str:
        return "hsm" if scope in (None, "", "hsm") else str(scope)

    def create_key_set(self, key_type: str, m: int = 1, n: int = 1,
                       shared_secret: str = None, scope: str = "hsm") -> dict:
        key_type = key_type.lower()
        if key_type not in PED_KEY_TYPES:
            raise PEDError("PED_INVALID_KEY_TYPE",
                           f"Unknown PED key type '{key_type}'; valid colors: {', '.join(PED_KEY_TYPES)}")
        if not isinstance(m, int) or not isinstance(n, int) or m < 1 or n < 1 or m > n:
            raise PEDError("PED_INVALID_QUORUM", "Quorum must satisfy 1 <= M <= N")
        state = self._load()
        if state["connection"]["state"] != "connected":
            raise PEDError("PED_NOT_CONNECTED", "Connect a local or remote PED first")
        scope = self._normalize_scope(scope)
        key_set = {
            "id": "KS-" + secrets.token_hex(4).upper(),
            "type": key_type,
            "m": m,
            "n": n,
            "scope": scope,
            "created_with": state["connection"]["mode"],
            "shares": [],
            "secret_hash": None,
            "secret_salt": None,
            "domain_id": "DOM-" + secrets.token_hex(8).upper() if key_type == "red" else None,
        }
        if shared_secret:
            key_set["secret_hash"], key_set["secret_salt"] = self.storage.hash_pin(shared_secret)
        for share_number in range(1, n + 1):
            serial = self._new_serial(key_type)
            key_set["shares"].append({
                "share": share_number,
                "copies": [{"serial": serial, "status": "active"}],
            })
        state["key_sets"].append(key_set)
        self._save(state)
        return key_set

    @staticmethod
    def _new_serial(key_type: str) -> str:
        return f"{key_type[:2].upper()}-{secrets.token_hex(4).upper()}"

    def list_key_sets(self) -> list:
        return self._load()["key_sets"]

    def duplicate_key(self, serial: str, count: int = 1) -> list:
        if count < 1:
            raise PEDError("PED_INVALID_DUPLICATE_COUNT", "Duplicate count must be positive")
        state = self._load()
        if state["connection"]["state"] != "connected":
            raise PEDError("PED_NOT_CONNECTED", "Connect a PED before duplicating a key")
        found = self._find_copy(state, serial)
        if not found:
            raise PEDError("PED_KEY_NOT_FOUND", f"PED key {serial} was not found")
        key_set, share, copy = found
        if copy["status"] != "active":
            raise PEDError("PED_KEY_LOST", f"PED key {serial} is marked lost")
        duplicates = []
        for _ in range(count):
            new_copy = {"serial": self._new_serial(key_set["type"]), "status": "active"}
            share["copies"].append(new_copy)
            duplicates.append(new_copy["serial"])
        self._save(state)
        return duplicates

    def mark_lost(self, serial: str) -> dict:
        state = self._load()
        found = self._find_copy(state, serial)
        if not found:
            raise PEDError("PED_KEY_NOT_FOUND", f"PED key {serial} was not found")
        key_set, share, copy = found
        copy["status"] = "lost"
        available = self._available_shares(key_set)
        self._save(state)
        return {
            "serial": serial,
            "key_set_id": key_set["id"],
            "available_shares": available,
            "threshold": key_set["m"],
            "recoverable": available >= key_set["m"],
        }

    @staticmethod
    def _find_copy(state: dict, serial: str):
        for key_set in state["key_sets"]:
            for share in key_set["shares"]:
                for copy in share["copies"]:
                    if copy["serial"].upper() == serial.upper():
                        return key_set, share, copy
        return None

    @staticmethod
    def _available_shares(key_set: dict) -> int:
        return sum(any(c["status"] == "active" for c in share["copies"])
                   for share in key_set["shares"])

    def requires_shared_secret(self, key_type: str, scope: str = "hsm") -> bool:
        scope = self._normalize_scope(scope)
        return any(s["type"] == key_type.lower() and s["scope"] == scope and s.get("secret_hash")
                   for s in self._load()["key_sets"])

    def authenticate(self, key_type: str, serials: list, shared_secret: str = None,
                     scope: str = "hsm") -> PEDAuthResult:
        return self._authenticate(self._load(), key_type.lower(), serials,
                                  shared_secret, self._normalize_scope(scope), True)

    def _authenticate(self, state: dict, key_type: str, serials: list,
                      shared_secret: str, scope: str, require_connection: bool) -> PEDAuthResult:
        if require_connection and state["connection"]["state"] != "connected":
            raise PEDError("PED_NOT_CONNECTED", "No local or remote PED is connected")
        if not serials:
            raise PEDError("PED_KEY_REQUIRED", f"Present {PED_KEY_TYPES[key_type]['color']} PED key(s)")

        resolved = []
        for serial in serials:
            found = self._find_copy(state, serial.strip())
            if not found:
                raise PEDError("PED_WRONG_KEY", f"PED key {serial} is unknown")
            key_set, share, copy = found
            if copy["status"] != "active":
                raise PEDError("PED_KEY_LOST", f"PED key {serial} is marked lost")
            if key_set["type"] != key_type:
                expected = PED_KEY_TYPES[key_type]["color"]
                actual = PED_KEY_TYPES[key_set["type"]]["color"]
                raise PEDError("PED_WRONG_KEY", f"Expected {expected} key; {serial} is a {actual} key")
            if key_set["scope"] != scope:
                raise PEDError("PED_WRONG_KEY", f"PED key {serial} belongs to scope {key_set['scope']}, not {scope}")
            resolved.append((key_set, share))

        set_ids = {item[0]["id"] for item in resolved}
        if len(set_ids) != 1:
            raise PEDError("PED_KEYSET_MISMATCH", "Presented PED keys are from different key sets")
        key_set = resolved[0][0]
        distinct_shares = {share["share"] for _, share in resolved}
        if len(distinct_shares) < key_set["m"]:
            raise PEDError("PED_QUORUM_NOT_MET",
                           f"Presented {len(distinct_shares)} distinct share(s); {key_set['m']} required")
        if key_set.get("secret_hash"):
            if not shared_secret or not self.storage.verify_pin(
                    shared_secret, key_set["secret_hash"], key_set["secret_salt"]):
                raise PEDError("PED_SHARED_SECRET_INCORRECT", "Shared secret is incorrect")
        return PEDAuthResult(key_set["id"], key_type, len(distinct_shares),
                             key_set["m"], key_set.get("domain_id"))

    def verify_cloning_domain(self, serials: list, expected_domain: str,
                              shared_secret: str = None, scope: str = "hsm") -> PEDAuthResult:
        result = self.authenticate("red", serials, shared_secret, scope)
        if result.domain_id != expected_domain:
            raise PEDError("PED_CLONING_DOMAIN_MISMATCH",
                           "Presented Red PED keys have the wrong cloning domain")
        return result
