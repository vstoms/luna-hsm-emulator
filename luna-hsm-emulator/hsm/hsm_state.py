"""Persistent HSM-level identity and lifecycle state.

The HSM Security Officer is independent of every application partition.  A
Network HSM can therefore be initialized and the HSM SO can authenticate when
no application partitions exist.
"""

import json


class HSMStateManager:
    META_KEY = "hsm_state"
    MAX_SO_ATTEMPTS = 3

    def __init__(self, storage):
        self.storage = storage

    @staticmethod
    def _default() -> dict:
        return {
            "initialized": False,
            "zeroized": True,
            "label": "",
            "auth_mode": "password",
            "so_pin_hash": "",
            "so_pin_salt": "",
            "failed_so_attempts": 0,
        }

    def load(self) -> dict:
        raw = self.storage.get_meta(self.META_KEY)
        if not raw:
            return self._default()
        try:
            state = self._default()
            state.update(json.loads(raw))
            return state
        except (TypeError, json.JSONDecodeError):
            return self._default()

    def save(self, state: dict) -> None:
        self.storage.set_meta(self.META_KEY, json.dumps(state))

    def initialize(self, label: str, auth_mode: str,
                   so_password: str = None, soft: bool = False) -> dict:
        state = self.load()
        if soft and state["initialized"]:
            # Soft initialization preserves the existing HSM SO and admin
            # cloning domain; only the label and user partitions change.
            state["label"] = label
            state["zeroized"] = False
            state["failed_so_attempts"] = 0
            self.save(state)
            return state

        state = self._default()
        state.update({"initialized": True, "zeroized": False,
                      "label": label, "auth_mode": auth_mode})
        if auth_mode == "password":
            if not so_password:
                raise ValueError("HSM SO password is required")
            state["so_pin_hash"], state["so_pin_salt"] = self.storage.hash_pin(so_password)
        self.save(state)
        return state

    def authenticate_password(self, password: str) -> tuple:
        """Return ``(authenticated, zeroize_required, attempts_remaining)``."""
        state = self.load()
        if not state["initialized"] or state["auth_mode"] != "password":
            return False, False, self.MAX_SO_ATTEMPTS
        valid = bool(password) and self.storage.verify_pin(
            password, state["so_pin_hash"], state["so_pin_salt"])
        if valid:
            state["failed_so_attempts"] = 0
            self.save(state)
            return True, False, self.MAX_SO_ATTEMPTS
        state["failed_so_attempts"] += 1
        remaining = max(0, self.MAX_SO_ATTEMPTS - state["failed_so_attempts"])
        zeroize = remaining == 0
        self.save(state)
        return False, zeroize, remaining

    def mark_zeroized(self) -> dict:
        state = self.load()
        state.update({
            "initialized": False,
            "zeroized": True,
            "label": "",
            "so_pin_hash": "",
            "so_pin_salt": "",
            "failed_so_attempts": 0,
        })
        self.save(state)
        return state

    def factory_reset(self) -> dict:
        state = self._default()
        self.save(state)
        return state
