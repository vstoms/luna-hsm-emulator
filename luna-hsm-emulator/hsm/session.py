"""Session management for the Luna 7 HSM emulator.

Supports multiple simultaneous sessions per partition with R/W and R/O
session types, matching the PKCS#11 session model.
"""

import time
from typing import Optional

from pkcs11.constants import (
    PKCS11Error, CKR_SESSION_HANDLE_INVALID, CKR_SESSION_COUNT,
    CKR_SESSION_READ_ONLY, CKR_SESSION_PARALLEL_NOT_SUPPORTED,
    CKF_SERIAL_SESSION, CKF_RW_SESSION,
    CKU_SO, CKU_USER,
)

MAX_SESSIONS = 32


class Session:
    """A single PKCS#11 session."""

    def __init__(self, session_id: int, slot_id: int, flags: int):
        self.session_id = session_id
        self.slot_id = slot_id
        self.flags = flags
        self.is_rw = bool(flags & CKF_RW_SESSION)
        self.user_type: Optional[int] = None  # None = not logged in
        self.created_at = time.time()
        # Operation state
        self._find_active = False
        self._find_results: list = []
        self._encrypt_active = False
        self._decrypt_active = False
        self._sign_active = False
        self._verify_active = False
        self._digest_active = False
        self._encrypt_key = None
        self._decrypt_key = None
        self._sign_key = None
        self._verify_key = None
        self._encrypt_mech = None
        self._decrypt_mech = None
        self._sign_mech = None
        self._verify_mech = None
        self._digest_mech = None
        self._digest_buffer = b""
        self._sign_buffer = b""
        self._verify_buffer = b""
        self._encrypt_buffer = b""
        self._decrypt_buffer = b""

    @property
    def is_logged_in(self) -> bool:
        return self.user_type is not None


class SessionManager:
    """Manages PKCS#11 sessions."""

    def __init__(self):
        self._sessions: dict = {}
        self._next_id = 1

    def open_session(self, slot_id: int, flags: int = CKF_SERIAL_SESSION) -> int:
        """Open a new session. Returns session ID."""
        if len(self._sessions) >= MAX_SESSIONS:
            raise PKCS11Error(CKR_SESSION_COUNT, "Maximum session count reached")
        session_id = self._next_id
        self._next_id += 1
        self._sessions[session_id] = Session(session_id, slot_id, flags)
        return session_id

    def close_session(self, session_id: int):
        """Close a specific session."""
        if session_id not in self._sessions:
            raise PKCS11Error(CKR_SESSION_HANDLE_INVALID)
        del self._sessions[session_id]

    def close_all_sessions(self, slot_id: int = None):
        """Close all sessions, optionally filtered by slot."""
        if slot_id is None:
            self._sessions.clear()
        else:
            to_remove = [sid for sid, s in self._sessions.items() if s.slot_id == slot_id]
            for sid in to_remove:
                del self._sessions[sid]

    def get_session(self, session_id: int) -> Session:
        """Return the session or raise."""
        s = self._sessions.get(session_id)
        if s is None:
            raise PKCS11Error(CKR_SESSION_HANDLE_INVALID)
        return s

    def get_session_info(self, session_id: int) -> dict:
        """Return session info for C_GetSessionInfo."""
        s = self.get_session(session_id)
        return {
            "slot_id": s.slot_id,
            "state": s.user_type or 0,
            "flags": s.flags,
            "device_error": 0,
        }

    def count_sessions(self, slot_id: int = None) -> int:
        if slot_id is None:
            return len(self._sessions)
        return sum(1 for s in self._sessions.values() if s.slot_id == slot_id)
