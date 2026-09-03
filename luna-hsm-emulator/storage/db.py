"""SQLite persistence layer with AES-GCM encrypted blobs.

All sensitive key material is encrypted using a master key derived from
the HSM master password via PBKDF2.  The SQLite database stores:
  - HSM metadata (serial, firmware, model)
  - Partitions (slots) and their metadata
  - Objects (keys) with encrypted key material
  - Audit log entries (hash-chained)
  - Role PINs (hashed with PBKDF2)
"""

import os
import json
import sqlite3
import hashlib
import hmac
import struct
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from pkcs11.constants import PKCS11Error, CKR_FUNCTION_FAILED, CKR_DEVICE_MEMORY
from pkcs11.objects import CKObject

DEFAULT_DB_PATH = os.path.join(os.path.expanduser("~"), ".luna_hsm_emulator", "hsm.db")
PBKDF2_ITERATIONS = 100_000


class Storage:
    """Encrypted SQLite storage for the HSM emulator."""

    def __init__(self, db_path: str = None, master_password: str = ""):
        self.db_path = db_path or DEFAULT_DB_PATH
        self.salt_path = self.db_path + ".salt"
        self.master_password = master_password
        self._conn: Optional[sqlite3.Connection] = None
        self._master_key: Optional[bytes] = None
        self._salt: Optional[bytes] = None

    # ------------------------------------------------------------------
    # Master key derivation
    # ------------------------------------------------------------------

    def _ensure_dirs(self):
        d = os.path.dirname(self.db_path)
        if d and not os.path.exists(d):
            os.makedirs(d, exist_ok=True)

    def _derive_master_key(self) -> bytes:
        """Derive the AES-256 master key from the master password."""
        if self._master_key is not None:
            return self._master_key
        if self._salt is None:
            self._load_or_create_salt()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self._salt,
            iterations=PBKDF2_ITERATIONS,
            backend=default_backend(),
        )
        self._master_key = kdf.derive(self.master_password.encode("utf-8"))
        return self._master_key

    def _load_or_create_salt(self):
        self._ensure_dirs()
        if os.path.exists(self.salt_path):
            with open(self.salt_path, "rb") as f:
                self._salt = f.read()
        else:
            self._salt = os.urandom(16)
            with open(self.salt_path, "wb") as f:
                f.write(self._salt)

    # ------------------------------------------------------------------
    # Blob encryption / decryption
    # ------------------------------------------------------------------

    def encrypt_blob(self, plaintext: bytes) -> bytes:
        """Encrypt *plaintext* with AES-256-GCM. Returns nonce + ciphertext + tag."""
        key = self._derive_master_key()
        nonce = os.urandom(12)
        aesgcm = AESGCM(key)
        ct = aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ct

    def decrypt_blob(self, blob: bytes) -> bytes:
        """Decrypt an AES-256-GCM blob (nonce + ciphertext + tag)."""
        key = self._derive_master_key()
        nonce = blob[:12]
        ct = blob[12:]
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ct, None)

    # ------------------------------------------------------------------
    # Database lifecycle
    # ------------------------------------------------------------------

    def open(self):
        """Open the database and create tables if needed."""
        self._ensure_dirs()
        self._conn = sqlite3.connect(self.db_path)
        self._conn.row_factory = sqlite3.Row
        self._create_tables()

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            raise PKCS11Error(CKR_FUNCTION_FAILED, "Database not open")
        return self._conn

    def _create_tables(self):
        c = self._conn.cursor()
        c.executescript("""
            CREATE TABLE IF NOT EXISTS hsm_meta (
                key TEXT PRIMARY KEY,
                value TEXT
            );

            CREATE TABLE IF NOT EXISTS partitions (
                slot_id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                label TEXT,
                initialized INTEGER DEFAULT 0,
                max_objects INTEGER DEFAULT 1024,
                max_storage INTEGER DEFAULT 1048576,
                so_pin_hash TEXT,
                so_pin_salt TEXT,
                co_pin_hash TEXT,
                co_pin_salt TEXT,
                cu_pin_hash TEXT,
                cu_pin_salt TEXT,
                so_login_attempts INTEGER DEFAULT 0,
                co_login_attempts INTEGER DEFAULT 0,
                cu_login_attempts INTEGER DEFAULT 0,
                so_locked INTEGER DEFAULT 0,
                co_locked INTEGER DEFAULT 0,
                cu_locked INTEGER DEFAULT 0,
                max_login_attempts INTEGER DEFAULT 10,
                flags INTEGER DEFAULT 0,
                created_at REAL
            );

            CREATE TABLE IF NOT EXISTS objects (
                handle INTEGER PRIMARY KEY,
                slot_id INTEGER NOT NULL,
                label TEXT,
                object_data TEXT NOT NULL,
                key_material BLOB,
                created_at REAL,
                FOREIGN KEY (slot_id) REFERENCES partitions(slot_id)
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                session_id INTEGER,
                role TEXT,
                operation TEXT NOT NULL,
                object_label TEXT,
                object_handle INTEGER,
                success INTEGER NOT NULL,
                detail TEXT,
                prev_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS session_state (
                session_id INTEGER PRIMARY KEY,
                slot_id INTEGER,
                flags INTEGER,
                user_type INTEGER,
                is_rw INTEGER,
                created_at REAL
            );
        """)
        self._conn.commit()

    # ------------------------------------------------------------------
    # HSM metadata
    # ------------------------------------------------------------------

    def get_meta(self, key: str, default=None):
        c = self.conn.cursor()
        row = c.execute("SELECT value FROM hsm_meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default

    def set_meta(self, key: str, value: str):
        c = self.conn.cursor()
        c.execute(
            "INSERT INTO hsm_meta (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )
        self._conn.commit()

    # ------------------------------------------------------------------
    # Partition policies
    # ------------------------------------------------------------------

    def get_partition_policies(self, slot_id: int) -> dict:
        """Return dict of policy_id -> value for a partition."""
        import json
        raw = self.get_meta(f"policies_slot_{slot_id}")
        if raw:
            try:
                return {int(k): v for k, v in json.loads(raw).items()}
            except (json.JSONDecodeError, TypeError):
                pass
        return {}

    def set_partition_policies(self, slot_id: int, policies: dict):
        """Persist partition policies as JSON in hsm_meta."""
        import json
        self.set_meta(f"policies_slot_{slot_id}", json.dumps(policies))

    def get_partition_policy(self, slot_id: int, policy_id: int) -> Optional[int]:
        policies = self.get_partition_policies(slot_id)
        return policies.get(policy_id)

    def set_partition_policy(self, slot_id: int, policy_id: int, value: int):
        policies = self.get_partition_policies(slot_id)
        policies[policy_id] = value
        self.set_partition_policies(slot_id, policies)

    # ------------------------------------------------------------------
    # Partition policy templates (PPT)
    # ------------------------------------------------------------------

    def get_all_ppt_templates(self) -> dict:
        """Return all stored PPT templates as {name: {policies, description}}."""
        import json
        raw = self.get_meta("ppt_templates")
        if raw:
            try:
                templates = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                return {}
            # Convert string keys back to int for policies in each template
            result = {}
            for name, t in templates.items():
                policies = {int(k): v for k, v in t.get("policies", {}).items()}
                result[name] = {"description": t.get("description", ""), "policies": policies}
            return result
        return {}

    def get_ppt_template(self, name: str) -> Optional[dict]:
        import json
        raw = self.get_meta("ppt_templates")
        if raw:
            try:
                templates = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                return None
            if name in templates:
                t = templates[name]
                # Convert string keys back to int for policies
                policies = {int(k): v for k, v in t.get("policies", {}).items()}
                return {"description": t.get("description", ""), "policies": policies}
        return None

    def save_ppt_template(self, name: str, description: str, policies: dict):
        import json
        templates = self.get_all_ppt_templates()
        templates[name] = {"description": description, "policies": policies}
        self.set_meta("ppt_templates", json.dumps(templates))

    def delete_ppt_template(self, name: str) -> bool:
        import json
        templates = self.get_all_ppt_templates()
        if name in templates:
            del templates[name]
            self.set_meta("ppt_templates", json.dumps(templates))
            return True
        return False

    # ------------------------------------------------------------------
    # Partition CRUD
    # ------------------------------------------------------------------

    def insert_partition(self, slot_id: int, name: str, label: str,
                         max_objects: int = 1024, max_storage: int = 1048576,
                         max_login_attempts: int = 10, flags: int = 0,
                         created_at: float = None):
        import time
        c = self.conn.cursor()
        c.execute(
            """INSERT INTO partitions
               (slot_id, name, label, max_objects, max_storage,
                max_login_attempts, flags, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (slot_id, name, label, max_objects, max_storage,
             max_login_attempts, flags, created_at or time.time()),
        )
        self._conn.commit()

    def get_partition(self, slot_id: int) -> Optional[dict]:
        c = self.conn.cursor()
        row = c.execute("SELECT * FROM partitions WHERE slot_id = ?", (slot_id,)).fetchone()
        return dict(row) if row else None

    def get_partition_by_name(self, name: str) -> Optional[dict]:
        c = self.conn.cursor()
        row = c.execute("SELECT * FROM partitions WHERE name = ?", (name,)).fetchone()
        return dict(row) if row else None

    def get_all_partitions(self) -> list:
        c = self.conn.cursor()
        rows = c.execute("SELECT * FROM partitions ORDER BY slot_id").fetchall()
        return [dict(r) for r in rows]

    def update_partition(self, slot_id: int, **kwargs):
        if not kwargs:
            return
        sets = ", ".join(f"{k} = ?" for k in kwargs)
        vals = list(kwargs.values()) + [slot_id]
        c = self.conn.cursor()
        c.execute(f"UPDATE partitions SET {sets} WHERE slot_id = ?", vals)
        self._conn.commit()

    def delete_partition(self, slot_id: int):
        c = self.conn.cursor()
        c.execute("DELETE FROM objects WHERE slot_id = ?", (slot_id,))
        c.execute("DELETE FROM partitions WHERE slot_id = ?", (slot_id,))
        self._conn.commit()

    # ------------------------------------------------------------------
    # Object CRUD
    # ------------------------------------------------------------------

    def insert_object(self, handle: int, slot_id: int, label: str,
                      obj: CKObject, key_material: bytes = None):
        obj_data = json.dumps(obj.to_dict())
        encrypted_material = None
        if key_material is not None:
            encrypted_material = self.encrypt_blob(key_material)
        partition = self.get_partition(slot_id)
        if partition is None:
            raise PKCS11Error(CKR_DEVICE_MEMORY, f"Partition slot {slot_id} not found")
        if self.count_objects(slot_id) >= partition["max_objects"]:
            raise PKCS11Error(CKR_DEVICE_MEMORY,
                              f"Partition object quota exceeded ({partition['max_objects']})")
        payload_size = len(obj_data.encode("utf-8")) + len(encrypted_material or b"")
        used = self.get_partition_storage_used(slot_id)
        if used + payload_size > partition["max_storage"]:
            raise PKCS11Error(
                CKR_DEVICE_MEMORY,
                f"Partition storage quota exceeded ({used} + {payload_size} > {partition['max_storage']} bytes)",
            )
        c = self.conn.cursor()
        c.execute(
            """INSERT INTO objects (handle, slot_id, label, object_data, key_material, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (handle, slot_id, label, obj_data, encrypted_material, obj.created_at),
        )
        self._conn.commit()

    def update_object(self, handle: int, obj: CKObject, key_material: bytes = None):
        obj_data = json.dumps(obj.to_dict())
        encrypted_material = None
        if key_material is not None:
            encrypted_material = self.encrypt_blob(key_material)
        c = self.conn.cursor()
        current = c.execute(
            "SELECT slot_id, LENGTH(object_data) AS object_len, "
            "COALESCE(LENGTH(key_material), 0) AS key_len FROM objects WHERE handle = ?",
            (handle,),
        ).fetchone()
        if current:
            partition = self.get_partition(current["slot_id"])
            used = self.get_partition_storage_used(current["slot_id"])
            old_size = current["object_len"] + current["key_len"]
            new_key_size = len(encrypted_material) if encrypted_material is not None else current["key_len"]
            new_size = len(obj_data.encode("utf-8")) + new_key_size
            if used - old_size + new_size > partition["max_storage"]:
                raise PKCS11Error(CKR_DEVICE_MEMORY,
                                  "Partition storage quota exceeded by object update")
        if encrypted_material is not None:
            c.execute(
                "UPDATE objects SET object_data = ?, key_material = ? WHERE handle = ?",
                (obj_data, encrypted_material, handle),
            )
        else:
            c.execute(
                "UPDATE objects SET object_data = ? WHERE handle = ?",
                (obj_data, handle),
            )
        self._conn.commit()

    def get_object(self, handle: int) -> tuple:
        """Return (CKObject, key_material_bytes_or_None)."""
        c = self.conn.cursor()
        row = c.execute("SELECT * FROM objects WHERE handle = ?", (handle,)).fetchone()
        if not row:
            return None, None
        obj = CKObject.from_dict(json.loads(row["object_data"]))
        key_material = None
        if row["key_material"]:
            key_material = self.decrypt_blob(row["key_material"])
        return obj, key_material

    def get_object_by_label(self, slot_id: int, label: str) -> tuple:
        c = self.conn.cursor()
        row = c.execute(
            "SELECT * FROM objects WHERE slot_id = ? AND label = ?",
            (slot_id, label),
        ).fetchone()
        if not row:
            return None, None
        obj = CKObject.from_dict(json.loads(row["object_data"]))
        key_material = None
        if row["key_material"]:
            key_material = self.decrypt_blob(row["key_material"])
        return obj, key_material

    def get_all_objects(self, slot_id: int) -> list:
        c = self.conn.cursor()
        rows = c.execute(
            "SELECT * FROM objects WHERE slot_id = ? ORDER BY handle", (slot_id,)
        ).fetchall()
        result = []
        for row in rows:
            obj = CKObject.from_dict(json.loads(row["object_data"]))
            key_material = None
            if row["key_material"]:
                key_material = self.decrypt_blob(row["key_material"])
            result.append((obj, key_material))
        return result

    def delete_object(self, handle: int):
        c = self.conn.cursor()
        c.execute("DELETE FROM objects WHERE handle = ?", (handle,))
        self._conn.commit()

    def count_objects(self, slot_id: int) -> int:
        c = self.conn.cursor()
        row = c.execute(
            "SELECT COUNT(*) as cnt FROM objects WHERE slot_id = ?", (slot_id,)
        ).fetchone()
        return row["cnt"]

    def get_partition_storage_used(self, slot_id: int) -> int:
        """Return persisted object metadata plus encrypted material in bytes."""
        row = self.conn.execute(
            "SELECT COALESCE(SUM(LENGTH(object_data) + COALESCE(LENGTH(key_material), 0)), 0) AS used "
            "FROM objects WHERE slot_id = ?", (slot_id,),
        ).fetchone()
        return int(row["used"])

    def get_max_handle(self) -> int:
        c = self.conn.cursor()
        row = c.execute("SELECT MAX(handle) as mx FROM objects").fetchone()
        return row["mx"] if row["mx"] else 0

    # ------------------------------------------------------------------
    # PIN hashing
    # ------------------------------------------------------------------

    def hash_pin(self, pin: str, salt: bytes = None) -> tuple:
        """Hash a PIN with PBKDF2. Returns (hash_hex, salt_hex)."""
        if salt is None:
            salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
            backend=default_backend(),
        )
        h = kdf.derive(pin.encode("utf-8"))
        return h.hex(), salt.hex()

    def verify_pin(self, pin: str, stored_hash: str, stored_salt: str) -> bool:
        salt = bytes.fromhex(stored_salt)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
            backend=default_backend(),
        )
        h = kdf.derive(pin.encode("utf-8"))
        return hmac.compare_digest(h.hex(), stored_hash)

    # ------------------------------------------------------------------
    # Audit log
    # ------------------------------------------------------------------

    def insert_audit(self, timestamp: str, session_id: int, role: str,
                     operation: str, object_label: str, object_handle: int,
                     success: bool, detail: str) -> tuple:
        """Insert an audit entry with hash chaining. Returns (entry_hash, prev_hash)."""
        c = self.conn.cursor()
        prev_row = c.execute(
            "SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1"
        ).fetchone()
        prev_hash = prev_row["entry_hash"] if prev_row else "0" * 64

        entry_str = f"{timestamp}|{session_id}|{role}|{operation}|{object_label}|{object_handle}|{int(success)}|{detail}|{prev_hash}"
        entry_hash = hashlib.sha256(entry_str.encode("utf-8")).hexdigest()

        c.execute(
            """INSERT INTO audit_log
               (timestamp, session_id, role, operation, object_label,
                object_handle, success, detail, prev_hash, entry_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (timestamp, session_id, role, operation, object_label,
             object_handle, int(success), detail, prev_hash, entry_hash),
        )
        self._conn.commit()
        return entry_hash, prev_hash

    def get_audit_logs(self, limit: int = 100) -> list:
        c = self.conn.cursor()
        rows = c.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    def clear_audit_logs(self):
        c = self.conn.cursor()
        c.execute("DELETE FROM audit_log")
        self._conn.commit()

    def verify_audit_chain(self) -> bool:
        """Verify the hash chain integrity of the audit log."""
        c = self.conn.cursor()
        rows = c.execute(
            "SELECT * FROM audit_log ORDER BY id ASC"
        ).fetchall()
        prev_hash = "0" * 64
        for row in rows:
            entry_str = f"{row['timestamp']}|{row['session_id']}|{row['role']}|{row['operation']}|{row['object_label']}|{row['object_handle']}|{row['success']}|{row['detail']}|{prev_hash}"
            computed = hashlib.sha256(entry_str.encode("utf-8")).hexdigest()
            if computed != row["entry_hash"]:
                return False
            prev_hash = row["entry_hash"]
        return True

    # ------------------------------------------------------------------
    # Export / Import
    # ------------------------------------------------------------------

    def export_state(self, filepath: str):
        """Export the full HSM state to a JSON file (key material encrypted)."""
        c = self.conn.cursor()
        meta = {r["key"]: r["value"] for r in c.execute("SELECT * FROM hsm_meta").fetchall()}
        partitions = [dict(r) for r in c.execute("SELECT * FROM partitions").fetchall()]
        objects = []
        for row in c.execute("SELECT * FROM objects").fetchall():
            objects.append({
                "handle": row["handle"],
                "slot_id": row["slot_id"],
                "label": row["label"],
                "object_data": row["object_data"],
                "key_material": row["key_material"].hex() if row["key_material"] else None,
                "created_at": row["created_at"],
            })
        audit = [dict(r) for r in c.execute("SELECT * FROM audit_log").fetchall()]
        state = {
            "hsm_meta": meta,
            "partitions": partitions,
            "objects": objects,
            "audit_log": audit,
        }
        with open(filepath, "w") as f:
            json.dump(state, f, indent=2)

    def import_state(self, filepath: str):
        """Import HSM state from a JSON file. Replaces current state."""
        with open(filepath, "r") as f:
            state = json.load(f)
        c = self.conn.cursor()
        # Clear existing
        c.execute("DELETE FROM hsm_meta")
        c.execute("DELETE FROM partitions")
        c.execute("DELETE FROM objects")
        c.execute("DELETE FROM audit_log")
        # Insert meta
        for k, v in state.get("hsm_meta", {}).items():
            c.execute("INSERT INTO hsm_meta (key, value) VALUES (?, ?)", (k, v))
        # Insert partitions
        for p in state.get("partitions", []):
            cols = ", ".join(p.keys())
            placeholders = ", ".join("?" * len(p))
            c.execute(f"INSERT INTO partitions ({cols}) VALUES ({placeholders})",
                      list(p.values()))
        # Insert objects
        for o in state.get("objects", []):
            km = bytes.fromhex(o["key_material"]) if o["key_material"] else None
            c.execute(
                """INSERT INTO objects (handle, slot_id, label, object_data, key_material, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (o["handle"], o["slot_id"], o["label"], o["object_data"],
                 km, o["created_at"]),
            )
        # Insert audit
        for a in state.get("audit_log", []):
            cols = ", ".join(a.keys())
            placeholders = ", ".join("?" * len(a))
            c.execute(f"INSERT INTO audit_log ({cols}) VALUES ({placeholders})",
                      list(a.values()))
        self._conn.commit()
