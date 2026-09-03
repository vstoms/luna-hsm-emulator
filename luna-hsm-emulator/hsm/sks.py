"""Scalable Key Storage for Luna V1 partition training.

V1 key objects can be extracted as authenticated blobs encrypted by a
partition's SKS Master Key (SMK).  Only the SMK is cloned/backed up; blobs are
intended for external repositories.
"""

import base64
import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from hsm.domain import CloningDomainManager
from pkcs11.constants import PKCS11Error, CKR_ACTION_PROHIBITED, CKR_DATA_INVALID
from pkcs11.objects import CKObject


class SKSManager:
    META_KEY = "sks_state"

    def __init__(self, storage, lifecycle):
        self.storage = storage
        self.lifecycle = lifecycle
        self.domains = CloningDomainManager(storage)

    def _load(self) -> dict:
        raw = self.storage.get_meta(self.META_KEY)
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except (TypeError, json.JSONDecodeError):
            return {}

    def _save(self, state: dict):
        self.storage.set_meta(self.META_KEY, json.dumps(state))

    def _require_v1(self, slot_id: int):
        if self.lifecycle.status(slot_id)["version"] != 1:
            raise PKCS11Error(CKR_ACTION_PROHIBITED, "SKS requires a V1 partition")

    def _protect_smk(self, smk: bytes) -> str:
        return base64.b64encode(self.storage.encrypt_blob(smk)).decode()

    def _unprotect_smk(self, value: str) -> bytes:
        return self.storage.decrypt_blob(base64.b64decode(value))

    def ensure_smk(self, slot_id: int) -> dict:
        self._require_v1(slot_id)
        state = self._load()
        entry = state.setdefault(str(slot_id), {})
        if not entry.get("primary"):
            entry["primary"] = self._protect_smk(os.urandom(32))
            entry["rollover"] = None
            entry["generation"] = 1
            self._save(state)
        return {"slot_id": slot_id, "generation": entry["generation"],
                "rollover_active": bool(entry.get("rollover"))}

    def clone_smk(self, source_slot: int, destination_slot: int) -> dict:
        self._require_v1(source_slot)
        self._require_v1(destination_slot)
        negotiation = self.domains.negotiate_cloning(source_slot, destination_slot)
        self.ensure_smk(source_slot)
        state = self._load()
        source = state[str(source_slot)]
        state[str(destination_slot)] = {
            "primary": source["primary"], "rollover": None,
            "generation": source["generation"],
        }
        self._save(state)
        return {"source_slot": source_slot, "destination_slot": destination_slot,
                "cloning_protocol": negotiation["protocol"],
                "generation": source["generation"]}

    def rollover_start(self, slot_id: int) -> dict:
        self.ensure_smk(slot_id)
        state = self._load()
        entry = state[str(slot_id)]
        if entry.get("rollover"):
            raise PKCS11Error(CKR_ACTION_PROHIBITED, "SMK rollover is already active")
        entry["rollover"] = entry["primary"]
        entry["primary"] = self._protect_smk(os.urandom(32))
        entry["generation"] += 1
        self._save(state)
        return self.status(slot_id)

    def rollover_end(self, slot_id: int) -> dict:
        self.ensure_smk(slot_id)
        state = self._load()
        entry = state[str(slot_id)]
        if not entry.get("rollover"):
            raise PKCS11Error(CKR_ACTION_PROHIBITED, "No SMK rollover is active")
        entry["rollover"] = None
        self._save(state)
        return self.status(slot_id)

    def status(self, slot_id: int) -> dict:
        info = self.ensure_smk(slot_id)
        return info

    def extract(self, slot_id: int, handle: int) -> bytes:
        self.ensure_smk(slot_id)
        obj, material = self.storage.get_object(handle)
        slot_handles = {candidate.handle for candidate, _ in
                        self.storage.get_all_objects(slot_id)}
        if obj is None or handle not in slot_handles:
            raise PKCS11Error(CKR_DATA_INVALID, "Object not found on partition")
        payload = json.dumps({
            "format": "LUNA-SKS-1", "object": obj.to_dict(),
            "material": base64.b64encode(material or b"").decode(),
        }, sort_keys=True).encode()
        entry = self._load()[str(slot_id)]
        key = self._unprotect_smk(entry["primary"])
        nonce = os.urandom(12)
        ciphertext = AESGCM(key).encrypt(nonce, payload, b"LUNA-SKS-1")
        return b"LSKS1" + nonce + ciphertext

    def insert(self, slot_id: int, blob: bytes) -> int:
        self.ensure_smk(slot_id)
        if not blob.startswith(b"LSKS1") or len(blob) < 34:
            raise PKCS11Error(CKR_DATA_INVALID, "Invalid SKS blob")
        nonce, ciphertext = blob[5:17], blob[17:]
        entry = self._load()[str(slot_id)]
        payload = None
        for protected in (entry.get("primary"), entry.get("rollover")):
            if not protected:
                continue
            try:
                payload = AESGCM(self._unprotect_smk(protected)).decrypt(
                    nonce, ciphertext, b"LUNA-SKS-1")
                break
            except Exception:
                pass
        if payload is None:
            raise PKCS11Error(CKR_DATA_INVALID, "SKS blob was encrypted by a different SMK")
        decoded = json.loads(payload)
        obj = CKObject.from_dict(decoded["object"])
        obj.handle = self.storage.get_max_handle() + 1
        material = base64.b64decode(decoded["material"])
        self.storage.insert_object(obj.handle, slot_id, obj.label(), obj, material)
        return obj.handle
