"""Key storage and retrieval for the Luna 7 HSM emulator.

Handles object handle allocation, key material encryption at rest,
and enforces key extraction policies (CKA_EXTRACTABLE, CKA_SENSITIVE).
"""

from typing import Optional

from storage.db import Storage
from pkcs11.objects import CKObject
from pkcs11.constants import (
    PKCS11Error, CKR_OBJECT_HANDLE_INVALID, CKR_ATTRIBUTE_SENSITIVE,
    CKA_EXTRACTABLE, CKA_SENSITIVE, CKA_LABEL, CKA_CLASS,
    CKO_SECRET_KEY, CKO_PUBLIC_KEY, CKO_PRIVATE_KEY,
)


class KeyStore:
    """Key storage with handle management and encrypted key material."""

    def __init__(self, storage: Storage):
        self.storage = storage

    def allocate_handle(self) -> int:
        """Allocate the next object handle."""
        max_h = self.storage.get_max_handle()
        return max_h + 1

    def store(self, slot_id: int, obj: CKObject, key_material: bytes = None) -> int:
        """Store an object. Returns the handle."""
        handle = self.allocate_handle()
        obj.handle = handle
        label = obj.label()
        self.storage.insert_object(handle, slot_id, label, obj, key_material)
        return handle

    def retrieve(self, handle: int) -> tuple:
        """Retrieve an object by handle. Returns (CKObject, key_material_or_None)."""
        obj, km = self.storage.get_object(handle)
        if obj is None:
            raise PKCS11Error(CKR_OBJECT_HANDLE_INVALID, f"Handle 0x{handle:08X} not found")
        return obj, km

    def retrieve_by_label(self, slot_id: int, label: str) -> tuple:
        """Retrieve an object by label within a partition."""
        obj, km = self.storage.get_object_by_label(slot_id, label)
        if obj is None:
            raise PKCS11Error(CKR_OBJECT_HANDLE_INVALID, f"No object with label '{label}' on slot {slot_id}")
        return obj, km

    def list_objects(self, slot_id: int) -> list:
        """Return all objects on a partition. Returns list of (CKObject, key_material)."""
        return self.storage.get_all_objects(slot_id)

    def delete(self, handle: int):
        """Delete an object by handle."""
        obj, _ = self.retrieve(handle)
        if not obj.get(CKA_LABEL):
            pass
        self.storage.delete_object(handle)

    def update(self, handle: int, obj: CKObject, key_material: bytes = None):
        """Update an object's attributes and optionally its key material."""
        self.storage.update_object(handle, obj, key_material)

    def get_key_material(self, handle: int) -> Optional[bytes]:
        """Retrieve raw key material for an object (if extractable)."""
        obj, km = self.retrieve(handle)
        if km is None:
            return None
        if obj.is_sensitive() and not obj.is_extractable():
            raise PKCS11Error(CKR_ATTRIBUTE_SENSITIVE,
                              "Key is sensitive and not extractable — cannot read in plaintext")
        return km

    def check_quota(self, slot_id: int) -> bool:
        """Check if the partition can accept more objects."""
        p = self.storage.get_partition(slot_id)
        if p is None:
            return False
        count = self.storage.count_objects(slot_id)
        return count < p["max_objects"]
