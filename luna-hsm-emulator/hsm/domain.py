"""First-class cloning domains and secure object cloning.

Cloning moves key material only inside the emulated secure boundary.  Unlike
wrapping it does not require CKA_EXTRACTABLE, and unlike backup it directly
copies objects between online partitions.  Matching cloning domains and
partition cloning policies are mandatory.
"""

import hashlib
import json
import secrets

from pkcs11.constants import (
    CKA_CLASS, CKO_PRIVATE_KEY, CKO_SECRET_KEY, PKCS11Error,
    CKR_ACTION_PROHIBITED, CKR_ARGUMENTS_BAD, CKR_TOKEN_NOT_PRESENT,
)
from pkcs11.objects import CKObject


DOMAIN_MISMATCH_CODE = "LUNA_RET_CLONING_DOMAIN_MISMATCH"


class CloningDomainError(Exception):
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


class CloningDomainManager:
    """Manage HSM/partition domains, inheritance, and secure cloning."""

    HSM_META = "cloning_hsm_domain"
    PARTITION_META = "cloning_partition_domains"

    def __init__(self, storage):
        self.storage = storage

    @staticmethod
    def domain_from_secret(secret: str) -> str:
        if not secret:
            raise CloningDomainError("LUNA_RET_INVALID_DOMAIN", "Cloning domain cannot be empty")
        # Persist only a one-way identifier; never the supplied domain secret.
        digest = hashlib.sha256(("luna-cloning-domain:" + secret).encode()).hexdigest()
        return "DOM-" + digest[:24].upper()

    def _get_partition_settings(self) -> dict:
        raw = self.storage.get_meta(self.PARTITION_META)
        if raw:
            try:
                return json.loads(raw)
            except (TypeError, json.JSONDecodeError):
                pass
        return {}

    def _save_partition_settings(self, settings: dict):
        self.storage.set_meta(self.PARTITION_META, json.dumps(settings))

    def ensure_hsm_domain(self) -> str:
        domain = self.storage.get_meta(self.HSM_META)
        if not domain:
            domain = "DOM-" + secrets.token_hex(12).upper()
            self.storage.set_meta(self.HSM_META, domain)
        return domain

    def get_hsm_domain(self) -> str:
        return self.ensure_hsm_domain()

    def get_partition_domain(self, slot_id: int) -> dict:
        partition = self.storage.get_partition(slot_id)
        if partition is None:
            raise CloningDomainError("LUNA_RET_PARTITION_NOT_FOUND",
                                     f"Partition slot {slot_id} not found")
        setting = self._get_partition_settings().get(
            str(slot_id), {"inherit": False, "domain_id": None})
        inherited = setting.get("inherit", False)
        domain_id = self.get_hsm_domain() if inherited else setting.get("domain_id")
        return {
            "slot_id": slot_id,
            "partition": partition["name"],
            "domain_id": domain_id,
            "fingerprint": self.fingerprint(domain_id),
            "inherited": inherited,
            "source": "HSM" if inherited else "partition",
        }

    @staticmethod
    def fingerprint(domain_id: str) -> str:
        if not domain_id:
            return "UNSET"
        return hashlib.sha256(domain_id.encode()).hexdigest()[:16].upper()

    def _affected_inherited_slots(self) -> list:
        settings = self._get_partition_settings()
        return [p["slot_id"] for p in self.storage.get_all_partitions()
                if settings.get(str(p["slot_id"]), {"inherit": False}).get("inherit", False)]

    def set_hsm_domain(self, domain_id: str, force: bool = False) -> dict:
        current = self.storage.get_meta(self.HSM_META)
        affected = self._affected_inherited_slots()
        populated = [slot for slot in affected if self.storage.count_objects(slot)]
        if current and current != domain_id and populated and not force:
            raise CloningDomainError(
                "LUNA_RET_DOMAIN_CHANGE_REQUIRES_ZEROIZE",
                "Changing the HSM domain affects populated inherited partitions; confirm destructive zeroization",
            )
        deleted = self._clear_slots(populated) if current != domain_id and force else 0
        self.storage.set_meta(self.HSM_META, domain_id)
        return {"domain_id": domain_id, "fingerprint": self.fingerprint(domain_id),
                "affected_slots": affected, "objects_deleted": deleted}

    def set_partition_domain(self, slot_id: int, domain_id: str = None,
                             inherit: bool = False, force: bool = False) -> dict:
        current = self.get_partition_domain(slot_id)
        new_domain = self.get_hsm_domain() if inherit else domain_id
        if not new_domain:
            raise CloningDomainError("LUNA_RET_INVALID_DOMAIN",
                                     "An explicit partition domain is required")
        changed = current["domain_id"] != new_domain
        object_count = self.storage.count_objects(slot_id)
        if changed and object_count and not force:
            raise CloningDomainError(
                "LUNA_RET_DOMAIN_CHANGE_REQUIRES_ZEROIZE",
                "Changing a populated partition domain requires destructive zeroization",
            )
        deleted = self._clear_slots([slot_id]) if changed and object_count and force else 0
        settings = self._get_partition_settings()
        settings[str(slot_id)] = {
            "inherit": bool(inherit),
            "domain_id": None if inherit else new_domain,
            "domains": [] if inherit else [
                {"domain_id": new_domain, "label": "", "primary": True, "original": True}
            ],
        }
        self._save_partition_settings(settings)
        result = self.get_partition_domain(slot_id)
        result["objects_deleted"] = deleted
        return result

    def _clear_slots(self, slots: list) -> int:
        deleted = 0
        for slot_id in slots:
            for obj, _ in self.storage.get_all_objects(slot_id):
                self.storage.delete_object(obj.handle)
                deleted += 1
        return deleted

    def list_domains(self, slot_id: int) -> list:
        """Return all domains defined on a partition, including the primary."""
        primary = self.get_partition_domain(slot_id)
        settings = self._get_partition_settings()
        setting = settings.get(str(slot_id), {})
        domains = setting.get("domains")
        if domains is None:
            domains = ([{"domain_id": primary["domain_id"], "label": "",
                         "primary": True, "original": True}] if primary["domain_id"] else [])
        return [{**entry, "fingerprint": self.fingerprint(entry["domain_id"])}
                for entry in domains]

    def _extended_enabled(self, slot_id: int) -> bool:
        from hsm.policies import get_policy_by_name
        policy = get_policy_by_name("ALLOW_EXTENDED_DOMAIN_MANAGEMENT")
        stored = self.storage.get_partition_policies(slot_id)
        return bool(stored.get(policy.policy_id, policy.default_value))

    def add_domain(self, slot_id: int, domain_id: str, label: str,
                   primary: bool = False) -> dict:
        if not self._extended_enabled(slot_id):
            raise CloningDomainError("LUNA_RET_POLICY_ID_NOT_FOUND",
                                     "Partition policy 44 must be enabled")
        label = label or ""
        settings = self._get_partition_settings()
        setting = settings.get(str(slot_id))
        if not setting or not setting.get("domain_id"):
            raise CloningDomainError("LUNA_RET_INVALID_DOMAIN", "Partition is not initialized")
        domains = setting.setdefault("domains", [
            {"domain_id": setting["domain_id"], "label": "", "primary": True, "original": True}
        ])
        if len(domains) >= 3:
            raise CloningDomainError("LUNA_RET_DOMAIN_COUNT_INVALID",
                                     "A partition can contain at most three domains")
        if any(item["domain_id"] == domain_id for item in domains):
            raise CloningDomainError("LUNA_RET_DOMAIN_ALREADY_EXISTS", "Domain already exists")
        if any(item["label"].lower() == label.lower() for item in domains):
            raise CloningDomainError("LUNA_RET_DOMAIN_LABEL_INVALID",
                                     "Domain label already exists or is not set")
        if primary:
            for item in domains:
                item["primary"] = False
            setting["domain_id"] = domain_id
        entry = {"domain_id": domain_id, "label": label, "primary": primary,
                 "original": False}
        domains.append(entry)
        self._save_partition_settings(settings)
        return {**entry, "fingerprint": self.fingerprint(domain_id)}

    def delete_domain(self, slot_id: int, label: str) -> dict:
        if not self._extended_enabled(slot_id):
            raise CloningDomainError("LUNA_RET_POLICY_ID_NOT_FOUND",
                                     "Partition policy 44 must be enabled")
        label = label or ""
        settings = self._get_partition_settings()
        setting = settings.get(str(slot_id), {})
        domains = setting.get("domains", [])
        entry = next((item for item in domains if item["label"].lower() == label.lower()), None)
        if not entry:
            raise CloningDomainError("LUNA_RET_DOMAIN_NOT_FOUND", f"Domain '{label}' not found")
        if entry.get("original"):
            raise CloningDomainError("LUNA_RET_OPERATION_RESTRICTED",
                                     "The original partition domain cannot be deleted")
        setting["domains"] = [item for item in domains if item is not entry]
        self._save_partition_settings(settings)
        return entry

    def change_domain_label(self, slot_id: int, old_label: str, new_label: str,
                            primary: bool = False) -> dict:
        if not self._extended_enabled(slot_id):
            raise CloningDomainError("LUNA_RET_POLICY_ID_NOT_FOUND",
                                     "Partition policy 44 must be enabled")
        old_label = old_label or ""
        if not new_label:
            raise CloningDomainError("LUNA_RET_DOMAIN_LABEL_INVALID", "A new label is required")
        settings = self._get_partition_settings()
        domains = settings.get(str(slot_id), {}).get("domains", [])
        entry = next((item for item in domains if item["label"].lower() == old_label.lower()), None)
        if not entry:
            raise CloningDomainError("LUNA_RET_DOMAIN_NOT_FOUND", f"Domain '{old_label}' not found")
        if any(item is not entry and item["label"].lower() == new_label.lower() for item in domains):
            raise CloningDomainError("LUNA_RET_DOMAIN_LABEL_INVALID", "Domain label already exists")
        entry["label"] = new_label
        if primary:
            for item in domains:
                item["primary"] = item is entry
            settings[str(slot_id)]["domain_id"] = entry["domain_id"]
        self._save_partition_settings(settings)
        return entry

    def negotiate_cloning(self, source_slot: int, destination_slot: int) -> dict:
        source_domains = sorted(self.list_domains(source_slot),
                                key=lambda item: not item.get("primary"))
        destination_ids = {entry["domain_id"] for entry in self.list_domains(destination_slot)}
        shared = next((entry for entry in source_domains
                       if entry["domain_id"] in destination_ids), None)
        if not shared:
            raise CloningDomainError(
                DOMAIN_MISMATCH_CODE,
                f"Secure cloning failed: source slot {source_slot} and destination slot "
                f"{destination_slot} do not share the same cloning domain",
            )
        cpv4 = self._extended_enabled(source_slot) and self._extended_enabled(destination_slot)
        return {"domain_id": shared["domain_id"], "domain_label": shared["label"],
                "protocol": "CPv4" if cpv4 else "CPv3"}

    def assert_matching(self, source_slot: int, destination_slot: int) -> str:
        return self.negotiate_cloning(source_slot, destination_slot)["domain_id"]

    def _policy_enabled(self, slot_id: int, policy_name: str) -> bool:
        from hsm.policies import get_policy_by_name
        policy = get_policy_by_name(policy_name)
        stored = self.storage.get_partition_policies(slot_id)
        return bool(stored.get(policy.policy_id, policy.default_value))

    def clone_objects(self, source_slot: int, destination_slot: int,
                      labels: list = None, token_objects_only: bool = False,
                      synchronize: bool = False) -> dict:
        if source_slot == destination_slot:
            raise PKCS11Error(CKR_ARGUMENTS_BAD, "Source and destination partitions must differ")
        if self.storage.get_partition(source_slot) is None:
            raise PKCS11Error(CKR_TOKEN_NOT_PRESENT, f"Source slot {source_slot} not found")
        if self.storage.get_partition(destination_slot) is None:
            raise PKCS11Error(CKR_TOKEN_NOT_PRESENT, f"Destination slot {destination_slot} not found")
        negotiation = self.negotiate_cloning(source_slot, destination_slot)
        domain = negotiation["domain_id"]

        existing_labels = {obj.label() for obj, _ in self.storage.get_all_objects(destination_slot)}
        cloned, skipped_policy, skipped_existing = [], [], []
        source_objects = self.storage.get_all_objects(source_slot)
        for obj, material in source_objects:
            if token_objects_only and not obj.is_token_object():
                continue
            if labels and obj.label() not in labels:
                continue
            object_class = obj.get(CKA_CLASS)
            policy = None
            if object_class == CKO_PRIVATE_KEY:
                policy = "ALLOW_PRIVATE_KEY_CLONING"
            elif object_class == CKO_SECRET_KEY:
                policy = "ALLOW_SECRET_KEY_CLONING"
            if policy and (not self._policy_enabled(source_slot, policy)
                           or not self._policy_enabled(destination_slot, policy)):
                skipped_policy.append(obj.label())
                continue
            identity = self.storage.object_identity(obj.handle)
            existing_handle = self.storage.object_handle(destination_slot, identity)
            if synchronize and existing_handle is not None:
                replica = CKObject.from_dict(obj.to_dict())
                replica.handle = existing_handle
                self.storage.update_object(existing_handle, replica, material)
                skipped_existing.append(obj.label())
                continue
            if not synchronize and obj.label() in existing_labels:
                skipped_existing.append(obj.label())
                continue
            destination = self.storage.get_partition(destination_slot)
            if self.storage.count_objects(destination_slot) >= destination["max_objects"]:
                raise PKCS11Error(CKR_ACTION_PROHIBITED, "Destination partition object quota exceeded")
            cloned_obj = CKObject.from_dict(obj.to_dict())
            cloned_obj.handle = self.storage.get_max_handle() + 1
            self.storage.insert_object(cloned_obj.handle, destination_slot,
                                       cloned_obj.label(), cloned_obj, material,
                                       cloning_id=identity)
            existing_labels.add(cloned_obj.label())
            cloned.append(cloned_obj.label())

        return {
            "source_slot": source_slot,
            "destination_slot": destination_slot,
            "domain_fingerprint": self.fingerprint(domain),
            "domain_label": negotiation["domain_label"],
            "cloning_protocol": negotiation["protocol"],
            "cloned": cloned,
            "skipped_policy": skipped_policy,
            "skipped_existing": skipped_existing,
            "secure_boundary": True,
        }
