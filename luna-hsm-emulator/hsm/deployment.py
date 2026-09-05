"""Deployment and operations features for the Luna Network HSM emulator."""

import json
import time
import hashlib
from typing import Optional

from hsm.domain import CloningDomainManager, CloningDomainError


DEFAULT_LICENSES = {
    "base_configuration": {"id": "621000153-000", "description": "Base configuration", "enabled": True},
    "max_partitions": {"id": "621000153-002", "description": "Maximum partitions", "limit": 10, "enabled": True},
    "key_backup": {"id": "621001854-003", "description": "Key backup via cloning protocol", "enabled": True},
    "max_storage": {"id": "621001914-002", "description": "Maximum 10 partitions", "limit": 10485760, "enabled": True},
    "ha": {"id": "621001335-002", "description": "High Availability", "enabled": True},
    "stc": {"id": "621001520-001", "description": "Secure Trusted Channel", "enabled": True},
}


class DeploymentManager:
    """Persists HA, network deployment, license, and support state."""

    def __init__(self, storage):
        self.storage = storage
        self.domains = CloningDomainManager(storage)
        self._ensure_state()

    def _read(self, key: str, default):
        raw = self.storage.get_meta(key)
        if not raw:
            return default
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return default

    def _write(self, key: str, value) -> None:
        self.storage.set_meta(key, json.dumps(value))

    def _ensure_state(self) -> None:
        if not self.storage.get_meta("ha_groups"):
            self._write("ha_groups", {})
        if not self.storage.get_meta("ntp_config"):
            self._write("ntp_config", {
                "enabled": True,
                "servers": ["pool.ntp.org"],
                "synchronized": True,
                "last_sync": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            })
        if not self.storage.get_meta("network_bonds"):
            self._write("network_bonds", {})
        if not self.storage.get_meta("license_config"):
            self._write("license_config", DEFAULT_LICENSES)
        if not self.storage.get_meta("support_bundle_history"):
            self._write("support_bundle_history", [])

    # ------------------------------------------------------------------
    # HA groups
    # ------------------------------------------------------------------

    def _token_objects(self, slot_id: int) -> list:
        """Return persistent objects only; PKCS#11 session objects never replicate."""
        return [(obj, material) for obj, material in self.storage.get_all_objects(slot_id)
                if obj.is_token_object()]

    def _policy_fingerprint(self, slot_id: int) -> str:
        from hsm.policies import POLICY_CATALOG
        stored = self.storage.get_partition_policies(slot_id)
        effective = {p.policy_id: stored.get(p.policy_id, p.default_value)
                     for p in POLICY_CATALOG}
        return hashlib.sha256(json.dumps(effective, sort_keys=True).encode()).hexdigest()[:16].upper()

    def _normalize_ha_group(self, group: dict) -> dict:
        """Upgrade HA groups persisted by earlier emulator versions in place."""
        if "virtual_slot" not in group:
            next_slot = int(self.storage.get_meta("ha_next_slot", "1000000"))
            group["virtual_slot"] = next_slot
            self.storage.set_meta("ha_next_slot", str(next_slot + 1))
            groups = self._read("ha_groups", {})
            groups[group["name"]] = group
            self._write("ha_groups", groups)
        group.setdefault("deleted_objects", [])
        group.setdefault("mode", "round-robin")
        group.setdefault("recovery_mode", "automatic")
        group.setdefault("round_robin_cursor", 0)
        group.setdefault("operation_count", 0)
        group.setdefault("failover_count", 0)
        group.setdefault("last_operation", None)
        for index, member in enumerate(group.get("members", [])):
            member.setdefault("state", member.get("status", "active"))
            member.setdefault("status", member["state"])
            member.setdefault("role", "active" if group["mode"] == "round-robin" or index == 0 else "standby")
            member.setdefault("sync_status", "current" if member.get("last_sync") else "not-synchronized")
            member.setdefault("network_partition", False)
            member.setdefault("failure_reason", None)
            member.setdefault("retry_attempts", 0)
            member.setdefault("firmware", self.storage.get_meta("firmware_version") or "7.13.0")
            member.setdefault("policy_fingerprint", self._policy_fingerprint(member["slot_id"]))
        return group

    def _save_ha_group(self, groups: dict, group: dict):
        groups[group["name"]] = group
        self._write("ha_groups", groups)

    def list_ha_groups(self) -> list:
        groups = self._read("ha_groups", {})
        return [self._normalize_ha_group(group) for group in groups.values()]

    def get_ha_group(self, name: str) -> Optional[dict]:
        group = self._read("ha_groups", {}).get(name)
        return self._normalize_ha_group(group) if group else None

    def create_ha_group(self, name: str, slot_id: int, label: str = "") -> dict:
        groups = self._read("ha_groups", {})
        if name in groups:
            return {"success": False, "error": f"HA group '{name}' already exists"}
        partition = self.storage.get_partition(slot_id)
        if partition is None:
            return {"success": False, "error": f"Partition slot {slot_id} not found"}
        virtual_slot = int(self.storage.get_meta("ha_next_slot", "1000000"))
        self.storage.set_meta("ha_next_slot", str(virtual_slot + 1))
        settings = self._read("ha_client_settings", {})
        group = {
            "virtual_slot": virtual_slot,
            "deleted_objects": [],
            "name": name,
            "label": label or name,
            "state": "active",
            "retry_count": settings.get("retry_count", 216),
            "poll_interval": settings.get("poll_interval", 0),
            "infinite_polling": settings.get("retry_count", 216) == -1,
            "synchronize_on_add": True,
            "mode": "round-robin",
            "recovery_mode": "automatic",
            "round_robin_cursor": 0,
            "operation_count": 0,
            "failover_count": 0,
            "last_operation": None,
            "members": [{
                "slot_id": slot_id,
                "serial": f"HA-{slot_id:04d}",
                "partition": partition["name"],
                "status": "active",
                "state": "active",
                "role": "active",
                "objects": len(self._token_objects(slot_id)),
                "last_sync": None,
                "sync_status": "current",
                "network_partition": False,
                "failure_reason": None,
                "retry_attempts": 0,
                "firmware": self.storage.get_meta("firmware_version") or "7.13.0",
                "policy_fingerprint": self._policy_fingerprint(slot_id),
            }],
            "domain_fingerprint": self.domains.get_partition_domain(slot_id)["fingerprint"],
            "created_at": time.time(),
        }
        groups[name] = group
        self._write("ha_groups", groups)
        return {"success": True, "group": group}

    def group_for_slot(self, slot_id: int):
        return next((g for g in self.list_ha_groups() if g["virtual_slot"] == slot_id), None)

    def set_ha_only(self, enabled: bool):
        settings = self._read("ha_client_settings", {})
        settings["ha_only"] = bool(enabled)
        self._write("ha_client_settings", settings)

    def ha_only(self) -> bool:
        return bool(self._read("ha_client_settings", {}).get("ha_only", False))

    def client_slots(self, include_members: bool = False) -> list:
        groups = self.list_ha_groups()
        hidden = {m["slot_id"] for g in groups for m in g["members"]}
        physical = [p["slot_id"] for p in self.storage.get_all_partitions()
                    if include_members or not self.ha_only() or p["slot_id"] not in hidden]
        return physical + [g["virtual_slot"] for g in groups]

    def record_deletion(self, name: str, identity: str):
        groups = self._read("ha_groups", {})
        group = self._normalize_ha_group(groups[name])
        if identity not in group["deleted_objects"]:
            group["deleted_objects"].append(identity)
        self._save_ha_group(groups, group)

    def _apply_deletions(self, group: dict, slot_id: int):
        for identity in group.get("deleted_objects", []):
            handle = self.storage.object_handle(slot_id, identity)
            if handle is not None:
                self.storage.delete_object(handle)

    def poll_ha_recovery(self, name: str):
        """Client-driven bounded recovery; never sleep in a crypto call."""
        group = self.get_ha_group(name)
        if not group or group["recovery_mode"] != "automatic":
            return
        now = time.time()
        for member in group["members"]:
            if member["state"] not in ("unavailable", "recovering"):
                continue
            limit = group["retry_count"]
            if limit != -1 and member["retry_attempts"] >= limit:
                continue
            if now - member.get("last_retry", 0) < group["poll_interval"]:
                continue
            groups = self._read("ha_groups", {})
            current = self._normalize_ha_group(groups[name])
            target = self._find_ha_member(current, member["slot_id"])
            target["retry_attempts"] += 1
            target["last_retry"] = now
            self._save_ha_group(groups, current)
            self.recover_ha_member(name, member["slot_id"])

    def delete_ha_group(self, name: str) -> dict:
        groups = self._read("ha_groups", {})
        if name not in groups:
            return {"success": False, "error": f"HA group '{name}' not found"}
        del groups[name]
        self._write("ha_groups", groups)
        return {"success": True}

    def add_ha_member(self, group_name: str, slot_id: int, serial: str = "") -> dict:
        groups = self._read("ha_groups", {})
        group = groups.get(group_name)
        if group is None:
            return {"success": False, "error": f"HA group '{group_name}' not found"}
        group = self._normalize_ha_group(group)
        partition = self.storage.get_partition(slot_id)
        if partition is None:
            return {"success": False, "error": f"Partition slot {slot_id} not found"}
        if any(m["slot_id"] == slot_id for m in group["members"]):
            return {"success": False, "error": f"Slot {slot_id} is already in HA group '{group_name}'"}
        try:
            self.domains.assert_matching(group["members"][0]["slot_id"], slot_id)
        except CloningDomainError as exc:
            return {"success": False, "error": str(exc), "code": exc.code}
        source = group["members"][0]
        firmware = self.storage.get_meta("firmware_version") or "7.13.0"
        policy_fingerprint = self._policy_fingerprint(slot_id)
        if firmware != source["firmware"]:
            return {"success": False, "error": "LUNA_RET_HA_FIRMWARE_MISMATCH: member firmware is incompatible",
                    "code": "LUNA_RET_HA_FIRMWARE_MISMATCH"}
        if policy_fingerprint != self._policy_fingerprint(source["slot_id"]):
            return {"success": False, "error": "LUNA_RET_HA_POLICY_MISMATCH: partition policies are incompatible",
                    "code": "LUNA_RET_HA_POLICY_MISMATCH"}
        group["members"].append({
            "slot_id": slot_id,
            "serial": serial or f"HA-{slot_id:04d}",
            "partition": partition["name"],
            "status": "active",
            "state": "active",
            "role": "active" if group["mode"] == "round-robin" else "standby",
            "objects": len(self._token_objects(slot_id)),
            "last_sync": None,
            "sync_status": "out-of-sync",
            "network_partition": False,
            "failure_reason": None,
            "retry_attempts": 0,
            "firmware": firmware,
            "policy_fingerprint": policy_fingerprint,
        })
        self._write("ha_groups", groups)
        return {"success": True, "member": group["members"][-1]}

    def remove_ha_member(self, group_name: str, slot_id: int) -> dict:
        groups = self._read("ha_groups", {})
        group = groups.get(group_name)
        if group is None:
            return {"success": False, "error": f"HA group '{group_name}' not found"}
        if len(group["members"]) <= 1:
            return {"success": False, "error": "An HA group must retain at least one member"}
        members = [m for m in group["members"] if m["slot_id"] != slot_id]
        if len(members) == len(group["members"]):
            return {"success": False, "error": f"Slot {slot_id} is not in HA group '{group_name}'"}
        group["members"] = members
        self._write("ha_groups", groups)
        return {"success": True}

    def set_ha_mode(self, group_name: str, mode: str) -> dict:
        """Select round-robin load balancing or active/standby routing."""
        if mode not in ("round-robin", "active-standby"):
            return {"success": False, "error": "Mode must be round-robin or active-standby"}
        groups = self._read("ha_groups", {})
        group = groups.get(group_name)
        if group is None:
            return {"success": False, "error": f"HA group '{group_name}' not found"}
        group = self._normalize_ha_group(group)
        group["mode"] = mode
        for index, member in enumerate(group["members"]):
            member["role"] = "active" if mode == "round-robin" or index == 0 else "standby"
        self._save_ha_group(groups, group)
        return {"success": True, "mode": mode}

    def set_ha_recovery_mode(self, group_name: str, mode: str) -> dict:
        if mode not in ("automatic", "manual"):
            return {"success": False, "error": "Recovery mode must be automatic or manual"}
        groups = self._read("ha_groups", {})
        group = groups.get(group_name)
        if group is None:
            return {"success": False, "error": f"HA group '{group_name}' not found"}
        group = self._normalize_ha_group(group)
        group["recovery_mode"] = mode
        self._save_ha_group(groups, group)
        return {"success": True, "recovery_mode": mode}

    def _find_ha_member(self, group: dict, slot_id: int):
        return next((member for member in group["members"] if member["slot_id"] == slot_id), None)

    def fail_ha_member(self, group_name: str, slot_id: int, reason: str = "simulated failure") -> dict:
        groups = self._read("ha_groups", {})
        group = groups.get(group_name)
        if group is None:
            return {"success": False, "error": f"HA group '{group_name}' not found"}
        group = self._normalize_ha_group(group)
        member = self._find_ha_member(group, slot_id)
        if member is None:
            return {"success": False, "error": f"Slot {slot_id} is not an HA member"}
        member.update({"state": "unavailable", "status": "unavailable",
                       "sync_status": "out-of-sync", "failure_reason": reason,
                       "retry_attempts": 0, "last_retry": time.time()})
        if member["role"] == "active":
            replacement = next((m for m in group["members"]
                                if m is not member and m["state"] in ("active", "standby")), None)
            if replacement:
                if group["mode"] == "active-standby":
                    replacement["role"] = "active"
                    member["role"] = "standby"
                group["failover_count"] += 1
        group["state"] = "degraded"
        self._save_ha_group(groups, group)
        return {"success": True, "slot_id": slot_id, "state": member["state"]}

    def set_ha_network_partition(self, group_name: str, slot_id: int, partitioned: bool) -> dict:
        if partitioned:
            result = self.fail_ha_member(group_name, slot_id, "simulated network partition")
            if not result["success"]:
                return result
            groups = self._read("ha_groups", {})
            group = self._normalize_ha_group(groups[group_name])
            self._find_ha_member(group, slot_id)["network_partition"] = True
            self._save_ha_group(groups, group)
            return result
        groups = self._read("ha_groups", {})
        group = groups.get(group_name)
        if group is None:
            return {"success": False, "error": f"HA group '{group_name}' not found"}
        group = self._normalize_ha_group(group)
        member = self._find_ha_member(group, slot_id)
        if member is None:
            return {"success": False, "error": f"Slot {slot_id} is not an HA member"}
        member["network_partition"] = False
        member["failure_reason"] = None
        member["state"] = "recovering"
        member["status"] = "recovering"
        self._save_ha_group(groups, group)
        if group["recovery_mode"] == "automatic":
            return self.recover_ha_member(group_name, slot_id)
        return {"success": True, "slot_id": slot_id, "state": "recovering"}

    def check_ha_compatibility(self, group_name: str, slot_id: int,
                               source_slot: int = None) -> dict:
        group = self.get_ha_group(group_name)
        if group is None:
            return {"success": False, "error": f"HA group '{group_name}' not found"}
        member = self._find_ha_member(group, slot_id)
        if member is None:
            return {"success": False, "error": f"Slot {slot_id} is not an HA member"}
        source = (self._find_ha_member(group, source_slot) if source_slot is not None
                  else group["members"][0])
        errors = []
        try:
            self.domains.assert_matching(source["slot_id"], slot_id)
        except CloningDomainError as exc:
            errors.append(str(exc))
        current_firmware = member.get("firmware")
        if current_firmware != source.get("firmware"):
            errors.append("LUNA_RET_HA_FIRMWARE_MISMATCH")
        source_policy = self._policy_fingerprint(source["slot_id"])
        current_policy = self._policy_fingerprint(slot_id)
        if current_policy != source_policy:
            errors.append("LUNA_RET_HA_POLICY_MISMATCH")
        return {"success": not errors, "compatible": not errors, "errors": errors}

    def set_ha_member_firmware(self, group_name: str, slot_id: int, firmware: str) -> dict:
        """Set a per-member simulated firmware version for compatibility training."""
        groups = self._read("ha_groups", {})
        group = groups.get(group_name)
        if group is None:
            return {"success": False, "error": f"HA group '{group_name}' not found"}
        group = self._normalize_ha_group(group)
        member = self._find_ha_member(group, slot_id)
        if member is None:
            return {"success": False, "error": f"Slot {slot_id} is not an HA member"}
        member["firmware"] = firmware
        self._save_ha_group(groups, group)
        return {"success": True, "firmware": firmware}

    def route_ha_operation(self, group_name: str, operation: str,
                           session_object: bool = False, allowed_slots: set = None) -> dict:
        """Route an operation to a healthy member with load balancing/failover."""
        groups = self._read("ha_groups", {})
        group = groups.get(group_name)
        if group is None:
            return {"success": False, "error": f"HA group '{group_name}' not found"}
        group = self._normalize_ha_group(group)
        eligible = [m for m in group["members"]
                    if m["state"] in ("active", "standby") and not m["network_partition"]
                    and (allowed_slots is None or m["slot_id"] in allowed_slots)]
        if not eligible:
            return {"success": False, "error": "LUNA_RET_HA_NO_AVAILABLE_MEMBER",
                    "code": "LUNA_RET_HA_NO_AVAILABLE_MEMBER"}
        if group["mode"] == "round-robin":
            index = group["round_robin_cursor"] % len(eligible)
            member = eligible[index]
            group["round_robin_cursor"] = (index + 1) % len(eligible)
        else:
            member = next((m for m in eligible if m["role"] == "active"), eligible[0])
            if member["role"] != "active":
                member["role"] = "active"
                group["failover_count"] += 1
        group["operation_count"] += 1
        group["last_operation"] = {"operation": operation, "slot_id": member["slot_id"],
                                   "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
                                   "session_object": bool(session_object)}
        self._save_ha_group(groups, group)
        return {"success": True, "slot_id": member["slot_id"], "serial": member["serial"],
                "operation": operation, "load_balanced": group["mode"] == "round-robin",
                "session_object_replicated": False if session_object else None}

    def recover_ha_member(self, group_name: str, slot_id: int) -> dict:
        groups = self._read("ha_groups", {})
        group = groups.get(group_name)
        if group is None:
            return {"success": False, "error": f"HA group '{group_name}' not found"}
        group = self._normalize_ha_group(group)
        member = self._find_ha_member(group, slot_id)
        if member is None:
            return {"success": False, "error": f"Slot {slot_id} is not an HA member"}
        if member["network_partition"]:
            return {"success": False, "error": "Member remains isolated by a network partition"}
        compatibility = self.check_ha_compatibility(group_name, slot_id)
        if not compatibility["compatible"]:
            member.update({"state": "incompatible", "status": "incompatible",
                           "sync_status": "out-of-sync",
                           "failure_reason": ", ".join(compatibility["errors"])})
            self._save_ha_group(groups, group)
            return {"success": False, "error": member["failure_reason"], "partial": True}
        source = next((m for m in group["members"]
                       if m["slot_id"] != slot_id and m["state"] in ("active", "standby")), None)
        if source:
            try:
                self._apply_deletions(group, source["slot_id"])
                self._apply_deletions(group, slot_id)
                result = self.domains.clone_objects(source["slot_id"], slot_id,
                                                   token_objects_only=True, synchronize=True)
                if result["skipped_policy"]:
                    raise ValueError("Cloning policy prevented complete recovery")
            except Exception as exc:
                member["failure_reason"] = str(exc)
                member["sync_status"] = "partial"
                self._save_ha_group(groups, group)
                return {"success": False, "error": str(exc), "partial": True}
        self._apply_deletions(group, slot_id)
        member.update({"state": "active", "status": "active", "sync_status": "current",
                       "failure_reason": None, "retry_attempts": 0,
                       "objects": len(self._token_objects(slot_id)),
                       "last_sync": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())})
        group["state"] = "active" if all(m["state"] in ("active", "standby") for m in group["members"]) else "degraded"
        self._save_ha_group(groups, group)
        return {"success": True, "slot_id": slot_id, "state": member["state"]}

    def set_ha_retry(self, group_name: str, retry_count: int) -> dict:
        if retry_count < -1:
            return {"success": False, "error": "Retry count must be -1 or greater"}
        groups = self._read("ha_groups", {})
        if group_name is None:
            settings = self._read("ha_client_settings", {})
            settings["retry_count"] = retry_count
            self._write("ha_client_settings", settings)
            for group in groups.values():
                group["retry_count"] = retry_count
                group["infinite_polling"] = retry_count == -1
        else:
            group = groups.get(group_name)
            if group is None:
                return {"success": False, "error": f"HA group '{group_name}' not found"}
            group["retry_count"] = retry_count
            group["infinite_polling"] = retry_count == -1
        self._write("ha_groups", groups)
        return {"success": True, "retry_count": retry_count, "infinite_polling": retry_count == -1}

    def set_ha_interval(self, group_name: str, seconds: int) -> dict:
        if seconds < 0:
            return {"success": False, "error": "Polling interval cannot be negative"}
        groups = self._read("ha_groups", {})
        if group_name is None:
            settings = self._read("ha_client_settings", {})
            settings["poll_interval"] = seconds
            self._write("ha_client_settings", settings)
            for group in groups.values():
                group["poll_interval"] = seconds
        else:
            group = groups.get(group_name)
            if group is None:
                return {"success": False, "error": f"HA group '{group_name}' not found"}
            group["poll_interval"] = seconds
        self._write("ha_groups", groups)
        return {"success": True, "poll_interval": seconds}

    def synchronize_ha_group(self, name: str, source_slot: int = None) -> dict:
        """Replicate persistent keys independently and report partial failures."""
        groups = self._read("ha_groups", {})
        group = groups.get(name)
        if group is None:
            return {"success": False, "error": f"HA group '{name}' not found"}
        group = self._normalize_ha_group(group)
        if not group["members"]:
            return {"success": False, "error": f"HA group '{name}' has no members"}
        source = next((m for m in group["members"]
                       if m["state"] in ("active", "standby") and not m["network_partition"]
                       and (source_slot is None or m["slot_id"] == source_slot)), None)
        if source is None:
            return {"success": False, "error": "LUNA_RET_HA_NO_AVAILABLE_MEMBER"}

        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        source["objects"] = len(self._token_objects(source["slot_id"]))
        source["last_sync"] = timestamp
        source["sync_status"] = "current"
        cloned = 0
        failures = []
        for member in group["members"]:
            if member is source:
                continue
            if member["network_partition"]:
                member["retry_attempts"] += 1
                member["sync_status"] = "out-of-sync"
                failures.append({"slot_id": member["slot_id"], "error": "network partition"})
                continue
            if member["state"] == "unavailable" and group["recovery_mode"] == "manual":
                member["retry_attempts"] += 1
                failures.append({"slot_id": member["slot_id"], "error": member["failure_reason"] or "unavailable"})
                continue
            compatibility = self.check_ha_compatibility(
                name, member["slot_id"], source_slot=source["slot_id"])
            if not compatibility["compatible"]:
                member.update({"state": "incompatible", "status": "incompatible",
                               "sync_status": "out-of-sync",
                               "failure_reason": ", ".join(compatibility["errors"])})
                failures.append({"slot_id": member["slot_id"], "error": member["failure_reason"]})
                continue
            try:
                self._apply_deletions(group, source["slot_id"])
                self._apply_deletions(group, member["slot_id"])
                result = self.domains.clone_objects(
                    source["slot_id"], member["slot_id"], token_objects_only=True,
                    synchronize=True)
                if result["skipped_policy"]:
                    raise ValueError("Cloning policy prevented complete synchronization")
                cloned += len(result["cloned"])
                member.update({"state": "active", "status": "active", "sync_status": "current",
                               "objects": len(self._token_objects(member["slot_id"])),
                               "last_sync": timestamp, "failure_reason": None, "retry_attempts": 0})
            except Exception as exc:
                member["sync_status"] = "partial"
                member["failure_reason"] = str(exc)
                member["retry_attempts"] += 1
                failures.append({"slot_id": member["slot_id"], "error": str(exc)})

        group["state"] = "degraded" if failures else "active"
        self._save_ha_group(groups, group)
        return {"success": not failures, "partial": bool(failures), "group": name,
                "objects": source["objects"], "cloned": cloned,
                "members": len(group["members"]), "failures": failures,
                "timestamp": timestamp}

    def get_ha_status(self, name: str) -> dict:
        group = self.get_ha_group(name)
        if group is None:
            return {"success": False, "error": f"HA group '{name}' not found"}
        members = []
        for member in group["members"]:
            data = dict(member)
            data["objects"] = len(self._token_objects(member["slot_id"]))
            members.append(data)
        return {
            "success": True,
            "name": name,
            "state": group["state"],
            "mode": group["mode"],
            "recovery_mode": group["recovery_mode"],
            "members": len(members),
            "member_status": members,
            "active_members": sum(1 for m in members if m["state"] in ("active", "standby")),
            "retry_count": group["retry_count"],
            "poll_interval": group["poll_interval"],
            "infinite_polling": group["infinite_polling"],
            "operation_count": group["operation_count"],
            "failover_count": group["failover_count"],
            "last_operation": group["last_operation"],
        }

    # ------------------------------------------------------------------
    # NTP
    # ------------------------------------------------------------------

    def get_ntp_config(self) -> dict:
        return self._read("ntp_config", {})

    def add_ntp_server(self, server: str) -> dict:
        config = self.get_ntp_config()
        if server not in config["servers"]:
            config["servers"].append(server)
        self._write("ntp_config", config)
        return {"success": True, "servers": config["servers"]}

    def delete_ntp_server(self, server: str) -> dict:
        config = self.get_ntp_config()
        config["servers"] = [item for item in config["servers"] if item != server]
        if not config["servers"]:
            return {"success": False, "error": "At least one NTP server is required"}
        self._write("ntp_config", config)
        return {"success": True, "servers": config["servers"]}

    def enable_ntp(self) -> dict:
        config = self.get_ntp_config()
        config["enabled"] = True
        config["synchronized"] = True
        config["last_sync"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        self._write("ntp_config", config)
        return {"success": True}

    def disable_ntp(self) -> dict:
        config = self.get_ntp_config()
        config["enabled"] = False
        config["synchronized"] = False
        self._write("ntp_config", config)
        return {"success": True}

    def sync_ntp(self) -> dict:
        config = self.get_ntp_config()
        if not config["enabled"]:
            return {"success": False, "error": "NTP is disabled"}
        config["synchronized"] = True
        config["last_sync"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        self._write("ntp_config", config)
        return {"success": True, "last_sync": config["last_sync"]}

    # ------------------------------------------------------------------
    # Network bonding
    # ------------------------------------------------------------------

    def get_network_bonds(self) -> dict:
        return self._read("network_bonds", {})

    def configure_bond(self, name: str, members: list, ip: str, netmask: str, gateway: str = "") -> dict:
        if name not in ("bond0", "bond1"):
            return {"success": False, "error": "Bond name must be bond0 or bond1"}
        if len(members) != 2 or len(set(members)) != 2:
            return {"success": False, "error": "A bond requires two distinct interfaces"}
        if any(member not in ("eth0", "eth1", "eth2", "eth3") for member in members):
            return {"success": False, "error": "Bond members must be eth0 through eth3"}
        bonds = self.get_network_bonds()
        if any(name != existing and set(data["members"]) & set(members) for existing, data in bonds.items()):
            return {"success": False, "error": "An interface cannot belong to more than one bond"}
        bonds[name] = {
            "name": name,
            "members": members,
            "ip": ip,
            "netmask": netmask,
            "gateway": gateway,
            "status": "up",
            "mode": "active-backup",
        }
        self._write("network_bonds", bonds)
        return {"success": True, "bond": bonds[name]}

    def enable_bond(self, name: str) -> dict:
        bonds = self.get_network_bonds()
        if name not in bonds:
            return {"success": False, "error": f"Bond '{name}' is not configured"}
        bonds[name]["status"] = "up"
        self._write("network_bonds", bonds)
        return {"success": True}

    def disable_bond(self, name: str) -> dict:
        bonds = self.get_network_bonds()
        if name not in bonds:
            return {"success": False, "error": f"Bond '{name}' is not configured"}
        bonds[name]["status"] = "down"
        self._write("network_bonds", bonds)
        return {"success": True}

    def delete_bond(self, name: str) -> dict:
        bonds = self.get_network_bonds()
        if name not in bonds:
            return {"success": False, "error": f"Bond '{name}' is not configured"}
        del bonds[name]
        self._write("network_bonds", bonds)
        return {"success": True}

    # ------------------------------------------------------------------
    # Licenses
    # ------------------------------------------------------------------

    def list_licenses(self) -> list:
        licenses = self._read("license_config", DEFAULT_LICENSES)
        result = []
        for key, value in licenses.items():
            entry = dict(value)
            entry["name"] = key
            result.append(entry)
        return result

    def get_license_limit(self, name: str, default: int) -> int:
        license_info = self._read("license_config", DEFAULT_LICENSES).get(name, {})
        return int(license_info.get("limit", default)) if license_info.get("enabled", False) else 0

    def set_license_limit(self, name: str, limit: int) -> dict:
        if limit < 0:
            return {"success": False, "error": "License limit cannot be negative"}
        licenses = self._read("license_config", DEFAULT_LICENSES)
        if name not in licenses:
            return {"success": False, "error": f"License '{name}' not found"}
        licenses[name]["limit"] = limit
        licenses[name]["enabled"] = True
        self._write("license_config", licenses)
        return {"success": True, "name": name, "limit": limit}

    def set_license_enabled(self, name: str, enabled: bool) -> dict:
        licenses = self._read("license_config", DEFAULT_LICENSES)
        if name not in licenses:
            return {"success": False, "error": f"License '{name}' not found"}
        licenses[name]["enabled"] = enabled
        self._write("license_config", licenses)
        return {"success": True, "name": name, "enabled": enabled}

    # ------------------------------------------------------------------
    # Support information
    # ------------------------------------------------------------------

    def build_support_bundle(self, appliance, api=None) -> str:
        """Build a diagnostic report without credentials or key material."""
        status = appliance.get_status()
        network = appliance.get_network_info()
        safe_interfaces = {}
        for name, info in network.get("interfaces", {}).items():
            safe_interfaces[name] = {
                "method": info.get("method"),
                "ip": info.get("ip", ""),
                "netmask": info.get("netmask", ""),
                "gateway": info.get("gateway", ""),
                "status": info.get("status", ""),
            }
        lines = [
            "Luna Network HSM 7 Emulator Support Information",
            f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}",
            "",
            "[Appliance]",
            f"Hostname: {status['hostname']}",
            f"Uptime: {status['uptime_str']}",
            f"Partitions: {status['partitions']}",
            f"Registered clients: {status['clients']}",
            f"Services running: {status['services_running']}/{status['services_total']}",
            "",
            "[Network]",
            f"Domain: {network.get('domain', '')}",
            f"DNS servers: {', '.join(network.get('dns_nameservers', []))}",
            f"Interfaces: {json.dumps(safe_interfaces, sort_keys=True)}",
            f"Bonds: {json.dumps(self.get_network_bonds(), sort_keys=True)}",
            "",
            "[NTP]",
            f"Configuration: {json.dumps(self.get_ntp_config(), sort_keys=True)}",
            "",
            "[Connections]",
            f"Summary: {json.dumps(appliance.connections.get_connection_summary(), sort_keys=True)}",
            "",
            "[HA]",
            f"Groups: {json.dumps(self.list_ha_groups(), sort_keys=True)}",
            "",
            "[Licenses]",
            f"Licenses: {json.dumps(self.list_licenses(), sort_keys=True)}",
            "",
            "[Safety]",
            "Credentials, PINs, password hashes, private keys, encrypted key blobs, and secret values are excluded.",
        ]
        bundle = "\n".join(lines)
        history = self._read("support_bundle_history", [])
        history.append({"generated_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), "length": len(bundle)})
        self._write("support_bundle_history", history[-20:])
        return bundle

    def get_support_bundle_history(self) -> list:
        return self._read("support_bundle_history", [])
