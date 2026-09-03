"""Deployment and operations features for the Luna Network HSM emulator."""

import json
import time
from typing import Optional


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

    def list_ha_groups(self) -> list:
        groups = self._read("ha_groups", {})
        return list(groups.values())

    def get_ha_group(self, name: str) -> Optional[dict]:
        return self._read("ha_groups", {}).get(name)

    def create_ha_group(self, name: str, slot_id: int, label: str = "") -> dict:
        groups = self._read("ha_groups", {})
        if name in groups:
            return {"success": False, "error": f"HA group '{name}' already exists"}
        partition = self.storage.get_partition(slot_id)
        if partition is None:
            return {"success": False, "error": f"Partition slot {slot_id} not found"}
        group = {
            "name": name,
            "label": label or name,
            "state": "active",
            "retry_count": 216,
            "poll_interval": 0,
            "infinite_polling": False,
            "synchronize_on_add": True,
            "members": [{
                "slot_id": slot_id,
                "serial": f"HA-{slot_id:04d}",
                "partition": partition["name"],
                "status": "active",
                "objects": self.storage.count_objects(slot_id),
                "last_sync": None,
            }],
            "created_at": time.time(),
        }
        groups[name] = group
        self._write("ha_groups", groups)
        return {"success": True, "group": group}

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
        partition = self.storage.get_partition(slot_id)
        if partition is None:
            return {"success": False, "error": f"Partition slot {slot_id} not found"}
        if any(m["slot_id"] == slot_id for m in group["members"]):
            return {"success": False, "error": f"Slot {slot_id} is already in HA group '{group_name}'"}
        group["members"].append({
            "slot_id": slot_id,
            "serial": serial or f"HA-{slot_id:04d}",
            "partition": partition["name"],
            "status": "active",
            "objects": self.storage.count_objects(slot_id),
            "last_sync": None,
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

    def set_ha_retry(self, group_name: str, retry_count: int) -> dict:
        if retry_count < -1:
            return {"success": False, "error": "Retry count must be -1 or greater"}
        groups = self._read("ha_groups", {})
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
        group = groups.get(group_name)
        if group is None:
            return {"success": False, "error": f"HA group '{group_name}' not found"}
        group["poll_interval"] = seconds
        self._write("ha_groups", groups)
        return {"success": True, "poll_interval": seconds}

    def synchronize_ha_group(self, name: str) -> dict:
        groups = self._read("ha_groups", {})
        group = groups.get(name)
        if group is None:
            return {"success": False, "error": f"HA group '{name}' not found"}
        source_objects = max((m["objects"] for m in group["members"]), default=0)
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        for member in group["members"]:
            member["objects"] = source_objects
            member["last_sync"] = timestamp
            member["status"] = "active"
        self._write("ha_groups", groups)
        return {"success": True, "group": name, "objects": source_objects, "members": len(group["members"]), "timestamp": timestamp}

    def get_ha_status(self, name: str) -> dict:
        group = self.get_ha_group(name)
        if group is None:
            return {"success": False, "error": f"HA group '{name}' not found"}
        return {
            "success": True,
            "name": name,
            "state": group["state"],
            "members": len(group["members"]),
            "active_members": sum(1 for m in group["members"] if m["status"] == "active"),
            "retry_count": group["retry_count"],
            "poll_interval": group["poll_interval"],
            "infinite_polling": group["infinite_polling"],
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
