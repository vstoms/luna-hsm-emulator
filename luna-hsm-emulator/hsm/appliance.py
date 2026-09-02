"""Luna Network HSM 7 Appliance emulation.

This module simulates the appliance-level state of a Luna Network HSM 7,
which is managed through LunaSH (the server-side command shell). This is
distinct from the PKCS#11 / lunacm client-side interface.

The appliance manages:
  - Appliance users and roles (admin, operator, monitor, audit)
  - Network configuration (hostname, interfaces, DNS, routes)
  - NTLS (Network Trust Link Service) connections
  - HSM clients and their partition assignments
  - System services (ntls, ssh, stc, webserver)
  - System configuration (timezone, SSH, banners, reboot)
  - System status (CPU, memory, disk, uptime)
  - Syslog configuration
"""

import time
import os
import hashlib
import secrets
import json
from typing import Optional

from hsm.connections import ConnectionManager, CERT_SELF_SIGNED
from hsm.deployment import DeploymentManager


# Appliance user roles
ROLE_ADMIN = "admin"
ROLE_OPERATOR = "operator"
ROLE_MONITOR = "monitor"
ROLE_AUDIT = "audit"

ALL_ROLES = [ROLE_ADMIN, ROLE_OPERATOR, ROLE_MONITOR, ROLE_AUDIT]

ROLE_DESCRIPTIONS = {
    ROLE_ADMIN: "All commands, except some specialized audit commands. Highest-level administrative role.",
    ROLE_OPERATOR: "Most commands, except some configuration commands for the system and the HSM.",
    ROLE_MONITOR: "Only commands that present information about the appliance or the HSM.",
    ROLE_AUDIT: "Only commands governing HSM audit logging functions.",
}

# Default users created on a fresh appliance
DEFAULT_USERS = [
    {"username": "admin", "role": ROLE_ADMIN, "description": ROLE_DESCRIPTIONS[ROLE_ADMIN]},
    {"username": "operator", "role": ROLE_OPERATOR, "description": ROLE_DESCRIPTIONS[ROLE_OPERATOR]},
    {"username": "monitor", "role": ROLE_MONITOR, "description": ROLE_DESCRIPTIONS[ROLE_MONITOR]},
    {"username": "audit", "role": ROLE_AUDIT, "description": ROLE_DESCRIPTIONS[ROLE_AUDIT]},
]

# Appliance hostname prefix
APPLIANCE_HOSTNAME_PREFIX = "luna7"

# Simulated services
DEFAULT_SERVICES = {
    "ntls": {"status": "running", "description": "Network Trust Link Service"},
    "ssh": {"status": "running", "description": "SSH remote access"},
    "stc": {"status": "stopped", "description": "Secure Trusted Channel"},
    "webserver": {"status": "stopped", "description": "REST API web server"},
    "snmp": {"status": "running", "description": "SNMP monitoring agent"},
    "ntp": {"status": "running", "description": "Network Time Protocol"},
}

# Default network config
DEFAULT_NETWORK = {
    "hostname": "luna7-appliance",
    "domain": "local",
    "dns_nameservers": ["8.8.8.8", "8.8.4.4"],
    "dns_searchdomains": ["local"],
    "interfaces": {
        "eth0": {
            "method": "static",
            "ip": "192.168.1.100",
            "netmask": "255.255.255.0",
            "gateway": "192.168.1.1",
            "mac": "00:0C:29:A1:B2:C3",
            "speed": "auto",
            "status": "up",
        },
    },
    "routes": [
        {"destination": "default", "gateway": "192.168.1.1", "interface": "eth0"},
    ],
}

# Default sysconf
DEFAULT_SYSCONF = {
    "timezone": "UTC",
    "force_so_login": False,
    "banner": "",
    "reboot_on_panic": True,
    "ssh_port": 22,
    "ssh_password_auth": True,
    "ssh_pubkey_auth": True,
    "ssh_ip": "",
    "ntp_server": "pool.ntp.org",
    "date_format": "YYYY-MM-DD HH:MM:SS",
}


class ApplianceUser:
    """An appliance-level user account."""

    def __init__(self, username: str, role: str, password_hash: str = "",
                 password_salt: str = "", enabled: bool = True,
                 created_at: float = None, last_login: float = None):
        self.username = username
        self.role = role
        self.password_hash = password_hash
        self.password_salt = password_salt
        self.enabled = enabled
        self.created_at = created_at or time.time()
        self.last_login = last_login

    def to_dict(self) -> dict:
        return {
            "username": self.username,
            "role": self.role,
            "password_hash": self.password_hash,
            "password_salt": self.password_salt,
            "enabled": self.enabled,
            "created_at": self.created_at,
            "last_login": self.last_login,
        }

    @classmethod
    def from_dict(cls, d: dict):
        return cls(
            d["username"], d["role"], d.get("password_hash", ""),
            d.get("password_salt", ""), d.get("enabled", True),
            d.get("created_at"), d.get("last_login"),
        )


class HSMClient:
    """A registered HSM client that can be assigned to partitions."""

    def __init__(self, client_id: int, name: str, ip: str = "",
                 distinguished_name: str = "", created_at: float = None):
        self.client_id = client_id
        self.name = name
        self.ip = ip
        self.distinguished_name = distinguished_name
        self.assigned_partitions = []  # list of slot_ids
        self.created_at = created_at or time.time()

    def to_dict(self) -> dict:
        return {
            "client_id": self.client_id,
            "name": self.name,
            "ip": self.ip,
            "distinguished_name": self.distinguished_name,
            "assigned_partitions": self.assigned_partitions,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, d: dict):
        c = cls(d["client_id"], d["name"], d.get("ip", ""),
                d.get("distinguished_name", ""), d.get("created_at"))
        c.assigned_partitions = d.get("assigned_partitions", [])
        return c


class Appliance:
    """Emulates the Luna Network HSM 7 appliance.

    This is the server-side appliance that hosts the HSM. It is managed
    through LunaSH, which is the appliance's command shell (as opposed
    to lunacm, which is the client-side PKCS#11 configuration manager).
    """

    def __init__(self, storage):
        self.storage = storage
        self._current_user = None  # logged-in appliance user
        self._hsm_logged_in = False  # HSM SO login state
        self._audit_logged_in = False  # Auditor login state
        self._boot_time = time.time()
        self.connections = ConnectionManager(storage)
        self.deployment = DeploymentManager(storage)
        self._ensure_state()

    def _ensure_state(self):
        """Initialize appliance metadata if not present."""
        if not self.storage.get_meta("appliance_hostname"):
            self.storage.set_meta("appliance_hostname", DEFAULT_NETWORK["hostname"])
        if not self.storage.get_meta("appliance_domain"):
            self.storage.set_meta("appliance_domain", DEFAULT_NETWORK["domain"])
        if not self.storage.get_meta("appliance_users"):
            # Create default users
            users = []
            for u in DEFAULT_USERS:
                users.append(ApplianceUser(u["username"], u["role"]))
            self._save_users(users)
        if not self.storage.get_meta("appliance_services"):
            import json
            self.storage.set_meta("appliance_services", json.dumps(DEFAULT_SERVICES))
        if not self.storage.get_meta("appliance_network"):
            import json
            self.storage.set_meta("appliance_network", json.dumps(DEFAULT_NETWORK))
        if not self.storage.get_meta("appliance_sysconf"):
            import json
            self.storage.set_meta("appliance_sysconf", json.dumps(DEFAULT_SYSCONF))
        if not self.storage.get_meta("appliance_clients"):
            self.storage.set_meta("appliance_clients", "[]")
        if not self.storage.get_meta("appliance_syslog_config"):
            import json
            self.storage.set_meta("appliance_syslog_config", json.dumps({
                "severity": "info",
                "remote_hosts": [],
                "rotations": 10,
            }))

    # ------------------------------------------------------------------
    # User authentication
    # ------------------------------------------------------------------

    def _get_users(self) -> list:
        import json
        raw = self.storage.get_meta("appliance_users")
        if raw:
            try:
                return [ApplianceUser.from_dict(d) for d in json.loads(raw)]
            except (json.JSONDecodeError, TypeError):
                pass
        return []

    def _save_users(self, users: list):
        import json
        self.storage.set_meta("appliance_users",
                              json.dumps([u.to_dict() for u in users]))

    def login(self, username: str, password: str) -> dict:
        """Log in to the appliance as a user.

        On a real Luna 7, this is SSH-based authentication.
        """
        users = self._get_users()
        user = next((u for u in users if u.username == username), None)
        if user is None:
            return {"success": False, "error": "User not found"}
        if not user.enabled:
            return {"success": False, "error": "User account is disabled"}
        if not user.password_hash:
            # First login — set password
            if not password:
                return {"success": False, "error": "Password required for first login",
                        "first_login": True}
            ph, ps = self._hash_password(password)
            user.password_hash = ph
            user.password_salt = ps
            user.last_login = time.time()
            self._save_users(users)
            self._current_user = user
            return {"success": True, "user": user, "first_login": True}
        if not self._verify_password(password, user.password_hash, user.password_salt):
            return {"success": False, "error": "Invalid password"}
        user.last_login = time.time()
        self._save_users(users)
        self._current_user = user
        return {"success": True, "user": user}

    def logout(self):
        """Log out of the appliance."""
        self._current_user = None
        self._hsm_logged_in = False
        self._audit_logged_in = False

    def get_current_user(self) -> Optional[ApplianceUser]:
        return self._current_user

    def is_logged_in(self) -> bool:
        return self._current_user is not None

    def _check_role(self, *allowed_roles) -> bool:
        if self._current_user is None:
            return False
        return self._current_user.role in allowed_roles

    def _hash_password(self, password: str) -> tuple:
        salt = secrets.token_hex(16)
        h = hashlib.sha256((password + salt).encode()).hexdigest()
        return h, salt

    def _verify_password(self, password: str, hash_val: str, salt: str) -> bool:
        h = hashlib.sha256((password + salt).encode()).hexdigest()
        return h == hash_val

    # ------------------------------------------------------------------
    # User management
    # ------------------------------------------------------------------

    def list_users(self) -> list:
        """List all appliance users."""
        users = self._get_users()
        return [{
            "username": u.username,
            "role": u.role,
            "enabled": u.enabled,
            "created": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(u.created_at)),
            "last_login": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(u.last_login)) if u.last_login else "Never",
        } for u in users]

    def add_user(self, username: str, role: str, password: str = "") -> dict:
        """Add a new appliance user. Requires admin role."""
        if not self._check_role(ROLE_ADMIN):
            return {"success": False, "error": "Permission denied: admin role required"}
        if role not in ALL_ROLES:
            return {"success": False, "error": f"Invalid role. Valid: {', '.join(ALL_ROLES)}"}
        users = self._get_users()
        if any(u.username == username for u in users):
            return {"success": False, "error": f"User '{username}' already exists"}
        ph, ps = self._hash_password(password) if password else ("", "")
        user = ApplianceUser(username, role, ph, ps)
        users.append(user)
        self._save_users(users)
        return {"success": True, "username": username, "role": role}

    def delete_user(self, username: str) -> dict:
        """Delete an appliance user. Requires admin role."""
        if not self._check_role(ROLE_ADMIN):
            return {"success": False, "error": "Permission denied: admin role required"}
        users = self._get_users()
        user = next((u for u in users if u.username == username), None)
        if user is None:
            return {"success": False, "error": f"User '{username}' not found"}
        if username in ("admin",):
            return {"success": False, "error": "Cannot delete the admin user"}
        users = [u for u in users if u.username != username]
        self._save_users(users)
        return {"success": True, "username": username}

    def enable_user(self, username: str) -> dict:
        """Enable a disabled user account. Requires admin role."""
        if not self._check_role(ROLE_ADMIN):
            return {"success": False, "error": "Permission denied: admin role required"}
        users = self._get_users()
        user = next((u for u in users if u.username == username), None)
        if user is None:
            return {"success": False, "error": f"User '{username}' not found"}
        user.enabled = True
        self._save_users(users)
        return {"success": True, "username": username}

    def disable_user(self, username: str) -> dict:
        """Disable a user account. Requires admin role."""
        if not self._check_role(ROLE_ADMIN):
            return {"success": False, "error": "Permission denied: admin role required"}
        if username == "admin":
            return {"success": False, "error": "Cannot disable the admin user"}
        users = self._get_users()
        user = next((u for u in users if u.username == username), None)
        if user is None:
            return {"success": False, "error": f"User '{username}' not found"}
        user.enabled = False
        self._save_users(users)
        return {"success": True, "username": username}

    def set_user_password(self, username: str, password: str) -> dict:
        """Set a user's password."""
        users = self._get_users()
        user = next((u for u in users if u.username == username), None)
        if user is None:
            return {"success": False, "error": f"User '{username}' not found"}
        ph, ps = self._hash_password(password)
        user.password_hash = ph
        user.password_salt = ps
        self._save_users(users)
        return {"success": True, "username": username}

    # ------------------------------------------------------------------
    # HSM SO login (separate from appliance login)
    # ------------------------------------------------------------------

    def hsm_login(self, so_pin: str) -> dict:
        """Log in to the HSM as Security Officer.

        On a real Luna 7: 'hsm login' — requires the HSM SO PIN.
        This is separate from the appliance SSH login.
        """
        if not self.is_logged_in():
            return {"success": False, "error": "Must log in to appliance first"}
        partitions = self.storage.get_all_partitions()
        if not partitions:
            return {"success": False, "error": "No partitions configured"}
        slot_id = partitions[0]["slot_id"]
        partition = self.storage.get_partition(slot_id)
        stored_hash = partition.get("so_pin_hash")
        stored_salt = partition.get("so_pin_salt")
        if not stored_hash or not stored_salt:
            return {"success": False, "error": "HSM SO PIN not initialized"}
        if not self.storage.verify_pin(so_pin, stored_hash, stored_salt):
            return {"success": False, "error": "Invalid HSM SO PIN"}
        self._hsm_logged_in = True
        return {"success": True}

    def hsm_logout(self):
        """Log out of the HSM."""
        self._hsm_logged_in = False

    def is_hsm_logged_in(self) -> bool:
        return self._hsm_logged_in

    def audit_login(self, audit_pin: str) -> dict:
        """Log in as the Auditor."""
        if not self.is_logged_in():
            return {"success": False, "error": "Must log in to appliance first"}
        self._audit_logged_in = True
        return {"success": True}

    def audit_logout(self):
        self._audit_logged_in = False

    def is_audit_logged_in(self) -> bool:
        return self._audit_logged_in

    # ------------------------------------------------------------------
    # Network configuration
    # ------------------------------------------------------------------

    def _get_network_config(self) -> dict:
        import json
        raw = self.storage.get_meta("appliance_network")
        if raw:
            try:
                return json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                pass
        return dict(DEFAULT_NETWORK)

    def _save_network_config(self, config: dict):
        import json
        self.storage.set_meta("appliance_network", json.dumps(config))

    def get_network_info(self) -> dict:
        return self._get_network_config()

    def set_hostname(self, hostname: str) -> dict:
        config = self._get_network_config()
        config["hostname"] = hostname
        self._save_network_config(config)
        self.storage.set_meta("appliance_hostname", hostname)
        return {"success": True, "hostname": hostname}

    def set_interface_static(self, iface: str, ip: str, netmask: str,
                             gateway: str = "") -> dict:
        config = self._get_network_config()
        if iface not in config["interfaces"]:
            config["interfaces"][iface] = {"method": "static", "status": "up",
                                          "mac": "00:00:00:00:00:00", "speed": "auto"}
        config["interfaces"][iface].update({
            "method": "static", "ip": ip, "netmask": netmask,
        })
        if gateway:
            config["interfaces"][iface]["gateway"] = gateway
        self._save_network_config(config)
        return {"success": True, "interface": iface, "ip": ip}

    def set_interface_dhcp(self, iface: str) -> dict:
        config = self._get_network_config()
        if iface not in config["interfaces"]:
            config["interfaces"][iface] = {"status": "up", "mac": "00:00:00:00:00:00",
                                          "speed": "auto"}
        config["interfaces"][iface]["method"] = "dhcp"
        self._save_network_config(config)
        return {"success": True, "interface": iface}

    def add_dns_nameserver(self, server: str) -> dict:
        config = self._get_network_config()
        if server not in config["dns_nameservers"]:
            config["dns_nameservers"].append(server)
        self._save_network_config(config)
        return {"success": True, "nameserver": server}

    def delete_dns_nameserver(self, server: str) -> dict:
        config = self._get_network_config()
        config["dns_nameservers"] = [s for s in config["dns_nameservers"] if s != server]
        self._save_network_config(config)
        return {"success": True}

    def add_route(self, destination: str, gateway: str, interface: str = "eth0") -> dict:
        config = self._get_network_config()
        config["routes"].append({"destination": destination, "gateway": gateway,
                                "interface": interface})
        self._save_network_config(config)
        return {"success": True}

    def delete_route(self, destination: str) -> dict:
        config = self._get_network_config()
        config["routes"] = [r for r in config["routes"]
                           if r["destination"] != destination]
        self._save_network_config(config)
        return {"success": True}

    def show_routes(self) -> list:
        config = self._get_network_config()
        return config["routes"]

    def ping(self, host: str) -> dict:
        """Simulate a network ping."""
        return {"success": True, "host": host, "result": "PING simulated — host is reachable"}

    # ------------------------------------------------------------------
    # NTLS
    # ------------------------------------------------------------------

    def get_ntls_info(self) -> dict:
        cert = self.connections.get_ntls_server_cert()
        summary = self.connections.get_connection_summary()
        bound = self.connections.get_ntls_bound_interfaces()
        return {
            "status": "running",
            "bound_interfaces": ", ".join(bound) if bound else "none",
            "connections": summary["ntls_total"],
            "connected": summary["ntls_connected"],
            "broken": summary.get("ntls_broken", 0),
            "certificate": cert.get("subject", "NTLS Server Certificate"),
            "cert_fingerprint": cert.get("fingerprint", ""),
            "cert_expiry": cert.get("expiry", ""),
            "cert_type": cert.get("type", CERT_SELF_SIGNED),
            "cert_key_type": cert.get("key_type", "RSA-2048"),
            "cert_san": cert.get("san", ""),
            "ip_check": True,
            "threads": 8,
        }

    def renew_ntls_certificate(self, hostname: str = None,
                                 key_type: str = "RSA",
                                 key_size: int = 2048,
                                 curve: str = None,
                                 days: int = 365,
                                 country: str = "US",
                                 state: str = "",
                                 location: str = "",
                                 organization: str = "Thales",
                                 orgunit: str = "",
                                 email: str = "",
                                 san: str = "",
                                 csr: bool = False) -> dict:
        """Renew the NTLS server certificate and restart dependent services.

        On a real Luna 7, after regenerating the cert with sysconf regenCert,
        the NTLS service must be restarted for the new certificate to take
        effect. All existing client trust relationships are invalidated.
        """
        result = self.connections.regenerate_ntls_cert(
            hostname=hostname, key_type=key_type, key_size=key_size,
            curve=curve, days=days, country=country, state=state,
            location=location, organization=organization, orgunit=orgunit,
            email=email, san=san, csr=csr,
        )

        # Restart the NTLS service to pick up the new certificate
        services = self._get_services()
        if "ntls" in services:
            services["ntls"]["status"] = "running"
            self._save_services(services)

        result["service_restarted"] = True
        return result

    # ------------------------------------------------------------------
    # HSM Clients
    # ------------------------------------------------------------------

    def _get_clients(self) -> list:
        import json
        raw = self.storage.get_meta("appliance_clients")
        if raw:
            try:
                return [HSMClient.from_dict(d) for d in json.loads(raw)]
            except (json.JSONDecodeError, TypeError):
                pass
        return []

    def _save_clients(self, clients: list):
        import json
        self.storage.set_meta("appliance_clients",
                              json.dumps([c.to_dict() for c in clients]))

    def register_client(self, name: str, ip: str = "") -> dict:
        """Register a new HSM client."""
        clients = self._get_clients()
        if any(c.name == name for c in clients):
            return {"success": False, "error": f"Client '{name}' already registered"}
        next_id = max([c.client_id for c in clients], default=0) + 1
        client = HSMClient(next_id, name, ip)
        clients.append(client)
        self._save_clients(clients)
        return {"success": True, "client_id": next_id, "name": name}

    def delete_client(self, name: str) -> dict:
        """Delete a registered client."""
        clients = self._get_clients()
        client = next((c for c in clients if c.name == name), None)
        if client is None:
            return {"success": False, "error": f"Client '{name}' not found"}
        clients = [c for c in clients if c.name != name]
        self._save_clients(clients)
        return {"success": True}

    def list_clients(self) -> list:
        """List all registered clients."""
        clients = self._get_clients()
        return [{
            "client_id": c.client_id,
            "name": c.name,
            "ip": c.ip,
            "distinguished_name": c.distinguished_name,
            "assigned_partitions": c.assigned_partitions,
            "created": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(c.created_at)),
        } for c in clients]

    def show_client(self, name: str) -> Optional[dict]:
        """Show details of a specific client."""
        clients = self._get_clients()
        client = next((c for c in clients if c.name == name), None)
        if client is None:
            return None
        return {
            "client_id": client.client_id,
            "name": client.name,
            "ip": client.ip,
            "distinguished_name": client.distinguished_name,
            "assigned_partitions": client.assigned_partitions,
            "created": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(client.created_at)),
        }

    def assign_partition(self, client_name: str, slot_id: int) -> dict:
        """Assign a partition to a client."""
        clients = self._get_clients()
        client = next((c for c in clients if c.name == client_name), None)
        if client is None:
            return {"success": False, "error": f"Client '{client_name}' not found"}
        partition = self.storage.get_partition(slot_id)
        if partition is None:
            return {"success": False, "error": f"Partition slot {slot_id} not found"}
        if slot_id not in client.assigned_partitions:
            client.assigned_partitions.append(slot_id)
        self._save_clients(clients)
        return {"success": True, "client": client_name, "slot_id": slot_id}

    def revoke_partition(self, client_name: str, slot_id: int) -> dict:
        """Revoke a partition assignment from a client."""
        clients = self._get_clients()
        client = next((c for c in clients if c.name == client_name), None)
        if client is None:
            return {"success": False, "error": f"Client '{client_name}' not found"}
        if slot_id in client.assigned_partitions:
            client.assigned_partitions.remove(slot_id)
        self._save_clients(clients)
        return {"success": True}

    # ------------------------------------------------------------------
    # Services
    # ------------------------------------------------------------------

    def _get_services(self) -> dict:
        import json
        raw = self.storage.get_meta("appliance_services")
        if raw:
            try:
                return json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                pass
        return dict(DEFAULT_SERVICES)

    def _save_services(self, services: dict):
        import json
        self.storage.set_meta("appliance_services", json.dumps(services))

    def list_services(self) -> list:
        services = self._get_services()
        return [{"name": k, "status": v["status"], "description": v["description"]}
                for k, v in services.items()]

    def start_service(self, name: str) -> dict:
        services = self._get_services()
        if name not in services:
            return {"success": False, "error": f"Unknown service: {name}"}
        services[name]["status"] = "running"
        self._save_services(services)
        return {"success": True, "service": name, "status": "running"}

    def stop_service(self, name: str) -> dict:
        services = self._get_services()
        if name not in services:
            return {"success": False, "error": f"Unknown service: {name}"}
        services[name]["status"] = "stopped"
        self._save_services(services)
        return {"success": True, "service": name, "status": "stopped"}

    def restart_service(self, name: str) -> dict:
        services = self._get_services()
        if name not in services:
            return {"success": False, "error": f"Unknown service: {name}"}
        services[name]["status"] = "running"
        self._save_services(services)
        return {"success": True, "service": name, "status": "running"}

    def service_status(self, name: str) -> dict:
        services = self._get_services()
        if name not in services:
            return {"success": False, "error": f"Unknown service: {name}"}
        return {"name": name, "status": services[name]["status"],
                "description": services[name]["description"]}

    # ------------------------------------------------------------------
    # System configuration (sysconf)
    # ------------------------------------------------------------------

    def _get_sysconf(self) -> dict:
        import json
        raw = self.storage.get_meta("appliance_sysconf")
        if raw:
            try:
                return json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                pass
        return dict(DEFAULT_SYSCONF)

    def _save_sysconf(self, config: dict):
        import json
        self.storage.set_meta("appliance_sysconf", json.dumps(config))

    def get_sysconf(self) -> dict:
        return self._get_sysconf()

    def set_timezone(self, timezone: str) -> dict:
        config = self._get_sysconf()
        config["timezone"] = timezone
        self._save_sysconf(config)
        return {"success": True, "timezone": timezone}

    def set_banner(self, text: str) -> dict:
        config = self._get_sysconf()
        config["banner"] = text
        self._save_sysconf(config)
        return {"success": True}

    def clear_banner(self) -> dict:
        config = self._get_sysconf()
        config["banner"] = ""
        self._save_sysconf(config)
        return {"success": True}

    def force_so_login_enable(self) -> dict:
        config = self._get_sysconf()
        config["force_so_login"] = True
        self._save_sysconf(config)
        return {"success": True}

    def force_so_login_disable(self) -> dict:
        config = self._get_sysconf()
        config["force_so_login"] = False
        self._save_sysconf(config)
        return {"success": True}

    def set_ssh_port(self, port: int) -> dict:
        config = self._get_sysconf()
        config["ssh_port"] = port
        self._save_sysconf(config)
        return {"success": True, "port": port}

    def reboot(self) -> dict:
        """Simulate an appliance reboot."""
        self._boot_time = time.time()
        self._hsm_logged_in = False
        self._audit_logged_in = False
        return {"success": True, "message": "Appliance rebooted."}

    def poweroff(self) -> dict:
        """Simulate an appliance power off."""
        return {"success": True, "message": "Appliance powering off."}

    # ------------------------------------------------------------------
    # System status
    # ------------------------------------------------------------------

    def get_status(self) -> dict:
        """Return overall appliance status."""
        uptime = max(time.time() - self._boot_time, 0.001)
        services = self._get_services()
        running = sum(1 for s in services.values() if s["status"] == "running")
        return {
            "hostname": self.storage.get_meta("appliance_hostname") or "luna7-appliance",
            "uptime": uptime,
            "uptime_str": self._format_uptime(uptime),
            "current_user": self._current_user.username if self._current_user else None,
            "hsm_logged_in": self._hsm_logged_in,
            "audit_logged_in": self._audit_logged_in,
            "services_total": len(services),
            "services_running": running,
            "partitions": len(self.storage.get_all_partitions()),
            "clients": len(self._get_clients()),
            "users": len(self._get_users()),
        }

    def get_cpu_status(self) -> dict:
        return {"cpu_usage": "12%", "cores": 4, "load_avg": "0.12 0.08 0.05"}

    def get_mem_status(self) -> dict:
        return {"total": "8192 MB", "used": "2048 MB", "free": "6144 MB", "usage": "25%"}

    def get_disk_status(self) -> dict:
        return {"total": "120 GB", "used": "30 GB", "free": "90 GB", "usage": "25%"}

    def get_date(self) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S %Z", time.localtime())

    def _format_uptime(self, seconds: float) -> str:
        days = int(seconds // 86400)
        hours = int((seconds % 86400) // 3600)
        mins = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        parts = []
        if days: parts.append(f"{days}d")
        if hours: parts.append(f"{hours}h")
        if mins: parts.append(f"{mins}m")
        parts.append(f"{secs}s")
        return " ".join(parts)

    # ------------------------------------------------------------------
    # Syslog
    # ------------------------------------------------------------------

    def get_syslog_config(self) -> dict:
        import json
        raw = self.storage.get_meta("appliance_syslog_config")
        if raw:
            try:
                return json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                pass
        return {"severity": "info", "remote_hosts": [], "rotations": 10}

    def set_syslog_severity(self, severity: str) -> dict:
        if severity not in ("emerg", "alert", "crit", "err", "warning", "info", "debug"):
            return {"success": False, "error": "Invalid severity. Valid: emerg, alert, crit, err, warning, info, debug"}
        import json
        config = self.get_syslog_config()
        config["severity"] = severity
        self.storage.set_meta("appliance_syslog_config", json.dumps(config))
        return {"success": True, "severity": severity}

    def add_syslog_remote_host(self, host: str) -> dict:
        import json
        config = self.get_syslog_config()
        if host not in config["remote_hosts"]:
            config["remote_hosts"].append(host)
        self.storage.set_meta("appliance_syslog_config", json.dumps(config))
        return {"success": True}

    def delete_syslog_remote_host(self, host: str) -> dict:
        import json
        config = self.get_syslog_config()
        config["remote_hosts"] = [h for h in config["remote_hosts"] if h != host]
        self.storage.set_meta("appliance_syslog_config", json.dumps(config))
        return {"success": True}

    def rotate_syslog(self) -> dict:
        return {"success": True, "message": "System logs rotated."}

    # ------------------------------------------------------------------
    # My (current user's files and settings)
    # ------------------------------------------------------------------

    def get_my_info(self) -> dict:
        if self._current_user is None:
            return {"error": "Not logged in"}
        return {
            "username": self._current_user.username,
            "role": self._current_user.role,
            "enabled": self._current_user.enabled,
            "created": time.strftime("%Y-%m-%d %H:%M:%S",
                                     time.localtime(self._current_user.created_at)),
            "last_login": time.strftime("%Y-%m-%d %H:%M:%S",
                                        time.localtime(self._current_user.last_login)) if self._current_user.last_login else "Never",
        }

    def set_my_password(self, old_password: str, new_password: str) -> dict:
        if self._current_user is None:
            return {"success": False, "error": "Not logged in"}
        if not self._verify_password(old_password, self._current_user.password_hash,
                                     self._current_user.password_salt):
            return {"success": False, "error": "Old password incorrect"}
        ph, ps = self._hash_password(new_password)
        self._current_user.password_hash = ph
        self._current_user.password_salt = ps
        users = self._get_users()
        for u in users:
            if u.username == self._current_user.username:
                u.password_hash = ph
                u.password_salt = ps
        self._save_users(users)
        return {"success": True}

    # ------------------------------------------------------------------
    # Package management
    # ------------------------------------------------------------------

    def list_packages(self) -> list:
        return [
            {"name": "luna-firmware-7.13.0.pkg", "size": "45 MB", "type": "firmware"},
            {"name": "luna-client-10.1.0.pkg", "size": "120 MB", "type": "client"},
        ]

    def verify_package(self, filename: str) -> dict:
        return {"success": True, "filename": filename, "status": "Package signature verified."}
