"""LunaSH command handler — emulates the Luna Network HSM 7 appliance shell.

LunaSH is the server-side command shell that runs on the Luna Network HSM 7
appliance itself (as opposed to lunacm, which is the client-side PKCS#11
configuration manager). It is accessed via SSH.

This handler implements the major LunaSH command groups:
  - status: View system status (CPU, memory, disk, date, uptime)
  - hsm: Manage the HSM (login, show, init, firmware, policies, PED, STM)
  - partition: Manage partitions (create, delete, list, show, init, policies)
  - user: Manage appliance users (add, delete, list, enable, disable)
  - client: Manage HSM clients (register, delete, list, assign partitions)
  - network: View and configure network settings
  - ntls: Manage NTLS connections
  - sysconf: Configure the appliance (timezone, SSH, banner, reboot)
  - service: View and manage services
  - syslog: Manage system logs
  - my: Manage current user's files and passwords
  - package: Manage secure package updates
  - token backup: Access backup HSM commands
  - audit: Audit logging commands
"""

import getpass
import time

from hsm.appliance import (
    Appliance, ROLE_ADMIN, ROLE_OPERATOR, ROLE_MONITOR, ROLE_AUDIT, ALL_ROLES,
    ROLE_DESCRIPTIONS,
)
from pkcs11.constants import PKCS11Error


class LunaSHCommands:
    """Handles LunaSH commands for the appliance."""

    def __init__(self, appliance: Appliance, api=None):
        self.appliance = appliance
        self.api = api  # PKCS11API for HSM operations that overlap

    def _check_login(self) -> bool:
        if not self.appliance.is_logged_in():
            print("  Error: Not logged in. Use 'login' to authenticate.")
            return False
        return True

    def _check_role(self, *roles) -> bool:
        if not self._check_login():
            return False
        if not self.appliance._check_role(*roles):
            print(f"  Error: This command requires one of: {', '.join(roles)}")
            return False
        return True

    def _check_hsm_login(self) -> bool:
        if not self._check_login():
            return False
        if not self.appliance.is_hsm_logged_in():
            print("  Error: HSM SO not logged in. Use 'hsm login' first.")
            return False
        return True

    # ------------------------------------------------------------------
    # Login / Logout
    # ------------------------------------------------------------------

    def cmd_login(self, args: list):
        """Handle appliance login."""
        if self.appliance.is_logged_in():
            print(f"  Already logged in as: {self.appliance.get_current_user().username}")
            print("  Use 'logout' first to switch users.")
            return

        username = input("  Username: ") if not args else args[0]
        password = getpass.getpass("  Password: ")
        result = self.appliance.login(username, password)
        if result["success"]:
            user = result["user"]
            if result.get("first_login"):
                print(f"  First login for '{username}'. Password set.")
            print(f"  Logged in as: {user.username} ({user.role})")
            print(f"  Role: {ROLE_DESCRIPTIONS.get(user.role, 'Unknown')}")
        else:
            print(f"  Login failed: {result['error']}")

    def cmd_logout(self, args: list):
        """Handle appliance logout."""
        if not self.appliance.is_logged_in():
            print("  Not logged in.")
            return
        user = self.appliance.get_current_user()
        self.appliance.logout()
        print(f"  Logged out: {user.username}")

    # ------------------------------------------------------------------
    # status
    # ------------------------------------------------------------------

    def cmd_status(self, args: list):
        """Handle 'status' commands."""
        if not args:
            print("  Usage: status cpu | mem | disk | date | time | interface | ps | netstat | sensors")
            return
        if not self._check_role(ROLE_ADMIN, ROLE_OPERATOR, ROLE_MONITOR, ROLE_AUDIT):
            return
        sub = args[0]

        if sub == "cpu":
            cpu = self.appliance.get_cpu_status()
            print(f"  CPU Usage: {cpu['cpu_usage']}")
            print(f"  Cores:     {cpu['cores']}")
            print(f"  Load Avg:  {cpu['load_avg']}")

        elif sub == "mem":
            mem = self.appliance.get_mem_status()
            print(f"  Total: {mem['total']}  Used: {mem['used']}  Free: {mem['free']}  Usage: {mem['usage']}")

        elif sub == "disk":
            disk = self.appliance.get_disk_status()
            print(f"  Total: {disk['total']}  Used: {disk['used']}  Free: {disk['free']}  Usage: {disk['usage']}")

        elif sub in ("date", "time"):
            print(f"  {self.appliance.get_date()}")

        elif sub == "interface":
            net = self.appliance.get_network_info()
            for name, iface in net["interfaces"].items():
                print(f"  {name}:")
                print(f"    Method:   {iface['method']}")
                print(f"    IP:       {iface.get('ip', 'N/A')}")
                print(f"    Netmask:  {iface.get('netmask', 'N/A')}")
                print(f"    Gateway:  {iface.get('gateway', 'N/A')}")
                print(f"    MAC:      {iface['mac']}")
                print(f"    Status:   {iface['status']}")

        elif sub == "ps":
            services = self.appliance.list_services()
            print(f"  {'PID':<8} {'USER':<12} {'COMMAND':<30} {'STATUS'}")
            print("  " + "-" * 65)
            for s in services:
                print(f"  {s['client_id'] if hasattr(s, 'client_id') else '---':<8} {'root':<12} {s['name']:<30} {s['status']}" if 'client_id' in s else f"  {'---':<8} {'root':<12} {s['name']:<30} {s['status']}")

        elif sub == "netstat":
            net = self.appliance.get_ntls_info()
            print(f"  NTLS Connections: {net['connections']}")
            print(f"  Bound Interface:  {net['bound_interfaces']}")
            clients = self.appliance.list_clients()
            for c in clients:
                print(f"  {c['name']:<20} {c['ip'] or 'N/A':<20} Partitions: {c['assigned_partitions']}")

        elif sub == "sensors":
            print("  Temperature: 35C (Normal)")
            print("  Fan Speed:   2400 RPM (Normal)")
            print("  Power Supply: OK")
            print("  Tamper:       Not tripped")

        else:
            print(f"  Unknown status subcommand: {sub}")

    # ------------------------------------------------------------------
    # hsm
    # ------------------------------------------------------------------

    def cmd_hsm(self, args: list):
        """Handle 'hsm' commands."""
        if not args:
            print("  Usage: hsm login | logout | show | init | factoryReset | zeroize |")
            print("         firmware show | firmware upgrade | firmware rollback |")
            print("         showPolicies | changePolicy | stm show | stm recover |")
            print("         ped show | selfTest | time | information show")
            return
        if not self._check_login():
            return
        sub = args[0]
        rest = args[1:]

        if sub == "login":
            if self.appliance.is_hsm_logged_in():
                print("  HSM SO already logged in.")
                return
            print("  [PED Simulation] Enter HSM SO PIN:")
            pin = getpass.getpass("  SO PIN: ")
            result = self.appliance.hsm_login(pin)
            if result["success"]:
                print("  HSM SO logged in.")
            else:
                print(f"  HSM login failed: {result['error']}")

        elif sub == "logout":
            self.appliance.hsm_logout()
            print("  HSM SO logged out.")

        elif sub == "show":
            if self.api:
                info = self.api.tokens.get_hsm_info()
                print(f"  Model:            {info['model']}")
                print(f"  Firmware:         {info['firmware']}")
                print(f"  Serial:           {info['serial']}")
                print(f"  Partitions:       {info['partition_count']} / {info['max_partitions']}")
                print(f"  HSM Login:        {'Yes' if self.appliance.is_hsm_logged_in() else 'No'}")
            else:
                print("  HSM information not available (no API connected).")

        elif sub == "init":
            if not self._check_role(ROLE_ADMIN):
                return
            print("  [PED Simulation] Initialize the HSM — set SO PIN:")
            pin = getpass.getpass("  SO PIN: ")
            confirm = getpass.getpass("  Confirm SO PIN: ")
            if pin != confirm:
                print("  Error: PINs do not match.")
                return
            if self.api:
                partitions = self.api.storage.get_all_partitions()
                if partitions:
                    self.api.tokens.init_token(partitions[0]["slot_id"], pin)
                    print("  HSM initialized. SO PIN set.")
                else:
                    print("  No partitions to initialize.")
            else:
                print("  HSM init not available (no API connected).")

        elif sub == "factoryReset":
            if not self._check_role(ROLE_ADMIN):
                return
            confirm = input("  WARNING: Factory reset will erase ALL data. Type 'FACTORYRESET' to confirm: ")
            if confirm != "FACTORYRESET":
                print("  Cancelled.")
                return
            if self.api:
                self.api.tokens.factory_reset()
                self.appliance._hsm_logged_in = False
                print("  HSM factory reset complete. All partitions and keys erased.")
            else:
                print("  Factory reset not available (no API connected).")

        elif sub == "zeroize":
            if not self._check_role(ROLE_ADMIN):
                return
            confirm = input("  WARNING: Zeroize will permanently destroy ALL key material. Type 'ZEROIZE' to confirm: ")
            if confirm != "ZEROIZE":
                print("  Cancelled.")
                return
            if self.api:
                self.api.tokens.factory_reset()
                print("  HSM zeroized. All key material destroyed.")
            else:
                print("  Zeroize not available.")

        elif sub == "firmware":
            self._hsm_firmware(rest)

        elif sub in ("showPolicies", "showpolicies"):
            if self.api:
                partitions = self.api.storage.get_all_partitions()
                if partitions:
                    print(self.api.tokens.show_policies(partitions[0]["slot_id"], verbose=True))
                else:
                    print("  No partitions configured.")
            else:
                print("  HSM policies not available.")

        elif sub in ("changePolicy", "changepolicy"):
            if not self._check_hsm_login():
                return
            if self.api:
                partitions = self.api.storage.get_all_partitions()
                if not partitions:
                    print("  No partitions configured.")
                    return
                slot_id = partitions[0]["slot_id"]
                policy_name = self._get_arg(rest, "-policy")
                value = self._get_arg(rest, "-value")
                if not policy_name or value is None:
                    print("  Usage: hsm changePolicy -policy <id> -value <value>")
                    return
                try:
                    self.api.tokens.change_policy(slot_id, policy_name, value,
                                                    audit=self.api.audit, force=True)
                    print(f"  Policy '{policy_name}' set to '{value}'.")
                except PKCS11Error as e:
                    print(f"  Error: {e}")

        elif sub == "stm":
            self._hsm_stm(rest)

        elif sub == "ped":
            if not rest:
                print("  Usage: hsm ped show | hsm ped connect | hsm ped disconnect")
                return
            if rest[0] == "show":
                print("  PED Status: Connected (USB)")
                print("  PED Vector: Initialized")
                print("  PED Timeout: 60 seconds")
            elif rest[0] == "connect":
                print("  PED connected.")
            elif rest[0] == "disconnect":
                print("  PED disconnected.")
            else:
                print(f"  Unknown ped subcommand: {rest[0]}")

        elif sub == "selfTest":
            print("  Running HSM self-test...")
            time.sleep(0.5)
            print("  Self-test PASSED. All cryptographic operations functional.")

        elif sub == "time":
            print(f"  HSM Time: {self.appliance.get_date()}")

        elif sub == "information":
            if not rest or rest[0] == "show":
                print("  HSM Information:")
                print("    FIPS Mode:       Level 3")
                print("    Cloning Mode:   Enabled")
                print("    Tamper:         Not tripped")
                print("    Firmware:       7.13.0")
                print("    Partitions:     V1 (new cloning protocol)")
            else:
                print(f"  Unknown information subcommand: {rest[0]}")

        else:
            print(f"  Unknown hsm subcommand: {sub}")

    def _hsm_firmware(self, args: list):
        if not args:
            print("  Usage: hsm firmware show | upgrade | rollback")
            return
        sub = args[0]
        if sub == "show":
            if self.api:
                info = self.api.tokens.get_firmware_info()
                print(f"  Current Firmware:  {info['current_version']}")
                print(f"  Latest Firmware:   {info['latest_version']}")
                print(f"  Update Available:  {'Yes' if info['update_available'] else 'No'}")
                print(f"  Available Versions: {info['available_count']}")
        elif sub == "upgrade":
            target = self._get_arg(args, "-version")
            if not target:
                print("  Usage: hsm firmware upgrade -version <version>")
                return
            if not self._check_hsm_login():
                return
            try:
                if self.api:
                    result = self.api.tokens.upgrade_firmware(
                        target, audit=self.api.audit, session_id=0
                    )
                    print(f"  Firmware upgraded: {result['previous_version']} -> {result['new_version']}")
            except PKCS11Error as e:
                print(f"  Error: {e}")
        elif sub == "rollback":
            if not self._check_hsm_login():
                return
            try:
                if self.api:
                    result = self.api.tokens.rollback_firmware(
                        audit=self.api.audit, session_id=0
                    )
                    print(f"  Firmware rolled back: {result['previous_version']} -> {result['new_version']}")
            except PKCS11Error as e:
                print(f"  Error: {e}")
        else:
            print(f"  Unknown firmware subcommand: {sub}")

    def _hsm_stm(self, args: list):
        if not args:
            print("  Usage: hsm stm show | hsm stm recover -string <s> | hsm stm transport")
            return
        sub = args[0]
        if sub == "show":
            print("  Secure Transport Mode (STM): Not active")
            print("  HSM has been initialized and is operational.")
        elif sub == "recover":
            rus = self._get_arg(args, "-string")
            if not rus:
                print("  Usage: hsm stm recover -string <random_user_string>")
                return
            print("  STM recovered. HSM is now in initialized state.")
        elif sub == "transport":
            print("  HSM placed in Secure Transport Mode. Reboot required.")
        else:
            print(f"  Unknown stm subcommand: {sub}")

    # ------------------------------------------------------------------
    # partition
    # ------------------------------------------------------------------

    def cmd_partition(self, args: list):
        """Handle 'partition' commands (LunaSH variant)."""
        if not args:
            print("  Usage: partition create | delete | list | show | init | changePolicy |")
            print("         showPolicies | clear | activate | deactivate | resize | rename")
            return
        if not self._check_login():
            return
        sub = args[0]
        rest = args[1:]

        if sub == "list":
            if self.api:
                print(self.api.tokens.list_partitions())
            else:
                print("  Partition list not available.")

        elif sub == "create":
            if not self._check_role(ROLE_ADMIN, ROLE_OPERATOR):
                return
            if not self._check_hsm_login():
                return
            name = self._get_arg(rest, "-name") or input("  Partition name: ")
            label = self._get_arg(rest, "-label") or name
            if not name:
                print("  Usage: partition create -name <name> [-label <label>]")
                return
            try:
                if self.api:
                    slot_id = self.api.tokens.create_partition(name, label)
                    print(f"  Partition '{name}' created. Slot ID: {slot_id}")
            except PKCS11Error as e:
                print(f"  Error: {e}")

        elif sub == "delete":
            if not self._check_role(ROLE_ADMIN, ROLE_OPERATOR):
                return
            if not self._check_hsm_login():
                return
            name = self._get_arg(rest, "-name")
            if not name:
                print("  Usage: partition delete -name <name>")
                return
            confirm = input(f"  Delete partition '{name}'? (yes/no): ")
            if confirm.lower() != "yes":
                print("  Cancelled.")
                return
            try:
                if self.api:
                    self.api.tokens.delete_partition(name)
                    print(f"  Partition '{name}' deleted.")
            except PKCS11Error as e:
                print(f"  Error: {e}")

        elif sub == "show":
            name = self._get_arg(rest, "-name")
            if self.api:
                partitions = self.api.storage.get_all_partitions()
                if name:
                    p = self.api.storage.get_partition_by_name(name)
                    if p:
                        print(self.api.tokens.show_partition_info(p["slot_id"]))
                    else:
                        print(f"  Partition '{name}' not found.")
                elif partitions:
                    print(self.api.tokens.show_partition_info(partitions[0]["slot_id"]))
                else:
                    print("  No partitions configured.")

        elif sub == "init":
            if not self._check_role(ROLE_ADMIN, ROLE_OPERATOR):
                return
            if not self._check_hsm_login():
                return
            name = self._get_arg(rest, "-name")
            if not name:
                print("  Usage: partition init -name <name>")
                return
            if self.api:
                p = self.api.storage.get_partition_by_name(name)
                if not p:
                    print(f"  Partition '{name}' not found.")
                    return
                print("  [PED Simulation] Set SO PIN for partition:")
                pin = getpass.getpass("  SO PIN: ")
                confirm = getpass.getpass("  Confirm SO PIN: ")
                if pin != confirm:
                    print("  Error: PINs do not match.")
                    return
                self.api.tokens.init_token(p["slot_id"], pin)
                print(f"  Partition '{name}' initialized. SO PIN set.")

        elif sub in ("showPolicies", "showpolicies"):
            if self.api:
                partitions = self.api.storage.get_all_partitions()
                if partitions:
                    verbose = "-verbose" in rest
                    print(self.api.tokens.show_policies(partitions[0]["slot_id"], verbose=verbose))
                else:
                    print("  No partitions configured.")

        elif sub in ("changePolicy", "changepolicy"):
            if not self._check_hsm_login():
                return
            if self.api:
                partitions = self.api.storage.get_all_partitions()
                if not partitions:
                    print("  No partitions configured.")
                    return
                slot_id = partitions[0]["slot_id"]
                policy_name = self._get_arg(rest, "-policy")
                value = self._get_arg(rest, "-value")
                if not policy_name or value is None:
                    print("  Usage: partition changePolicy -policy <id> -value <value>")
                    return
                try:
                    self.api.tokens.change_policy(slot_id, policy_name, value,
                                                    audit=self.api.audit, force=True)
                    print(f"  Policy '{policy_name}' set to '{value}'.")
                except PKCS11Error as e:
                    print(f"  Error: {e}")

        elif sub == "clear":
            if not self._check_hsm_login():
                return
            name = self._get_arg(rest, "-name")
            if not name:
                print("  Usage: partition clear -name <name>")
                return
            confirm = input(f"  Clear ALL objects on partition '{name}'? (yes/no): ")
            if confirm.lower() != "yes":
                print("  Cancelled.")
                return
            if self.api:
                p = self.api.storage.get_partition_by_name(name)
                if p:
                    objs = self.api.storage.get_all_objects(p["slot_id"])
                    for obj, _ in objs:
                        self.api.storage.delete_object(obj.handle)
                    print(f"  Partition '{name}' cleared. {len(objs)} objects deleted.")
                else:
                    print(f"  Partition '{name}' not found.")

        elif sub == "activate":
            name = self._get_arg(rest, "-name")
            print(f"  Partition '{name}' activated.")

        elif sub == "deactivate":
            name = self._get_arg(rest, "-name")
            print(f"  Partition '{name}' deactivated.")

        elif sub == "rename":
            name = self._get_arg(rest, "-name")
            new_name = self._get_arg(rest, "-newname")
            if not name or not new_name:
                print("  Usage: partition rename -name <old> -newname <new>")
                return
            print(f"  Partition '{name}' renamed to '{new_name}'.")

        elif sub == "resize":
            name = self._get_arg(rest, "-name")
            size = self._get_arg(rest, "-size")
            if not name or not size:
                print("  Usage: partition resize -name <name> -size <bytes>")
                return
            print(f"  Partition '{name}' resized to {size} bytes.")

        else:
            print(f"  Unknown partition subcommand: {sub}")

    # ------------------------------------------------------------------
    # user
    # ------------------------------------------------------------------

    def cmd_user(self, args: list):
        """Handle 'user' commands."""
        if not args:
            print("  Usage: user list | add | delete | enable | disable | password")
            return
        if not self._check_login():
            return
        sub = args[0]
        rest = args[1:]

        if sub == "list":
            if not self._check_role(ROLE_ADMIN, ROLE_OPERATOR, ROLE_MONITOR):
                return
            users = self.appliance.list_users()
            print(f"  {'Username':<20} {'Role':<12} {'Enabled':<10} {'Created':<22} {'Last Login'}")
            print("  " + "-" * 90)
            for u in users:
                print(f"  {u['username']:<20} {u['role']:<12} {'Yes' if u['enabled'] else 'No':<10} {u['created']:<22} {u['last_login']}")

        elif sub == "add":
            if not self._check_role(ROLE_ADMIN):
                return
            username = self._get_arg(rest, "-name")
            role = self._get_arg(rest, "-role")
            if not username or not role:
                print("  Usage: user add -name <username> -role <admin|operator|monitor|audit>")
                return
            password = getpass.getpass("  Initial password: ")
            result = self.appliance.add_user(username, role, password)
            if result["success"]:
                print(f"  User '{username}' added with role '{role}'.")
            else:
                print(f"  Error: {result['error']}")

        elif sub == "delete":
            if not self._check_role(ROLE_ADMIN):
                return
            username = self._get_arg(rest, "-name")
            if not username:
                print("  Usage: user delete -name <username>")
                return
            confirm = input(f"  Delete user '{username}'? (yes/no): ")
            if confirm.lower() != "yes":
                print("  Cancelled.")
                return
            result = self.appliance.delete_user(username)
            if result["success"]:
                print(f"  User '{username}' deleted.")
            else:
                print(f"  Error: {result['error']}")

        elif sub == "enable":
            if not self._check_role(ROLE_ADMIN):
                return
            username = self._get_arg(rest, "-name")
            if not username:
                print("  Usage: user enable -name <username>")
                return
            result = self.appliance.enable_user(username)
            if result["success"]:
                print(f"  User '{username}' enabled.")
            else:
                print(f"  Error: {result['error']}")

        elif sub == "disable":
            if not self._check_role(ROLE_ADMIN):
                return
            username = self._get_arg(rest, "-name")
            if not username:
                print("  Usage: user disable -name <username>")
                return
            result = self.appliance.disable_user(username)
            if result["success"]:
                print(f"  User '{username}' disabled.")
            else:
                print(f"  Error: {result['error']}")

        elif sub == "password":
            username = self._get_arg(rest, "-name")
            if not username:
                print("  Usage: user password -name <username>")
                return
            new_pw = getpass.getpass("  New password: ")
            confirm = getpass.getpass("  Confirm: ")
            if new_pw != confirm:
                print("  Error: Passwords do not match.")
                return
            result = self.appliance.set_user_password(username, new_pw)
            if result["success"]:
                print(f"  Password set for '{username}'.")
            else:
                print(f"  Error: {result['error']}")

        else:
            print(f"  Unknown user subcommand: {sub}")

    # ------------------------------------------------------------------
    # client
    # ------------------------------------------------------------------

    def cmd_client(self, args: list):
        """Handle 'client' commands."""
        if not args:
            print("  Usage: client list | register | delete | show | assignPartition | revokePartition")
            return
        if not self._check_login():
            return
        sub = args[0]
        rest = args[1:]

        if sub == "list":
            if not self._check_role(ROLE_ADMIN, ROLE_OPERATOR, ROLE_MONITOR):
                return
            clients = self.appliance.list_clients()
            if not clients:
                print("  No clients registered.")
                return
            print(f"  {'ID':<5} {'Name':<25} {'IP':<20} {'Partitions':<15} {'Created'}")
            print("  " + "-" * 90)
            for c in clients:
                print(f"  {c['client_id']:<5} {c['name']:<25} {c['ip'] or 'N/A':<20} {str(c['assigned_partitions']):<15} {c['created']}")

        elif sub == "register":
            if not self._check_role(ROLE_ADMIN, ROLE_OPERATOR):
                return
            name = self._get_arg(rest, "-name")
            ip = self._get_arg(rest, "-ip") or ""
            if not name:
                print("  Usage: client register -name <name> [-ip <ip>]")
                return
            result = self.appliance.register_client(name, ip)
            if result["success"]:
                print(f"  Client '{name}' registered. ID: {result['client_id']}")
            else:
                print(f"  Error: {result['error']}")

        elif sub == "delete":
            if not self._check_role(ROLE_ADMIN, ROLE_OPERATOR):
                return
            name = self._get_arg(rest, "-name")
            if not name:
                print("  Usage: client delete -name <name>")
                return
            result = self.appliance.delete_client(name)
            if result["success"]:
                print(f"  Client '{name}' deleted.")
            else:
                print(f"  Error: {result['error']}")

        elif sub == "show":
            name = self._get_arg(rest, "-name")
            if not name:
                print("  Usage: client show -name <name>")
                return
            client = self.appliance.show_client(name)
            if client is None:
                print(f"  Client '{name}' not found.")
                return
            print(f"  ID:              {client['client_id']}")
            print(f"  Name:            {client['name']}")
            print(f"  IP:              {client['ip'] or 'N/A'}")
            print(f"  Distinguished Name: {client['distinguished_name'] or 'N/A'}")
            print(f"  Assigned Partitions: {client['assigned_partitions']}")
            print(f"  Created:         {client['created']}")

        elif sub == "assignPartition":
            if not self._check_role(ROLE_ADMIN, ROLE_OPERATOR):
                return
            name = self._get_arg(rest, "-name")
            slot = self._get_arg(rest, "-partition")
            if not name or not slot:
                print("  Usage: client assignPartition -name <client> -partition <slot_id>")
                return
            result = self.appliance.assign_partition(name, int(slot))
            if result["success"]:
                print(f"  Partition {slot} assigned to client '{name}'.")
            else:
                print(f"  Error: {result['error']}")

        elif sub == "revokePartition":
            if not self._check_role(ROLE_ADMIN, ROLE_OPERATOR):
                return
            name = self._get_arg(rest, "-name")
            slot = self._get_arg(rest, "-partition")
            if not name or not slot:
                print("  Usage: client revokePartition -name <client> -partition <slot_id>")
                return
            result = self.appliance.revoke_partition(name, int(slot))
            if result["success"]:
                print(f"  Partition {slot} revoked from client '{name}'.")
            else:
                print(f"  Error: {result['error']}")

        else:
            print(f"  Unknown client subcommand: {sub}")

    # ------------------------------------------------------------------
    # network
    # ------------------------------------------------------------------

    def cmd_network(self, args: list):
        """Handle 'network' commands."""
        if not args:
            print("  Usage: network show | hostname | interface | dns | route | ping")
            return
        if not self._check_login():
            return
        sub = args[0]
        rest = args[1:]

        if sub == "show":
            if not self._check_role(ROLE_ADMIN, ROLE_OPERATOR, ROLE_MONITOR):
                return
            net = self.appliance.get_network_info()
            print(f"  Hostname:    {net['hostname']}")
            print(f"  Domain:      {net.get('domain', 'N/A')}")
            print(f"  DNS Servers: {', '.join(net['dns_nameservers'])}")
            print(f"  Search Domains: {', '.join(net.get('dns_searchdomains', []))}")
            print()
            for name, iface in net["interfaces"].items():
                print(f"  Interface {name}:")
                print(f"    Method:   {iface['method']}")
                print(f"    IP:       {iface.get('ip', 'N/A')}")
                print(f"    Netmask:  {iface.get('netmask', 'N/A')}")
                print(f"    Gateway:  {iface.get('gateway', 'N/A')}")
                print(f"    MAC:      {iface['mac']}")
                print(f"    Status:   {iface['status']}")
                print()
            print("  Routes:")
            for r in net["routes"]:
                print(f"    {r['destination']:<20} via {r['gateway']:<20} on {r['interface']}")

        elif sub == "hostname":
            if not self._check_role(ROLE_ADMIN):
                return
            hostname = rest[0] if rest else None
            if not hostname:
                print("  Usage: network hostname <hostname>")
                return
            result = self.appliance.set_hostname(hostname)
            print(f"  Hostname set to: {result['hostname']}")

        elif sub == "interface":
            if not rest:
                print("  Usage: network interface static|dhcp <interface> [-ip <ip> -netmask <mask> -gateway <gw>]")
                return
            mode = rest[0]
            iface = rest[1] if len(rest) > 1 else "eth0"
            if mode == "static":
                ip = self._get_arg(rest, "-ip")
                netmask = self._get_arg(rest, "-netmask")
                gateway = self._get_arg(rest, "-gateway") or ""
                if not ip or not netmask:
                    print("  Usage: network interface static <iface> -ip <ip> -netmask <mask> [-gateway <gw>]")
                    return
                if not self._check_role(ROLE_ADMIN):
                    return
                result = self.appliance.set_interface_static(iface, ip, netmask, gateway)
                print(f"  Interface {iface} configured: {ip}/{netmask}")
            elif mode == "dhcp":
                if not self._check_role(ROLE_ADMIN):
                    return
                result = self.appliance.set_interface_dhcp(iface)
                print(f"  Interface {iface} set to DHCP.")
            else:
                print(f"  Unknown interface mode: {mode}")

        elif sub == "dns":
            if not rest:
                print("  Usage: network dns add|delete nameserver <ip> | network dns add|delete searchdomain <domain>")
                return
            action = rest[0]
            if action in ("add", "delete"):
                if len(rest) < 3:
                    print(f"  Usage: network dns {action} nameserver|searchdomain <value>")
                    return
                dtype = rest[1]
                value = rest[2]
                if not self._check_role(ROLE_ADMIN):
                    return
                if dtype == "nameserver":
                    if action == "add":
                        self.appliance.add_dns_nameserver(value)
                        print(f"  DNS nameserver added: {value}")
                    else:
                        self.appliance.delete_dns_nameserver(value)
                        print(f"  DNS nameserver deleted: {value}")
                else:
                    print(f"  Unknown dns type: {dtype}")

        elif sub == "route":
            if not rest:
                print("  Usage: network route add|delete|show")
                return
            action = rest[0]
            if action == "show":
                routes = self.appliance.show_routes()
                for r in routes:
                    print(f"  {r['destination']:<20} via {r['gateway']:<20} on {r['interface']}")
            elif action == "add":
                if not self._check_role(ROLE_ADMIN):
                    return
                dest = self._get_arg(rest, "-destination")
                gw = self._get_arg(rest, "-gateway")
                iface = self._get_arg(rest, "-interface") or "eth0"
                if not dest or not gw:
                    print("  Usage: network route add -destination <dest> -gateway <gw> [-interface <iface>]")
                    return
                self.appliance.add_route(dest, gw, iface)
                print(f"  Route added: {dest} via {gw}")
            elif action == "delete":
                if not self._check_role(ROLE_ADMIN):
                    return
                dest = self._get_arg(rest, "-destination")
                if not dest:
                    print("  Usage: network route delete -destination <dest>")
                    return
                self.appliance.delete_route(dest)
                print(f"  Route deleted: {dest}")

        elif sub == "ping":
            if not self._check_role(ROLE_ADMIN, ROLE_OPERATOR, ROLE_MONITOR):
                return
            host = rest[0] if rest else None
            if not host:
                print("  Usage: network ping <host>")
                return
            result = self.appliance.ping(host)
            print(f"  {result['result']}")

        else:
            print(f"  Unknown network subcommand: {sub}")

    # ------------------------------------------------------------------
    # ntls
    # ------------------------------------------------------------------

    def cmd_ntls(self, args: list):
        """Handle 'ntls' commands — full NTLS connection management."""
        if not args:
            print("  Usage: ntls show | certificate show | certificate regenerate |")
            print("         connection list | connection create | connection delete |")
            print("         connection connect | connection disconnect | connection restore |")
            print("         ipcheck enable|disable|show | threads set|show |")
            print("         timer set|show | tcp_keepalive set|show")
            return
        if not self._check_login():
            return
        sub = args[0]
        rest = args[1:]

        if sub == "show":
            if not self._check_role(ROLE_ADMIN, ROLE_OPERATOR, ROLE_MONITOR):
                return
            info = self.appliance.get_ntls_info()
            summary = self.appliance.connections.get_connection_summary()
            print(f"  NTLS Status:       {info['status']}")
            print(f"  Bound Interfaces:  {info['bound_interfaces']}")
            print(f"  Total Connections: {info['connections']}")
            print(f"  Connected:         {info['connected']}")
            print(f"  Assigned (pending): {summary['ntls_assigned']}")
            print(f"  Certificate:       {info['certificate']}")
            print(f"  Cert Fingerprint:  {info['cert_fingerprint']}")
            print(f"  Cert Type:         {info['cert_type']}")
            print(f"  Cert Expiry:       {info['cert_expiry']}")
            print(f"  IP Check:          {'Enabled' if info['ip_check'] else 'Disabled'}")
            print(f"  Threads:           {info['threads']}")
            self._print_explain([
                "NTLS (Network Trust Link Service) is the high-performance",
                "connection type for traditional data center environments.",
                "Clients are identified by IP address and authenticated via",
                "certificates (self-signed or CA-signed).",
            ])

        elif sub == "certificate":
            if not rest:
                print("  Usage: ntls certificate show | regenerate")
                return
            if rest[0] == "show":
                cert = self.appliance.connections.get_ntls_server_cert()
                print(f"  NTLS Server Certificate:")
                print(f"    Subject:     {cert.get('subject', 'N/A')}")
                print(f"    Issuer:      {cert.get('issuer', 'N/A')}")
                print(f"    Serial:      {cert.get('serial', 'N/A')}")
                print(f"    Fingerprint: {cert.get('fingerprint', 'N/A')}")
                print(f"    Type:        {cert.get('type', 'N/A')}")
                print(f"    Expiry:      {cert.get('expiry', 'N/A')}")
                print(f"    Key Type:    {cert.get('key_type', 'N/A')}")
            elif rest[0] == "regenerate":
                if not self._check_role(ROLE_ADMIN):
                    return
                cert = self.appliance.connections.regenerate_ntls_cert()
                print(f"  NTLS certificate regenerated.")
                print(f"    New Fingerprint: {cert.get('fingerprint', 'N/A')}")
                self._print_explain([
                    "Regenerating the NTLS server certificate creates a new",
                    "self-signed certificate. All existing NTLS connections",
                    "must be re-established with the new certificate.",
                ])
            else:
                print(f"  Unknown certificate subcommand: {rest[0]}")

        elif sub == "connection":
            self._ntls_connection(rest)

        elif sub == "ipcheck":
            if not rest:
                print("  Usage: ntls ipcheck enable|disable|show")
                return
            if rest[0] == "show":
                print("  IP Check: Enabled")
            elif rest[0] == "enable":
                if not self._check_role(ROLE_ADMIN):
                    return
                print("  IP Check enabled.")
            elif rest[0] == "disable":
                if not self._check_role(ROLE_ADMIN):
                    return
                print("  IP Check disabled.")

        elif sub == "threads":
            if not rest:
                print("  Usage: ntls threads set <n> | show")
                return
            if rest[0] == "show":
                print(f"  NTLS Threads: 8")
            elif rest[0] == "set":
                if not self._check_role(ROLE_ADMIN):
                    return
                n = rest[1] if len(rest) > 1 else None
                if not n:
                    print("  Usage: ntls threads set <n>")
                    return
                print(f"  NTLS threads set to: {n}")

        elif sub == "timer":
            if not rest:
                print("  Usage: ntls timer set <seconds> | show")
                return
            if rest[0] == "show":
                print("  NTLS Timer: 30 seconds")
            elif rest[0] == "set":
                if not self._check_role(ROLE_ADMIN):
                    return
                print(f"  NTLS timer set to: {rest[1]}")

        elif sub == "tcp_keepalive":
            if not rest:
                print("  Usage: ntls tcp_keepalive set <seconds> | show")
                return
            if rest[0] == "show":
                print("  TCP Keepalive: 60 seconds")
            elif rest[0] == "set":
                if not self._check_role(ROLE_ADMIN):
                    return
                print(f"  TCP Keepalive set to: {rest[1]}")

        else:
            print(f"  Unknown ntls subcommand: {sub}")

    def _ntls_connection(self, args: list):
        """Handle 'ntls connection' subcommands."""
        if not args:
            print("  Usage: ntls connection list | create | delete | connect | disconnect | restore | show")
            return
        sub = args[0]
        rest = args[1:]

        if sub == "list":
            if not self._check_role(ROLE_ADMIN, ROLE_OPERATOR, ROLE_MONITOR):
                return
            conns = self.appliance.connections.list_ntls_connections()
            if not conns:
                print("  No NTLS connections.")
                return
            print(f"  {'Client':<25} {'Slot':<6} {'State':<15} {'Cert Type':<15} {'Created'}")
            print("  " + "-" * 90)
            for c in conns:
                print(f"  {c['client_name']:<25} {c['slot_id']:<6} {c['state']:<15} {c['cert_type']:<15} {time.strftime('%Y-%m-%d %H:%M', time.localtime(c['created_at']))}")

        elif sub == "create":
            if not self._check_role(ROLE_ADMIN, ROLE_OPERATOR):
                return
            client = self._get_arg(rest, "-client")
            slot = self._get_arg(rest, "-slot")
            cert_type = self._get_arg(rest, "-cert") or "self-signed"
            if not client or not slot:
                print("  Usage: ntls connection create -client <name> -slot <id> [-cert self-signed|ca-signed]")
                return
            result = self.appliance.connections.create_ntls_connection(
                client, int(slot), cert_type=cert_type
            )
            if result["success"]:
                print(f"  NTLS connection created: client='{client}', slot={slot}")
                print(f"  Certificate type: {cert_type}")
                print(f"  Certificate fingerprint: {result.get('cert_fingerprint', 'N/A')}")
                self._print_explain([
                    "Creating an NTLS connection simulates the process of:",
                    "1. Client generates a certificate (self-signed or CA-signed)",
                    "2. Client certificate is registered on the appliance",
                    "3. Partition is assigned to the client",
                    "",
                    "The connection is in 'assigned' state — use 'ntls connection connect'",
                    "to simulate establishing the trust link.",
                ])
            else:
                print(f"  Error: {result['error']}")

        elif sub == "delete":
            if not self._check_role(ROLE_ADMIN, ROLE_OPERATOR):
                return
            client = self._get_arg(rest, "-client")
            slot = self._get_arg(rest, "-slot")
            if not client or not slot:
                print("  Usage: ntls connection delete -client <name> -slot <id>")
                return
            result = self.appliance.connections.delete_ntls_connection(client, int(slot))
            if result["success"]:
                print(f"  NTLS connection deleted: client='{client}', slot={slot}")
            else:
                print(f"  Error: {result['error']}")

        elif sub == "connect":
            if not self._check_role(ROLE_ADMIN, ROLE_OPERATOR):
                return
            client = self._get_arg(rest, "-client")
            slot = self._get_arg(rest, "-slot")
            if not client or not slot:
                print("  Usage: ntls connection connect -client <name> -slot <id>")
                return
            result = self.appliance.connections.connect_ntls(client, int(slot))
            if result["success"]:
                print(f"  NTLS connection established: client='{client}', slot={slot}")
                self._print_explain([
                    "The NTLS trust link is now active. The client can perform",
                    "cryptographic operations on the assigned partition.",
                ])
            else:
                print(f"  Error: {result['error']}")

        elif sub == "disconnect":
            if not self._check_role(ROLE_ADMIN, ROLE_OPERATOR):
                return
            client = self._get_arg(rest, "-client")
            slot = self._get_arg(rest, "-slot")
            if not client or not slot:
                print("  Usage: ntls connection disconnect -client <name> -slot <id>")
                return
            result = self.appliance.connections.disconnect_ntls(client, int(slot))
            if result["success"]:
                print(f"  NTLS connection disconnected: client='{client}', slot={slot}")
            else:
                print(f"  Error: {result['error']}")

        elif sub == "restore":
            if not self._check_role(ROLE_ADMIN, ROLE_OPERATOR):
                return
            client = self._get_arg(rest, "-client")
            slot = self._get_arg(rest, "-slot")
            if not client or not slot:
                print("  Usage: ntls connection restore -client <name> -slot <id>")
                return
            result = self.appliance.connections.restore_ntls_connection(client, int(slot))
            if result["success"]:
                print(f"  {result['message']}")
                self._print_explain([
                    "Restoring a broken NTLS connection resets it to the",
                    "'assigned' state. Use 'ntls connection connect' to",
                    "re-establish the trust link.",
                ])
            else:
                print(f"  Error: {result['error']}")

        elif sub == "show":
            if not self._check_role(ROLE_ADMIN, ROLE_OPERATOR, ROLE_MONITOR):
                return
            client = self._get_arg(rest, "-client")
            slot = self._get_arg(rest, "-slot")
            if not client or not slot:
                print("  Usage: ntls connection show -client <name> -slot <id>")
                return
            conn = self.appliance.connections.get_ntls_connection(client, int(slot))
            if conn is None:
                print(f"  NTLS connection not found.")
                return
            print(f"  Client:          {conn['client_name']}")
            print(f"  Slot:             {conn['slot_id']}")
            print(f"  State:            {conn['state']}")
            print(f"  Cert Type:        {conn['cert_type']}")
            print(f"  Cert Subject:     {conn['cert_subject']}")
            print(f"  Cert Issuer:      {conn['cert_issuer']}")
            print(f"  Cert Serial:      {conn['cert_serial']}")
            print(f"  Cert Fingerprint: {conn['cert_fingerprint']}")
            print(f"  Cert Expiry:      {conn['cert_expiry']}")
            print(f"  Created:          {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(conn['created_at']))}")
            if conn['connected_at']:
                print(f"  Connected:        {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(conn['connected_at']))}")

        else:
            print(f"  Unknown connection subcommand: {sub}")

    # ------------------------------------------------------------------
    # STC (Secure Trusted Channel)
    # ------------------------------------------------------------------

    def cmd_stc(self, args: list):
        """Handle 'stc' commands — full STC connection management."""
        if not args:
            print("  Usage: stc enable | disable | show | status |")
            print("         identity create | identity delete | identity list | identity show | identity export |")
            print("         connection create | connection delete | connection list |")
            print("         connection connect | connection disconnect | connection restore |")
            print("         cipher show | cipher enable <name> | cipher disable <name> |")
            print("         hmac show | hmac enable | hmac disable |")
            print("         rekeyThreshold set <n> | rekeyThreshold show |")
            print("         activationTimeOut set <n> | activationTimeOut show |")
            print("         convert -client <name> -slot <id> |")
            print("         admin show")
            return
        if not self._check_login():
            return
        sub = args[0]
        rest = args[1:]

        if sub == "show":
            if not self._check_role(ROLE_ADMIN, ROLE_OPERATOR, ROLE_MONITOR):
                return
            config = self.appliance.connections.get_stc_config()
            summary = self.appliance.connections.get_connection_summary()
            print(f"  STC Enabled:        {'Yes' if config.get('enabled') else 'No'}")
            print(f"  Cipher:             {config.get('cipher', 'AES-256-GCM')}")
            print(f"  HMAC:               {config.get('hmac', 'HMAC-SHA256')}")
            print(f"  HMAC Enabled:       {'Yes' if config.get('hmac_enabled', True) else 'No'}")
            print(f"  Rekey Threshold:    {config.get('rekey_threshold', 1000000)}")
            print(f"  Activation Timeout: {config.get('activation_timeout', 300)}s")
            print(f"  Identities:         {summary['stc_identities']}")
            print(f"  Connections:        {summary['stc_total']}")
            print(f"  Connected:          {summary['stc_connected']}")
            self._print_explain([
                "STC (Secure Trusted Channel) provides higher-assurance",
                "session protection beyond TLS. All data is encrypted with",
                "symmetric encryption, and message authentication codes",
                "prevent tampering. STC is preferred for cloud and virtual",
                "environments where VMs are frequently cloned or moved.",
            ])

        elif sub == "status":
            if not self._check_role(ROLE_ADMIN, ROLE_OPERATOR, ROLE_MONITOR):
                return
            status = self.appliance.connections.get_stc_admin_status()
            print(f"  STC Admin Channel:")
            print(f"    Enabled:          {'Yes' if status['enabled'] else 'No'}")
            print(f"    Cipher:           {status['cipher']}")
            print(f"    HMAC:             {status['hmac']}")
            print(f"    HMAC Enabled:     {'Yes' if status['hmac_enabled'] else 'No'}")
            print(f"    Rekey Threshold:  {status['rekey_threshold']}")
            print(f"    Activation Timeout: {status['activation_timeout']}s")
            print(f"    Identities:       {status['identities']}")
            print(f"    Connections:      {status['connections']}")

        elif sub == "enable":
            if not self._check_role(ROLE_ADMIN):
                return
            result = self.appliance.connections.enable_stc()
            print(f"  STC enabled.")
            # Also start the stc service
            self.appliance.start_service("stc")

        elif sub == "disable":
            if not self._check_role(ROLE_ADMIN):
                return
            result = self.appliance.connections.disable_stc()
            print(f"  STC disabled.")
            self.appliance.stop_service("stc")

        elif sub == "identity":
            self._stc_identity(rest)

        elif sub == "connection":
            self._stc_connection(rest)

        elif sub == "cipher":
            if not rest:
                print("  Usage: stc cipher show | enable <name> | disable <name>")
                return
            if rest[0] == "show":
                from hsm.connections import STC_CIPHERS
                config = self.appliance.connections.get_stc_config()
                print(f"  Current cipher: {config.get('cipher', 'AES-256-GCM')}")
                print(f"  Available: {', '.join(STC_CIPHERS)}")
            elif rest[0] == "enable":
                if not self._check_role(ROLE_ADMIN):
                    return
                cipher = rest[1] if len(rest) > 1 else None
                if not cipher:
                    print("  Usage: stc cipher enable <name>")
                    return
                result = self.appliance.connections.set_stc_cipher(cipher)
                if result["success"]:
                    print(f"  STC cipher set to: {cipher}")
                else:
                    print(f"  Error: {result['error']}")
            elif rest[0] == "disable":
                if not self._check_role(ROLE_ADMIN):
                    return
                print("  Use 'stc cipher enable <name>' to set a different cipher.")

        elif sub == "hmac":
            if not rest:
                print("  Usage: stc hmac show | enable | disable")
                return
            if rest[0] == "show":
                config = self.appliance.connections.get_stc_config()
                print(f"  HMAC: {config.get('hmac', 'HMAC-SHA256')}")
                print(f"  HMAC Enabled: {'Yes' if config.get('hmac_enabled', True) else 'No'}")
            elif rest[0] == "enable":
                if not self._check_role(ROLE_ADMIN):
                    return
                self.appliance.connections.enable_stc_hmac()
                print("  STC HMAC enabled.")
            elif rest[0] == "disable":
                if not self._check_role(ROLE_ADMIN):
                    return
                self.appliance.connections.disable_stc_hmac()
                print("  STC HMAC disabled.")

        elif sub in ("rekeyThreshold", "rekeythreshold"):
            if not rest:
                print("  Usage: stc rekeyThreshold set <n> | show")
                return
            if rest[0] == "show":
                config = self.appliance.connections.get_stc_config()
                print(f"  Rekey Threshold: {config.get('rekey_threshold', 1000000)}")
            elif rest[0] == "set":
                if not self._check_role(ROLE_ADMIN):
                    return
                n = int(rest[1]) if len(rest) > 1 else None
                if not n:
                    print("  Usage: stc rekeyThreshold set <n>")
                    return
                result = self.appliance.connections.set_stc_rekey_threshold(n)
                if result["success"]:
                    print(f"  Rekey threshold set to: {n}")
                else:
                    print(f"  Error: {result['error']}")

        elif sub in ("activationTimeOut", "activationtimeout"):
            if not rest:
                print("  Usage: stc activationTimeOut set <n> | show")
                return
            if rest[0] == "show":
                config = self.appliance.connections.get_stc_config()
                print(f"  Activation Timeout: {config.get('activation_timeout', 300)}s")
            elif rest[0] == "set":
                if not self._check_role(ROLE_ADMIN):
                    return
                n = int(rest[1]) if len(rest) > 1 else None
                if not n:
                    print("  Usage: stc activationTimeOut set <n>")
                    return
                result = self.appliance.connections.set_stc_activation_timeout(n)
                if result["success"]:
                    print(f"  Activation timeout set to: {n}s")
                else:
                    print(f"  Error: {result['error']}")

        elif sub == "convert":
            if not self._check_role(ROLE_ADMIN):
                return
            client = self._get_arg(rest, "-client")
            slot = self._get_arg(rest, "-slot")
            if not client or not slot:
                print("  Usage: stc convert -client <name> -slot <id>")
                return
            confirm = input(f"  Convert NTLS connection for '{client}' on slot {slot} to STC? This is irreversible. (yes/no): ")
            if confirm.lower() != "yes":
                print("  Cancelled.")
                return
            result = self.appliance.connections.convert_ntls_to_stc(client, int(slot))
            if result["success"]:
                print(f"  {result['message']}")
                print(f"  STC Connection ID: {result['stc_connection_id']}")
                print(f"  Client Identity: {result['client_identity']}")
                print(f"  Partition Identity: {result['partition_identity']}")
                self._print_explain([
                    "Converting from NTLS to STC is a one-way operation.",
                    "STC partitions cannot be converted back to NTLS without",
                    "zeroizing the partition. STC provides higher assurance",
                    "with symmetric encryption and message authentication.",
                ])
            else:
                print(f"  Error: {result['error']}")

        elif sub == "admin":
            if not rest or rest[0] != "show":
                print("  Usage: stc admin show")
                return
            if not self._check_role(ROLE_ADMIN, ROLE_OPERATOR, ROLE_MONITOR):
                return
            status = self.appliance.connections.get_stc_admin_status()
            print(f"  STC Admin Channel Status:")
            print(f"    Enabled:          {'Yes' if status['enabled'] else 'No'}")
            print(f"    Cipher:           {status['cipher']}")
            print(f"    HMAC:             {status['hmac']}")
            print(f"    Identities:       {status['identities']}")
            print(f"    Connections:      {status['connections']}")

        else:
            print(f"  Unknown stc subcommand: {sub}")

    def _stc_identity(self, args: list):
        """Handle 'stc identity' subcommands."""
        if not args:
            print("  Usage: stc identity create | delete | list | show | export")
            return
        sub = args[0]
        rest = args[1:]

        if sub == "create":
            if not self._check_role(ROLE_ADMIN, ROLE_OPERATOR):
                return
            id_type = self._get_arg(rest, "-type")  # "client" or "partition"
            name = self._get_arg(rest, "-name")
            if not id_type or not name:
                print("  Usage: stc identity create -type <client|partition> -name <name>")
                return
            result = self.appliance.connections.create_stc_identity(name, id_type)
            if result["success"]:
                print(f"  STC {id_type} identity '{name}' created.")
                print(f"  Identity ID: {result['identity_id']}")
                self._print_explain([
                    f"STC identities have a public/private key pair. The public",
                    f"key must be exported and registered on the other end",
                    f"({'client' if id_type == 'partition' else 'appliance'}) to",
                    "establish mutual authentication.",
                ])
            else:
                print(f"  Error: {result['error']}")

        elif sub == "delete":
            if not self._check_role(ROLE_ADMIN, ROLE_OPERATOR):
                return
            id_type = self._get_arg(rest, "-type")
            name = self._get_arg(rest, "-name")
            if not id_type or not name:
                print("  Usage: stc identity delete -type <client|partition> -name <name>")
                return
            result = self.appliance.connections.delete_stc_identity(name, id_type)
            if result["success"]:
                print(f"  STC {id_type} identity '{name}' deleted.")
            else:
                print(f"  Error: {result['error']}")

        elif sub == "list":
            if not self._check_role(ROLE_ADMIN, ROLE_OPERATOR, ROLE_MONITOR):
                return
            identities = self.appliance.connections.list_stc_identities()
            if not identities:
                print("  No STC identities.")
                return
            print(f"  {'ID':<5} {'Name':<25} {'Type':<12} {'Initialized':<12} {'Created'}")
            print("  " + "-" * 75)
            for i in identities:
                print(f"  {i['identity_id']:<5} {i['name']:<25} {i['identity_type']:<12} {'Yes' if i['initialized'] else 'No':<12} {time.strftime('%Y-%m-%d %H:%M', time.localtime(i['created_at']))}")

        elif sub == "show":
            if not self._check_role(ROLE_ADMIN, ROLE_OPERATOR, ROLE_MONITOR):
                return
            id_type = self._get_arg(rest, "-type")
            name = self._get_arg(rest, "-name")
            if not id_type or not name:
                print("  Usage: stc identity show -type <client|partition> -name <name>")
                return
            identity = self.appliance.connections.get_stc_identity_by_name(name, id_type)
            if identity is None:
                print(f"  STC {id_type} identity '{name}' not found.")
                return
            print(f"  Identity ID:    {identity.identity_id}")
            print(f"  Name:           {identity.name}")
            print(f"  Type:           {identity.identity_type}")
            print(f"  Initialized:    {'Yes' if identity.initialized else 'No'}")
            print(f"  Public Key:     {identity.public_key[:32]}...")
            print(f"  Created:        {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(identity.created_at))}")

        elif sub == "export":
            if not self._check_role(ROLE_ADMIN, ROLE_OPERATOR, ROLE_MONITOR):
                return
            id_type = self._get_arg(rest, "-type")
            name = self._get_arg(rest, "-name")
            if not id_type or not name:
                print("  Usage: stc identity export -type <client|partition> -name <name>")
                return
            result = self.appliance.connections.export_stc_identity(name, id_type)
            if result["success"]:
                print(f"  STC {id_type} identity '{name}' exported.")
                print(f"  Public Key: {result['public_key']}")
                print(f"  File: {result['file']}")
                self._print_explain([
                    f"The exported {'partition identity (.pid)' if id_type == 'partition' else 'client identity (.clientID)'}",
                    "file must be transferred to the other end and registered",
                    "to establish mutual authentication for STC.",
                ])
            else:
                print(f"  Error: {result['error']}")

        else:
            print(f"  Unknown identity subcommand: {sub}")

    def _stc_connection(self, args: list):
        """Handle 'stc connection' subcommands."""
        if not args:
            print("  Usage: stc connection create | delete | list | connect | disconnect | restore")
            return
        sub = args[0]
        rest = args[1:]

        if sub == "list":
            if not self._check_role(ROLE_ADMIN, ROLE_OPERATOR, ROLE_MONITOR):
                return
            conns = self.appliance.connections.list_stc_connections()
            if not conns:
                print("  No STC connections.")
                return
            print(f"  {'ID':<5} {'Client':<25} {'Partition':<25} {'Slot':<6} {'State':<15} {'Cipher'}")
            print("  " + "-" * 95)
            for c in conns:
                print(f"  {c['connection_id']:<5} {c.get('client_name', 'N/A'):<25} {c.get('partition_name', 'N/A'):<25} {c['slot_id']:<6} {c['state']:<15} {c['cipher']}")

        elif sub == "create":
            if not self._check_role(ROLE_ADMIN, ROLE_OPERATOR):
                return
            client = self._get_arg(rest, "-client")
            partition = self._get_arg(rest, "-partition")
            slot = self._get_arg(rest, "-slot")
            cipher = self._get_arg(rest, "-cipher")
            hmac = self._get_arg(rest, "-hmac")
            if not client or not partition or not slot:
                print("  Usage: stc connection create -client <id_name> -partition <id_name> -slot <id> [-cipher <name>] [-hmac <name>]")
                return
            result = self.appliance.connections.create_stc_connection(
                client, partition, int(slot),
                cipher=cipher, hmac=hmac
            )
            if result["success"]:
                print(f"  STC connection created. ID: {result['connection_id']}")
                print(f"  Client identity: {result['client_identity']}")
                print(f"  Partition identity: {result['partition_identity']}")
                print(f"  Cipher: {result['cipher']}")
                print(f"  HMAC: {result['hmac']}")
                self._print_explain([
                    "The STC connection is in 'registered' state. Use",
                    "'stc connection connect' to establish the secure tunnel.",
                    "Mutual authentication will verify both identities before",
                    "establishing the encrypted session.",
                ])
            else:
                print(f"  Error: {result['error']}")

        elif sub == "delete":
            if not self._check_role(ROLE_ADMIN, ROLE_OPERATOR):
                return
            conn_id = self._get_arg(rest, "-id")
            if not conn_id:
                print("  Usage: stc connection delete -id <connection_id>")
                return
            result = self.appliance.connections.delete_stc_connection(int(conn_id))
            if result["success"]:
                print(f"  STC connection {conn_id} deleted.")
            else:
                print(f"  Error: {result['error']}")

        elif sub == "connect":
            if not self._check_role(ROLE_ADMIN, ROLE_OPERATOR):
                return
            conn_id = self._get_arg(rest, "-id")
            if not conn_id:
                print("  Usage: stc connection connect -id <connection_id>")
                return
            result = self.appliance.connections.connect_stc(int(conn_id))
            if result["success"]:
                print(f"  STC connection {conn_id} established.")
                print(f"  Cipher: {result.get('cipher', 'N/A')}")
                self._print_explain([
                    "The STC secure tunnel is now active. All communication",
                    "is encrypted with symmetric encryption and protected",
                    "with message authentication codes.",
                ])
            else:
                print(f"  Error: {result['error']}")

        elif sub == "disconnect":
            if not self._check_role(ROLE_ADMIN, ROLE_OPERATOR):
                return
            conn_id = self._get_arg(rest, "-id")
            if not conn_id:
                print("  Usage: stc connection disconnect -id <connection_id>")
                return
            result = self.appliance.connections.disconnect_stc(int(conn_id))
            if result["success"]:
                print(f"  STC connection {conn_id} disconnected.")
            else:
                print(f"  Error: {result['error']}")

        elif sub == "restore":
            if not self._check_role(ROLE_ADMIN, ROLE_OPERATOR):
                return
            conn_id = self._get_arg(rest, "-id")
            if not conn_id:
                print("  Usage: stc connection restore -id <connection_id>")
                return
            result = self.appliance.connections.restore_stc_connection(int(conn_id))
            if result["success"]:
                print(f"  {result['message']}")
            else:
                print(f"  Error: {result['error']}")

        else:
            print(f"  Unknown connection subcommand: {sub}")

    # ------------------------------------------------------------------
    # sysconf
    # ------------------------------------------------------------------

    def cmd_sysconf(self, args: list):
        """Handle 'sysconf' commands."""
        if not args:
            print("  Usage: sysconf timezone | banner | forceSOLogin | ssh | reboot | poweroff")
            return
        if not self._check_login():
            return
        sub = args[0]
        rest = args[1:]

        if sub == "timezone":
            if not rest:
                config = self.appliance.get_sysconf()
                print(f"  Current timezone: {config['timezone']}")
                return
            if rest[0] == "set":
                tz = rest[1] if len(rest) > 1 else None
                if not tz:
                    print("  Usage: sysconf timezone set <timezone>")
                    return
                if not self._check_role(ROLE_ADMIN):
                    return
                self.appliance.set_timezone(tz)
                print(f"  Timezone set to: {tz}")
            elif rest[0] == "show":
                config = self.appliance.get_sysconf()
                print(f"  Timezone: {config['timezone']}")
            else:
                print(f"  Unknown timezone subcommand: {rest[0]}")

        elif sub == "banner":
            if not rest:
                print("  Usage: sysconf banner add <text> | clear | show")
                return
            if rest[0] == "add":
                if not self._check_role(ROLE_ADMIN):
                    return
                text = " ".join(rest[1:])
                self.appliance.set_banner(text)
                print(f"  Banner set.")
            elif rest[0] == "clear":
                if not self._check_role(ROLE_ADMIN):
                    return
                self.appliance.clear_banner()
                print("  Banner cleared.")
            elif rest[0] == "show":
                config = self.appliance.get_sysconf()
                if config["banner"]:
                    print(f"  Banner: {config['banner']}")
                else:
                    print("  No banner set.")

        elif sub in ("forceSOLogin", "forcesologin"):
            if not rest:
                config = self.appliance.get_sysconf()
                print(f"  Force SO Login: {'Enabled' if config['force_so_login'] else 'Disabled'}")
                return
            if not self._check_role(ROLE_ADMIN):
                return
            if rest[0] == "enable":
                self.appliance.force_so_login_enable()
                print("  Force SO Login enabled.")
            elif rest[0] == "disable":
                self.appliance.force_so_login_disable()
                print("  Force SO Login disabled.")

        elif sub == "ssh":
            if not rest:
                print("  Usage: sysconf ssh port <port> | show")
                return
            if rest[0] == "port":
                if not self._check_role(ROLE_ADMIN):
                    return
                port = int(rest[1]) if len(rest) > 1 else None
                if not port:
                    print("  Usage: sysconf ssh port <port>")
                    return
                self.appliance.set_ssh_port(port)
                print(f"  SSH port set to: {port}")
            elif rest[0] == "show":
                config = self.appliance.get_sysconf()
                print(f"  SSH Port:          {config['ssh_port']}")
                print(f"  SSH Password Auth: {'Enabled' if config['ssh_password_auth'] else 'Disabled'}")
                print(f"  SSH PubKey Auth:   {'Enabled' if config['ssh_pubkey_auth'] else 'Disabled'}")

        elif sub in ("appliance",):
            if not rest:
                print("  Usage: sysconf appliance reboot | poweroff | hardReboot")
                return
            if rest[0] == "reboot":
                if not self._check_role(ROLE_ADMIN):
                    return
                confirm = input("  Reboot appliance? (yes/no): ")
                if confirm.lower() == "yes":
                    result = self.appliance.reboot()
                    print(f"  {result['message']}")
                else:
                    print("  Cancelled.")
            elif rest[0] == "poweroff":
                if not self._check_role(ROLE_ADMIN):
                    return
                confirm = input("  Power off appliance? (yes/no): ")
                if confirm.lower() == "yes":
                    result = self.appliance.poweroff()
                    print(f"  {result['message']}")
                else:
                    print("  Cancelled.")
            elif rest[0] == "hardReboot":
                if not self._check_role(ROLE_ADMIN):
                    return
                print("  Hard reboot initiated.")
            else:
                print(f"  Unknown appliance subcommand: {rest[0]}")

        else:
            print(f"  Unknown sysconf subcommand: {sub}")

    # ------------------------------------------------------------------
    # service
    # ------------------------------------------------------------------

    def cmd_service(self, args: list):
        """Handle 'service' commands."""
        if not args:
            print("  Usage: service list | start | stop | restart | status")
            return
        if not self._check_login():
            return
        sub = args[0]

        if sub == "list":
            if not self._check_role(ROLE_ADMIN, ROLE_OPERATOR, ROLE_MONITOR):
                return
            services = self.appliance.list_services()
            print(f"  {'Service':<20} {'Status':<12} {'Description'}")
            print("  " + "-" * 65)
            for s in services:
                print(f"  {s['name']:<20} {s['status']:<12} {s['description']}")

        elif sub == "start":
            if not self._check_role(ROLE_ADMIN, ROLE_OPERATOR):
                return
            name = args[1] if len(args) > 1 else None
            if not name:
                print("  Usage: service start <name>")
                return
            result = self.appliance.start_service(name)
            if result["success"]:
                print(f"  Service '{name}' started.")
            else:
                print(f"  Error: {result['error']}")

        elif sub == "stop":
            if not self._check_role(ROLE_ADMIN, ROLE_OPERATOR):
                return
            name = args[1] if len(args) > 1 else None
            if not name:
                print("  Usage: service stop <name>")
                return
            result = self.appliance.stop_service(name)
            if result["success"]:
                print(f"  Service '{name}' stopped.")
            else:
                print(f"  Error: {result['error']}")

        elif sub == "restart":
            if not self._check_role(ROLE_ADMIN, ROLE_OPERATOR):
                return
            name = args[1] if len(args) > 1 else None
            if not name:
                print("  Usage: service restart <name>")
                return
            result = self.appliance.restart_service(name)
            if result["success"]:
                print(f"  Service '{name}' restarted.")
            else:
                print(f"  Error: {result['error']}")

        elif sub == "status":
            if not self._check_role(ROLE_ADMIN, ROLE_OPERATOR, ROLE_MONITOR):
                return
            name = args[1] if len(args) > 1 else None
            if not name:
                print("  Usage: service status <name>")
                return
            result = self.appliance.service_status(name)
            if result.get("success", True) and "status" in result:
                print(f"  Service '{name}': {result['status']}")
            else:
                print(f"  Error: {result.get('error', 'Unknown')}")

        else:
            print(f"  Unknown service subcommand: {sub}")

    # ------------------------------------------------------------------
    # syslog
    # ------------------------------------------------------------------

    def cmd_syslog(self, args: list):
        """Handle 'syslog' commands."""
        if not args:
            print("  Usage: syslog show | severity set | rotate | remotehost add|delete|list")
            return
        if not self._check_login():
            return
        sub = args[0]
        rest = args[1:]

        if sub == "show":
            if not self._check_role(ROLE_ADMIN, ROLE_OPERATOR, ROLE_MONITOR):
                return
            config = self.appliance.get_syslog_config()
            print(f"  Severity:      {config['severity']}")
            print(f"  Rotations:     {config['rotations']}")
            print(f"  Remote Hosts:  {', '.join(config['remote_hosts']) if config['remote_hosts'] else 'None'}")

        elif sub == "severity":
            if not rest or rest[0] != "set":
                print("  Usage: syslog severity set <level>")
                return
            if not self._check_role(ROLE_ADMIN):
                return
            level = rest[1] if len(rest) > 1 else None
            if not level:
                print("  Usage: syslog severity set <level>")
                return
            result = self.appliance.set_syslog_severity(level)
            if result["success"]:
                print(f"  Syslog severity set to: {level}")
            else:
                print(f"  Error: {result['error']}")

        elif sub == "rotate":
            if not self._check_role(ROLE_ADMIN, ROLE_OPERATOR):
                return
            result = self.appliance.rotate_syslog()
            print(f"  {result['message']}")

        elif sub == "remotehost":
            if not rest:
                print("  Usage: syslog remotehost add|delete|list <host>")
                return
            action = rest[0]
            if action == "list":
                config = self.appliance.get_syslog_config()
                if config["remote_hosts"]:
                    for h in config["remote_hosts"]:
                        print(f"  {h}")
                else:
                    print("  No remote syslog hosts configured.")
            elif action == "add":
                if not self._check_role(ROLE_ADMIN):
                    return
                host = rest[1] if len(rest) > 1 else None
                if not host:
                    print("  Usage: syslog remotehost add <host>")
                    return
                self.appliance.add_syslog_remote_host(host)
                print(f"  Remote host added: {host}")
            elif action == "delete":
                if not self._check_role(ROLE_ADMIN):
                    return
                host = rest[1] if len(rest) > 1 else None
                if not host:
                    print("  Usage: syslog remotehost delete <host>")
                    return
                self.appliance.delete_syslog_remote_host(host)
                print(f"  Remote host deleted: {host}")

        else:
            print(f"  Unknown syslog subcommand: {sub}")

    # ------------------------------------------------------------------
    # my
    # ------------------------------------------------------------------

    def cmd_my(self, args: list):
        """Handle 'my' commands."""
        if not args:
            print("  Usage: my password set | file list | public-key list")
            return
        if not self._check_login():
            return
        sub = args[0]

        if sub == "password":
            if args[1:] and args[1] == "set":
                old = getpass.getpass("  Old password: ")
                new = getpass.getpass("  New password: ")
                confirm = getpass.getpass("  Confirm: ")
                if new != confirm:
                    print("  Error: Passwords do not match.")
                    return
                result = self.appliance.set_my_password(old, new)
                if result["success"]:
                    print("  Password changed.")
                else:
                    print(f"  Error: {result['error']}")
            elif args[1:] and args[1] == "expiry" and args[2:] and args[2] == "show":
                print("  Password expiry: 90 days")
            else:
                print("  Usage: my password set | my password expiry show")

        elif sub == "file":
            if args[1:] and args[1] == "list":
                print("  No files in current user's directory.")
            else:
                print("  Usage: my file list | clear | delete")

        elif sub == "public-key":
            if args[1:] and args[1] == "list":
                print("  No public keys registered.")
            else:
                print("  Usage: my public-key list | add | delete | clear")

        else:
            print(f"  Unknown my subcommand: {sub}")

    # ------------------------------------------------------------------
    # package
    # ------------------------------------------------------------------

    def cmd_package(self, args: list):
        """Handle 'package' commands."""
        if not args:
            print("  Usage: package list | verify | update | deletefile | erase")
            return
        if not self._check_role(ROLE_ADMIN):
            return
        sub = args[0]

        if sub == "list":
            packages = self.appliance.list_packages()
            print(f"  {'Filename':<35} {'Size':<10} {'Type'}")
            print("  " + "-" * 55)
            for p in packages:
                print(f"  {p['name']:<35} {p['size']:<10} {p['type']}")

        elif sub == "verify":
            filename = args[1] if len(args) > 1 else None
            if not filename:
                print("  Usage: package verify <filename>")
                return
            result = self.appliance.verify_package(filename)
            print(f"  {result['status']}")

        elif sub == "update":
            filename = args[1] if len(args) > 1 else None
            if not filename:
                print("  Usage: package update <filename>")
                return
            print(f"  Applying package: {filename}")
            time.sleep(0.5)
            print(f"  Package '{filename}' applied successfully.")

        elif sub == "listfile":
            print("  Files in package directory:")
            print("    luna-firmware-7.13.0.pkg")
            print("    luna-client-10.1.0.pkg")

        elif sub == "deletefile":
            filename = args[1] if len(args) > 1 else None
            if not filename:
                print("  Usage: package deletefile <filename>")
                return
            print(f"  File '{filename}' deleted.")

        elif sub == "erase":
            confirm = input("  Erase all package files? (yes/no): ")
            if confirm.lower() == "yes":
                print("  All package files erased.")
            else:
                print("  Cancelled.")

        else:
            print(f"  Unknown package subcommand: {sub}")

    # ------------------------------------------------------------------
    # token backup (LunaSH variant)
    # ------------------------------------------------------------------

    def cmd_token(self, args: list):
        """Handle 'token backup' commands (LunaSH variant)."""
        if not args:
            print("  Usage: token backup show | init | login | logout | list | factoryReset |")
            print("         partition list | partition show | partition delete |")
            print("         update firmware | update show")
            return
        if not self._check_login():
            return
        sub = args[0]
        rest = args[1:]

        if sub == "backup":
            if not rest:
                print("  Usage: token backup show | init | login | logout | list | factoryReset |")
                print("         partition list | partition show | partition delete |")
                print("         update firmware | update show")
                return
            bsub = rest[0]
            brest = rest[1:]

            if bsub == "show":
                if self.api and self.api.backup.is_connected():
                    print(self.api.backup.show_info())
                else:
                    print("  No backup HSM connected.")

            elif bsub == "init":
                if not self._check_role(ROLE_ADMIN, ROLE_OPERATOR):
                    return
                if self.api:
                    if not self.api.backup.is_connected():
                        self.api.backup.connect()
                    if self.api.backup._get_stm_state() == "secure_transport":
                        print("  Backup HSM is in Secure Transport Mode.")
                        print("  Use 'hsm stm recover' first.")
                        return
                    print("  [PED Simulation] Set SO PIN for backup HSM:")
                    pin = getpass.getpass("  SO PIN: ")
                    confirm = getpass.getpass("  Confirm: ")
                    if pin != confirm:
                        print("  Error: PINs do not match.")
                        return
                    self.api.backup.initialize(pin, audit=self.api.audit)
                    print("  Backup HSM initialized.")

            elif bsub == "login":
                if self.api:
                    if not self.api.backup.is_connected():
                        self.api.backup.connect()
                    print("  [PED Simulation] Enter backup HSM SO PIN:")
                    pin = getpass.getpass("  SO PIN: ")
                    try:
                        self.api.backup.login(pin, audit=self.api.audit)
                        print("  Logged in to backup HSM.")
                    except PKCS11Error as e:
                        print(f"  Login failed: {e}")

            elif bsub == "logout":
                if self.api:
                    self.api.backup.logout(audit=self.api.audit)
                    print("  Logged out of backup HSM.")

            elif bsub == "list":
                if self.api and self.api.backup.is_logged_in():
                    print(self.api.backup.list_backups())
                else:
                    print("  Not logged in to backup HSM.")

            elif bsub == "factoryReset":
                if not self._check_role(ROLE_ADMIN):
                    return
                confirm = input("  Factory reset backup HSM? Type 'BACKUPRESET' to confirm: ")
                if confirm == "BACKUPRESET":
                    if self.api:
                        self.api.backup.factory_reset(audit=self.api.audit)
                        print("  Backup HSM reset to factory defaults.")
                else:
                    print("  Cancelled.")

            elif bsub == "partition":
                if not brest:
                    print("  Usage: token backup partition list | show | delete")
                    return
                psub = brest[0]
                if psub == "list":
                    if self.api and self.api.backup.is_logged_in():
                        parts = self.api.backup.list_backup_partitions()
                        for p in parts:
                            print(f"  ID: {p['partition_id']}  Domain: {p['domain']}  Objects: {p['object_count']}  Created: {p['created_at']}")
                    else:
                        print("  Not logged in to backup HSM.")
                elif psub == "show":
                    print("  Use 'token backup list' for partition details.")
                elif psub == "delete":
                    print("  Partition deletion requires backup HSM login.")
                else:
                    print(f"  Unknown partition subcommand: {psub}")

            elif bsub == "update":
                if not brest:
                    print("  Usage: token backup update firmware | show")
                    return
                usub = brest[0]
                if usub == "firmware":
                    if self.api and self.api.backup.is_connected():
                        info = self.api.backup.get_firmware_info()
                        print(f"  Current: {info['current_version']}  Latest: {info['latest_version']}")
                    else:
                        print("  No backup HSM connected.")
                elif usub == "show":
                    if self.api and self.api.backup.is_connected():
                        info = self.api.backup.get_firmware_info()
                        print(f"  Current: {info['current_version']}")
                        print(f"  Latest:  {info['latest_version']}")
                        print(f"  Update:  {'Available' if info['update_available'] else 'Not available'}")
                    else:
                        print("  No backup HSM connected.")
                else:
                    print(f"  Unknown update subcommand: {usub}")

            else:
                print(f"  Unknown backup subcommand: {bsub}")

        else:
            print(f"  Unknown token subcommand: {sub}")

    # ------------------------------------------------------------------
    # audit
    # ------------------------------------------------------------------

    def cmd_audit(self, args: list):
        """Handle 'audit' commands (LunaSH variant)."""
        if not args:
            print("  Usage: audit login | logout | show | log list | log verify | log clear")
            return
        if not self._check_login():
            return
        sub = args[0]

        if sub == "login":
            if self.appliance.is_audit_logged_in():
                print("  Already logged in as Auditor.")
                return
            print("  [PED Simulation] Enter Auditor PIN:")
            pin = getpass.getpass("  PIN: ")
            result = self.appliance.audit_login(pin)
            if result["success"]:
                print("  Auditor logged in.")
            else:
                print(f"  Login failed: {result['error']}")

        elif sub == "logout":
            self.appliance.audit_logout()
            print("  Auditor logged out.")

        elif sub == "show":
            if self.api:
                logs = self.api.storage.get_audit_logs()
                print(f"  Total audit entries: {len(logs)}")
                if logs:
                    print(f"  First entry: {logs[0]['timestamp']}")
                    print(f"  Last entry:  {logs[-1]['timestamp']}")
                    print(f"  Chain intact: Yes")
            else:
                print("  Audit log not available.")

        elif sub == "log":
            if not args[1:]:
                print("  Usage: audit log list | verify | clear | tail")
                return
            lsub = args[1]
            if lsub == "list":
                if self.api:
                    logs = self.api.storage.get_audit_logs()
                    for log in logs[-20:]:  # last 20
                        print(f"  [{log['timestamp']}] {log['role']}: {log['operation']} ({'OK' if log['success'] else 'FAIL'}) {log.get('detail', '')}")
            elif lsub == "verify":
                print("  Audit chain verification: PASSED (all entries verified)")
            elif lsub == "clear":
                if not self.appliance.is_audit_logged_in():
                    print("  Error: Auditor login required.")
                    return
                confirm = input("  Clear ALL audit logs? (yes/no): ")
                if confirm.lower() == "yes":
                    if self.api:
                        self.api.storage.clear_audit_logs()
                        print("  Audit logs cleared.")
                else:
                    print("  Cancelled.")
            elif lsub == "tail":
                if self.api:
                    logs = self.api.storage.get_audit_logs()
                    for log in logs[-10:]:
                        print(f"  [{log['timestamp']}] {log['role']}: {log['operation']} ({'OK' if log['success'] else 'FAIL'})")
            else:
                print(f"  Unknown log subcommand: {lsub}")

        else:
            print(f"  Unknown audit subcommand: {sub}")

    # ------------------------------------------------------------------
    # help
    # ------------------------------------------------------------------

    def cmd_help(self, args: list):
        """Show LunaSH command reference."""
        print("""
  LunaSH Command Reference (Luna Network HSM 7 Appliance Shell)

  Authentication:
    login                               Log in to the appliance
    logout                              Log out of the appliance

  System Status:
    status cpu                          Show CPU usage
    status mem                          Show memory usage
    status disk                         Show disk usage
    status date                         Show current date/time
    status interface                    Show network interfaces
    status ps                           Show running processes
    status netstat                      Show network connections
    status sensors                      Show hardware sensors

  HSM Management:
    hsm login                            Log in as HSO (requires SO PIN)
    hsm logout                           Log out HSM SO
    hsm show                             Show HSM info
    hsm init                             Initialize HSM (set SO PIN)
    hsm factoryReset                     Factory reset HSM (destructive)
    hsm zeroize                          Zeroize HSM (destroys all keys)
    hsm firmware show                    Show firmware info
    hsm firmware upgrade -version <v>   Upgrade HSM firmware
    hsm firmware rollback                Roll back HSM firmware
    hsm showPolicies                     Show HSM policies
    hsm changePolicy -policy <id> -value <v>  Change HSM policy
    hsm stm show                         Show Secure Transport Mode status
    hsm stm recover -string <s>          Recover from STM
    hsm ped show                         Show PED status
    hsm selfTest                         Run HSM self-test
    hsm time                             Show HSM time
    hsm information show                 Show HSM information

  Partition Management:
    partition list                       List all partitions
    partition create -name <n> [-label <l>]  Create a partition
    partition delete -name <n>           Delete a partition
    partition show [-name <n>]           Show partition info
    partition init -name <n>             Initialize a partition (set SO PIN)
    partition showPolicies [-verbose]    Show partition policies
    partition changePolicy -policy <id> -value <v>  Change partition policy
    partition clear -name <n>            Clear all objects on a partition
    partition activate -name <n>          Activate a partition
    partition deactivate -name <n>       Deactivate a partition
    partition rename -name <n> -newname <n>  Rename a partition
    partition resize -name <n> -size <s>  Resize a partition

  User Management:
    user list                            List all appliance users
    user add -name <u> -role <r>          Add a user (admin, operator, monitor, audit)
    user delete -name <u>                 Delete a user
    user enable -name <u>                 Enable a user account
    user disable -name <u>                Disable a user account
    user password -name <u>               Set user password

  Client Management:
    client list                           List registered clients
    client register -name <n> [-ip <ip>]  Register a client
    client delete -name <n>               Delete a client
    client show -name <n>                 Show client details
    client assignPartition -name <c> -partition <s>  Assign partition to client
    client revokePartition -name <c> -partition <s>  Revoke partition from client

  Network:
    network show                          Show network configuration
    network hostname <hostname>           Set hostname
    network interface static <iface> -ip <ip> -netmask <mask> [-gateway <gw>]
    network interface dhcp <iface>        Set interface to DHCP
    network dns add|delete nameserver <ip>  Manage DNS nameservers
    network route add|delete|show         Manage network routes
    network ping <host>                   Ping a host

  NTLS:
    ntls show                             Show NTLS status
    ntls bind <interface>                 Bind NTLS to interface
    ntls certificate show                 Show NTLS certificate

  System Configuration:
    sysconf timezone set|show <tz>        Set/show timezone
    sysconf banner add <text> | clear | show  Manage login banner
    sysconf forceSOLogin enable|disable   Enable/disable forced SO login
    sysconf ssh port <port> | show         Configure SSH
    sysconf appliance reboot | poweroff    Reboot/poweroff appliance

  Services:
    service list                          List all services
    service start <name>                  Start a service
    service stop <name>                   Stop a service
    service restart <name>                Restart a service
    service status <name>                 Show service status

  Syslog:
    syslog show                           Show syslog configuration
    syslog severity set <level>           Set syslog severity
    syslog rotate                          Rotate system logs
    syslog remotehost add|delete|list <h>  Manage remote syslog hosts

  My (current user):
    my password set                       Change current user's password
    my password expiry show               Show password expiry
    my file list                          List current user's files
    my public-key list                    List current user's public keys

  Package Management:
    package list                          List available packages
    package verify <filename>             Verify package signature
    package update <filename>             Apply package update
    package listfile                      List files in package directory
    package deletefile <filename>         Delete a package file
    package erase                         Erase all package files

  Backup HSM (via LunaSH):
    token backup show                     Show backup HSM status
    token backup init                     Initialize backup HSM
    token backup login                    Login to backup HSM
    token backup logout                   Logout of backup HSM
    token backup list                     List backup partitions
    token backup factoryReset             Factory reset backup HSM
    token backup partition list           List backup partitions
    token backup update firmware          Show backup HSM firmware info
    token backup update show              Show backup HSM update status

  Audit:
    audit login                           Login as Auditor
    audit logout                           Logout Auditor
    audit show                             Show audit summary
    audit log list                         List audit log entries
    audit log verify                       Verify audit chain
    audit log clear                        Clear audit logs
    audit log tail                         Show recent audit entries
""")

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def _get_arg(self, args: list, flag: str) -> str:
        """Extract a -flag value from args list."""
        for i, a in enumerate(args):
            if a == flag and i + 1 < len(args):
                return args[i + 1]
        return None
