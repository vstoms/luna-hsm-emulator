"""Interactive LunaSH shell — emulates the Luna Network HSM 7 appliance shell.

LunaSH is the server-side command shell that runs on the Luna Network HSM 7
appliance. It is accessed via SSH and manages appliance-level concerns
(users, network, NTLS, clients, partitions, services, system config).

This is distinct from lunacm (the client-side PKCS#11 configuration manager).

LunaSH features emulated:
  - SSH-style login with appliance users (admin, operator, monitor, audit)
  - Command shortnames (e.g. 'hs' for 'hsm', 'par' for 'partition')
  - Tab-completion for subcommands
  - Role-based access control (RBAC)
  - HSM SO login (separate from appliance login)
  - Auditor login (separate from appliance login)
"""

import cmd
import shlex
import sys

from cli.lunash_commands import LunaSHCommands
from cli.output import invoke_with_result
from hsm.appliance import Appliance
from pkcs11.api import PKCS11API


# Command shortname mapping (matches real LunaSH shortcuts)
COMMAND_SHORTCUTS = {
    "a": "audit", "cli": "client", "clu": "cluster", "hs": "hsm",
    "k": "keyring", "m": "my", "ne": "network", "nt": "ntls",
    "pac": "package", "par": "partition", "se": "service",
    "sta": "status", "stc": "stc", "sysc": "sysconf",
    "sysl": "syslog", "u": "user", "w": "webserver",
}

# Subcommand completions per top-level command
SUBCOMMANDS = {
    "status": ["cpu", "mem", "disk", "date", "time", "interface", "ps", "netstat", "sensors"],
    "hsm": ["backup", "changePolicy", "changePw", "checkCertificates", "displayLicenses",
            "factoryReset", "firmware", "fm", "generateDAK", "information", "init", "login",
            "logout", "ped", "qos", "restart", "restore", "selfTest", "setLegacyDomain", "show",
            "showPolicies", "stc", "stm", "supportInfo", "tamper", "time", "update", "zeroize"],
    "partition": ["activate", "backup", "changePolicy", "changePw", "clear", "create",
                  "createChallenge", "deactivate", "delete", "init", "list", "rename", "resize",
                  "restore", "show", "showContents", "showPolicies", "stcIdentity"],
    "user": ["list", "add", "delete", "enable", "disable", "password"],
    "client": ["list", "register", "delete", "show", "assignPartition", "revokePartition"],
    "network": ["show", "hostname", "interface", "dns", "route", "ping"],
    "ntls": ["show", "bind", "unbind", "certificate", "connection", "ipcheck", "threads", "timer", "tcp_keepalive"],
    "stc": ["enable", "disable", "show", "status", "identity", "connection", "cipher", "hmac", "rekeyThreshold", "activationTimeOut", "convert", "admin"],
    "sysconf": ["appliance", "banner", "config", "ctc", "drift", "fingerprint",
                "forceSOLogin", "installCert", "license", "ntp", "radius", "regenCert",
                "reimage", "scp", "snmp", "ssh", "time", "timezone", "tls", "user"],
    "service": ["list", "start", "stop", "restart", "status"],
    "syslog": ["show", "severity", "rotate", "remotehost"],
    "my": ["password", "file", "public-key"],
    "package": ["list", "verify", "update", "listfile", "deletefile", "erase"],
    "token": ["backup"],
    "audit": ["login", "logout", "show", "log"],
    "cluster": ["admin", "backup", "client", "config", "create", "delete", "disable", "enable", "join", "leave", "list", "member", "restore", "show", "status"],
    "keyring": ["create", "delete", "disable", "enable", "list", "reset", "show", "unlock"],
    "webserver": ["bind", "certificate", "ciphers", "disable", "enable", "groups", "origin", "show"],
}


class LunaSHShell(cmd.Cmd):
    """Interactive LunaSH emulator shell."""

    intro = """
  ╔══════════════════════════════════════════════════════════════════╗
  ║         Thales Luna 7 Network HSM Emulator — LunaSH             ║
  ║         Appliance Command Shell  |  Training Use                  ║
  ║                                                                  ║
  ║  LunaSH is the server-side appliance shell (SSH-based).           ║
  ║  It manages users, network, clients, partitions, and services.  ║
  ║                                                                  ║
  ║  WARNING: Software emulator for educational purposes ONLY.       ║
  ║           NOT for production use. No hardware security boundary. ║
  ╚══════════════════════════════════════════════════════════════════╝

  Type 'login' to authenticate, 'help' for command reference, 'exit' to quit.
"""

    def __init__(self, appliance: Appliance, api: PKCS11API = None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.appliance = appliance
        self.handler = LunaSHCommands(appliance, api)
        self._update_prompt()

    def _update_prompt(self):
        """Update the prompt to reflect login state."""
        user = self.appliance.get_current_user()
        if user:
            hostname = self.appliance.storage.get_meta("appliance_hostname") or "luna7"
            hsm_state = " (HSO)" if self.appliance.is_hsm_logged_in() else ""
            self.prompt = f"[{hostname}] lunash:>{hsm_state} "
        else:
            self.prompt = "login as: "

    # ------------------------------------------------------------------
    # Command dispatch
    # ------------------------------------------------------------------

    def _resolve_command(self, name: str) -> str:
        """Resolve documented shortcuts and unambiguous LunaSH prefixes."""
        name = name.lower()
        if name in COMMAND_SHORTCUTS:
            return COMMAND_SHORTCUTS[name]
        commands = set(SUBCOMMANDS) | {"help"}
        if name in commands:
            return name
        matches = sorted(command for command in commands if command.startswith(name))
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            print(f"  Ambiguous command '{name}': {', '.join(matches)}")
            return ""
        return name

    def _run(self, line: str):
        """Parse and run a command line."""
        try:
            parts = shlex.split(line)
        except ValueError as error:
            print(f"  Syntax Error: {error}")
            return
        if not parts:
            return
        if parts[0].lower() == "tb":
            parts = ["token", "backup", *parts[1:]]
        if not self.appliance.is_logged_in():
            invoke_with_result(self.handler.cmd_login, [parts[0]],
                               "Command Result : 0 (Success)",
                               "Command Result : 1 (Failure)")
            self._update_prompt()
            return
        cmd_name = self._resolve_command(parts[0])
        if not cmd_name:
            return
        rest = parts[1:]
        if rest and not rest[0].startswith("-") and cmd_name in SUBCOMMANDS:
            token = rest[0].lower()
            choices = SUBCOMMANDS[cmd_name]
            matches = [choice for choice in choices if choice.lower().startswith(token)]
            if len(matches) == 1:
                rest[0] = matches[0]
            elif len(matches) > 1 and token not in {choice.lower() for choice in choices}:
                print(f"  Ambiguous subcommand '{rest[0]}': {', '.join(matches)}")
                return

        dispatch = {
            "status": self.handler.cmd_status,
            "hsm": self.handler.cmd_hsm,
            "partition": self.handler.cmd_partition,
            "user": self.handler.cmd_user,
            "client": self.handler.cmd_client,
            "network": self.handler.cmd_network,
            "ntls": self.handler.cmd_ntls,
            "stc": self.handler.cmd_stc,
            "sysconf": self.handler.cmd_sysconf,
            "service": self.handler.cmd_service,
            "syslog": self.handler.cmd_syslog,
            "my": self.handler.cmd_my,
            "package": self.handler.cmd_package,
            "token": self.handler.cmd_token,
            "audit": self.handler.cmd_audit,
            "cluster": self.handler.cmd_unavailable,
            "keyring": self.handler.cmd_unavailable,
            "webserver": self.handler.cmd_unavailable,
            "help": self.handler.cmd_help,
            "?": self.handler.cmd_help,
        }

        handler = dispatch.get(cmd_name)
        if handler:
            invoke_with_result(handler, rest,
                               "Command Result : 0 (Success)",
                               "Command Result : 1 (Failure)")
            self._update_prompt()
        elif cmd_name in ("exit", "quit", "bye"):
            print("  Exiting LunaSH.")
            return True
        else:
            print(f"  Unknown command: {parts[0]}. Type 'help' for available commands.")
            # Show available commands
            available = sorted(set(dispatch.keys()) - {"help"})
            print(f"  Available: {', '.join(available)}")

    # ------------------------------------------------------------------
    # cmd.Cmd overrides
    # ------------------------------------------------------------------

    def default(self, line: str):
        result = self._run(line.strip())
        if result is True:
            return True

    def do_exit(self, arg):
        print("  Exiting LunaSH.")
        return True

    def do_quit(self, arg):
        return self.do_exit(arg)

    def do_help(self, arg):
        self.handler.cmd_help([])

    # Custom command handlers
    def do_status(self, arg):
        self._run(f"status {arg}" if arg else "status")

    def do_hsm(self, arg):
        self._run(f"hsm {arg}" if arg else "hsm")

    def do_partition(self, arg):
        self._run(f"partition {arg}" if arg else "partition")

    def do_user(self, arg):
        self._run(f"user {arg}" if arg else "user")

    def do_client(self, arg):
        self._run(f"client {arg}" if arg else "client")

    def do_network(self, arg):
        self._run(f"network {arg}" if arg else "network")

    def do_ntls(self, arg):
        self._run(f"ntls {arg}" if arg else "ntls")

    def do_stc(self, arg):
        self._run(f"stc {arg}" if arg else "stc")

    def do_sysconf(self, arg):
        self._run(f"sysconf {arg}" if arg else "sysconf")

    def do_service(self, arg):
        self._run(f"service {arg}" if arg else "service")

    def do_syslog(self, arg):
        self._run(f"syslog {arg}" if arg else "syslog")

    def do_my(self, arg):
        self._run(f"my {arg}" if arg else "my")

    def do_package(self, arg):
        self._run(f"package {arg}" if arg else "package")

    def do_token(self, arg):
        self._run(f"token {arg}" if arg else "token")

    def do_audit(self, arg):
        self._run(f"audit {arg}" if arg else "audit")

    def do_ha(self, arg):
        self._run(f"ha {arg}" if arg else "ha")

    def do_ntp(self, arg):
        self._run(f"ntp {arg}" if arg else "ntp")

    def do_bond(self, arg):
        self._run(f"bond {arg}" if arg else "bond")

    def do_license(self, arg):
        self._run(f"license {arg}" if arg else "license")

    # ------------------------------------------------------------------
    # Tab completion
    # ------------------------------------------------------------------

    def completedefault(self, text, line, begidx, endidx):
        """Context-sensitive tab completion."""
        parts = line.split()
        if len(parts) <= 1:
            return []

        cmd_name = self._resolve_command(parts[0])
        subs = SUBCOMMANDS.get(cmd_name, [])

        if len(parts) == 2 or (len(parts) == 1 and not text):
            return [s for s in subs if s.startswith(text)]
        return []

    # ------------------------------------------------------------------
    # Empty line
    # ------------------------------------------------------------------

    def emptyline(self):
        pass

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def postloop(self):
        if self.appliance.is_logged_in():
            self.appliance.logout()


def run_lunash(appliance: Appliance, api: PKCS11API = None):
    """Start the interactive LunaSH shell."""
    shell = LunaSHShell(appliance, api)
    try:
        shell.cmdloop()
    except KeyboardInterrupt:
        print("\n  Use 'exit' to quit.")
        shell.cmdloop()
    finally:
        if shell.appliance.is_logged_in():
            shell.appliance.logout()


def run_lunash_command(appliance: Appliance, api: PKCS11API, command_line: str):
    """Run a single LunaSH command non-interactively."""
    handler = LunaSHCommands(appliance, api)
    try:
        parts = shlex.split(command_line)
    except ValueError as error:
        print(f"  Syntax Error: {error}")
        return
    if not parts:
        return

    # Resolve shortname
    cmd_name = parts[0].lower()
    if cmd_name in COMMAND_SHORTCUTS:
        cmd_name = COMMAND_SHORTCUTS[cmd_name]

    rest = parts[1:]
    dispatch = {
        "status": handler.cmd_status,
        "hsm": handler.cmd_hsm,
        "partition": handler.cmd_partition,
        "user": handler.cmd_user,
        "client": handler.cmd_client,
        "network": handler.cmd_network,
        "ntls": handler.cmd_ntls,
        "stc": handler.cmd_stc,
        "sysconf": handler.cmd_sysconf,
        "service": handler.cmd_service,
        "syslog": handler.cmd_syslog,
        "my": handler.cmd_my,
        "package": handler.cmd_package,
        "token": handler.cmd_token,
        "audit": handler.cmd_audit,
        "ha": handler.cmd_ha,
        "ntp": handler.cmd_ntp,
        "bond": handler.cmd_bond,
        "license": handler.cmd_license,
        "ped": handler.cmd_ped,
        "help": handler.cmd_help,
    }
    h = dispatch.get(cmd_name)
    if h:
        invoke_with_result(h, rest,
                           "Command Result : 0 (Success)",
                           "Command Result : 1 (Failure)")
    elif cmd_name in ("exit", "quit"):
        pass
    else:
        print(f"  Unknown command: {cmd_name}")
