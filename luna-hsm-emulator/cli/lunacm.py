"""Interactive lunacm shell — emulates the Thales Luna Configuration Manager.

Provides a command-line interface with tab-completion and command history
that mimics the real lunacm utility for educational purposes.
"""

import cmd
import sys
import os
import getpass

from cli.commands import CommandHandler
from pkcs11.api import PKCS11API
from storage.db import Storage
from pkcs11.constants import CKR_OK


class LunaCMShell(cmd.Cmd):
    """Interactive lunacm emulator shell."""

    intro = """
  ╔══════════════════════════════════════════════════════════════════╗
  ║         Thales Luna 7 Network HSM Emulator — lunacm             ║
  ║         Firmware 7.13.0  |  PKCS#11 v2.40  |  Training Use       ║
  ║                                                                  ║
  ║  WARNING: This is a software emulator for educational purposes    ║
  ║           only. It must NOT be used in production environments.  ║
  ╚══════════════════════════════════════════════════════════════════╝

  Type 'help' for command reference, 'exit' to quit.
"""

    prompt = "LunaCM Emulator v7.x > "

    def __init__(self, api: PKCS11API, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.handler = CommandHandler(api)

    # ------------------------------------------------------------------
    # Command dispatch
    # ------------------------------------------------------------------

    def _run(self, line: str):
        """Parse and run a command line."""
        parts = line.split()
        if not parts:
            return
        cmd_name = parts[0].lower()
        rest = parts[1:]

        dispatch = {
            "slot": self.handler.cmd_slot,
            "partition": self.handler.cmd_partition,
            "role": self.handler.cmd_role,
            "key": self.handler.cmd_key,
            "crypto": self.handler.cmd_crypto,
            "audit": self.handler.cmd_audit,
            "hsm": self.handler.cmd_hsm,
            "help": self.handler.cmd_help,
        }

        handler = dispatch.get(cmd_name)
        if handler:
            try:
                handler(rest)
            except Exception as e:
                print(f"  Error: {e}")
        elif cmd_name in ("exit", "quit", "bye"):
            print("  Exiting lunacm emulator.")
            return True
        else:
            print(f"  Unknown command: {cmd_name}. Type 'help' for available commands.")

    # ------------------------------------------------------------------
    # cmd.Cmd overrides
    # ------------------------------------------------------------------

    def default(self, line: str):
        result = self._run(line.strip())
        if result is True:
            return True  # exit

    def do_exit(self, arg):
        """Exit the emulator."""
        print("  Exiting lunacm emulator.")
        return True

    def do_quit(self, arg):
        """Exit the emulator."""
        return self.do_exit(arg)

    def do_help(self, arg):
        """Show help."""
        self.handler.cmd_help()

    # Custom command handlers that delegate to _run
    def do_slot(self, arg):
        self._run(f"slot {arg}" if arg else "slot")

    def do_partition(self, arg):
        self._run(f"partition {arg}" if arg else "partition")

    def do_role(self, arg):
        self._run(f"role {arg}" if arg else "role")

    def do_key(self, arg):
        self._run(f"key {arg}" if arg else "key")

    def do_crypto(self, arg):
        self._run(f"crypto {arg}" if arg else "crypto")

    def do_audit(self, arg):
        self._run(f"audit {arg}" if arg else "audit")

    def do_hsm(self, arg):
        self._run(f"hsm {arg}" if arg else "hsm")

    # ------------------------------------------------------------------
    # Tab completion
    # ------------------------------------------------------------------

    def completedefault(self, text, line, begidx, endidx):
        """Default completion for subcommands."""
        parts = line.split()
        if len(parts) <= 1:
            return []
        cmd_name = parts[0].lower()
        subcommands = {
            "slot": ["list", "set"],
            "partition": ["create", "delete", "list", "showinfo", "init", "changelabel", "clear", "contents", "showmechanism", "showpolicies", "changepolicy"],
            "role": ["login", "logout", "changepw", "list", "show", "init", "deactivate", "resetpw"],
            "key": ["generate", "list", "show", "delete", "wrap", "unwrap"],
            "crypto": ["encrypt", "decrypt", "sign", "verify", "digest"],
            "audit": ["log"],
            "hsm": ["show", "factoryreset", "export", "import", "firmware"],
        }
        subs = subcommands.get(cmd_name, [])
        if len(parts) == 2 or (len(parts) == 1 and not text):
            return [s for s in subs if s.startswith(text)]
        return []

    def completedefault_old(self, text, line, begidx, endidx):
        return self.completedefault(text, line, begidx, endidx)

    # ------------------------------------------------------------------
    # Empty line
    # ------------------------------------------------------------------

    def emptyline(self):
        pass

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def postloop(self):
        if self.handler.session_id is not None:
            try:
                self.handler.api.C_CloseSession(self.handler.session_id)
            except Exception:
                pass


def run_shell(api: PKCS11API):
    """Start the interactive lunacm shell."""
    shell = LunaCMShell(api)
    try:
        shell.cmdloop()
    except KeyboardInterrupt:
        print("\n  Use 'exit' to quit.")
        shell.cmdloop()
    finally:
        if shell.handler.session_id is not None:
            try:
                api.C_CloseSession(shell.handler.session_id)
            except Exception:
                pass


def run_command(api: PKCS11API, command_line: str):
    """Run a single command non-interactively."""
    handler = CommandHandler(api)
    # Parse the command line
    parts = command_line.split()
    if not parts:
        return
    cmd_name = parts[0].lower()
    rest = parts[1:]
    dispatch = {
        "slot": handler.cmd_slot,
        "partition": handler.cmd_partition,
        "role": handler.cmd_role,
        "key": handler.cmd_key,
        "crypto": handler.cmd_crypto,
        "audit": handler.cmd_audit,
        "hsm": handler.cmd_hsm,
        "help": handler.cmd_help,
    }
    h = dispatch.get(cmd_name)
    if h:
        try:
            h(rest)
        except Exception as e:
            print(f"  Error: {e}")
    elif cmd_name in ("exit", "quit"):
        pass
    else:
        print(f"  Unknown command: {cmd_name}")
