"""Interactive lunacm shell — emulates the Thales Luna Configuration Manager.

Provides a command-line interface with tab-completion and command history
that mimics the real lunacm utility for educational purposes.
"""

import cmd
import shlex
import sys
import os
import getpass

from cli.commands import CommandHandler
from cli.output import invoke_with_result
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

    prompt = "lunacm:> "

    def __init__(self, api: PKCS11API, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.handler = CommandHandler(api)

    # ------------------------------------------------------------------
    # Command dispatch
    # ------------------------------------------------------------------

    def _run(self, line: str):
        """Parse and run a command line."""
        try:
            parts = shlex.split(line)
        except ValueError as error:
            print(f"  Syntax Error: {error}")
            return
        if not parts:
            return
        aliases = {"a": "appid", "ccfg": "clientconfig", "f": "file",
                   "ha": "hagroup", "par": "partition", "p": "ped",
                   "rb": "remotebackup", "ro": "role", "s": "slot",
                   "r": "srk", "stcc": "stcconfig"}
        cmd_name = aliases.get(parts[0].lower(), parts[0].lower())
        rest = parts[1:]

        dispatch = {
            "appid": self.handler.cmd_unavailable,
            "clientconfig": self.handler.cmd_unavailable,
            "file": self.handler.cmd_unavailable,
            "hagroup": self.handler.cmd_hagroup,
            "partition": self.handler.cmd_partition,
            "ped": self.handler.cmd_unavailable,
            "remotebackup": self.handler.cmd_unavailable,
            "role": self.handler.cmd_role,
            "slot": self.handler.cmd_slot,
            "srk": self.handler.cmd_unavailable,
            "stc": self.handler.cmd_unavailable,
            "stcconfig": self.handler.cmd_unavailable,
            "stm": self.handler.cmd_unavailable,
            "help": self.handler.cmd_help,
            "?": self.handler.cmd_help,
        }

        handler = dispatch.get(cmd_name)
        if handler:
            invoke_with_result(handler, rest,
                               "Command Result : No Error",
                               "Command Result : 1 (Failure)")
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

    # ------------------------------------------------------------------
    # Tab completion
    # ------------------------------------------------------------------

    def completenames(self, text, *ignored):
        """Real LunaCM does not provide partial-command tab completion."""
        return []

    def completedefault(self, text, line, begidx, endidx):
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
        for session_id in set(self.handler._slot_sessions.values()):
            try:
                self.handler.api.C_CloseSession(session_id)
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
        for session_id in set(shell.handler._slot_sessions.values()):
            try:
                api.C_CloseSession(session_id)
            except Exception:
                pass


def run_command(api: PKCS11API, command_line: str):
    """Run a single command non-interactively."""
    handler = CommandHandler(api)
    try:
        parts = shlex.split(command_line)
    except ValueError as error:
        print(f"  Syntax Error: {error}")
        return
    if not parts:
        return
    aliases = {"a": "appid", "ccfg": "clientconfig", "f": "file",
               "ha": "hagroup", "par": "partition", "p": "ped",
               "rb": "remotebackup", "ro": "role", "s": "slot",
               "r": "srk", "stcc": "stcconfig"}
    cmd_name = aliases.get(parts[0].lower(), parts[0].lower())
    rest = parts[1:]
    dispatch = {
        "appid": handler.cmd_unavailable, "audit": handler.cmd_audit,
        "clientconfig": handler.cmd_unavailable, "file": handler.cmd_unavailable,
        "hagroup": handler.cmd_hagroup, "hsm": handler.cmd_hsm,
        "partition": handler.cmd_partition, "ped": handler.cmd_unavailable,
        "remotebackup": handler.cmd_unavailable, "role": handler.cmd_role,
        "slot": handler.cmd_slot, "srk": handler.cmd_unavailable,
        "stc": handler.cmd_unavailable, "stcconfig": handler.cmd_unavailable,
        "stm": handler.cmd_unavailable, "help": handler.cmd_help,
        "?": handler.cmd_help,
    }
    h = dispatch.get(cmd_name)
    if h:
        invoke_with_result(h, rest,
                           "Command Result : No Error",
                           "Command Result : 1 (Failure)")
    elif cmd_name in ("exit", "quit"):
        pass
    else:
        print(f"  Unknown command: {cmd_name}")
