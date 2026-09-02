#!/usr/bin/env python3
"""
Thales Luna 7 Network HSM Emulator — Main Entry Point

This is a software emulator for educational and training purposes only.
It must NOT be used in production environments.

Usage:
  Interactive mode:   python hsm_emulator.py
  Single command:     python hsm_emulator.py -c "slot list"
  Initialize HSM:     python hsm_emulator.py --init
  Show help:          python hsm_emulator.py --help

The emulator provides:
  - Full PKCS#11 v2.40 API surface
  - Luna 7 partition management and authentication model
  - Real cryptographic operations via pyca/cryptography (OpenSSL)
  - Interactive lunacm CLI shell
  - Encrypted SQLite persistent storage
  - Hash-chained audit logging
  - Educational --explain mode for PKCS#11 operations

DISCLAIMER: This is a software emulator. It does not provide the physical
security guarantees of a real Hardware Security Module. All key material
is stored in software and is only as secure as the host system.
"""

import sys
import os
import argparse
import getpass

# Ensure the emulator directory is on the Python path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from pkcs11.api import PKCS11API
from storage.db import Storage
from cli.lunacm import run_shell, run_command
from pkcs11.constants import CKR_OK


BANNER = """
  ╔══════════════════════════════════════════════════════════════════╗
  ║         Thales Luna 7 Network HSM Emulator                      ║
  ║         Firmware 7.13.0  |  PKCS#11 v2.40  |  Training Use       ║
  ║                                                                  ║
  ║  WARNING: Software emulator for educational purposes ONLY.       ║
  ║           NOT for production use. No hardware security boundary. ║
  ╚══════════════════════════════════════════════════════════════════╝
"""


def get_master_password() -> str:
    """Prompt for the HSM master password (simulates HSM boot PIN)."""
    print(BANNER)
    print("  The HSM emulator requires a master password to unlock encrypted storage.")
    print("  This simulates the HSM boot-time authentication.")
    print()
    password = getpass.getpass("  Master password: ")
    confirm = getpass.getpass("  Confirm password: ")
    if password != confirm:
        print("  Error: Passwords do not match.")
        sys.exit(1)
    return password


def main():
    parser = argparse.ArgumentParser(
        description="Thales Luna 7 Network HSM Emulator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python hsm_emulator.py                    # Start interactive shell
  python hsm_emulator.py -c "slot list"     # Run single command
  python hsm_emulator.py --init             # Initialize new HSM instance
  python hsm_emulator.py --db /tmp/test.db  # Use custom database path
""",
    )
    parser.add_argument(
        "-c", "--command", type=str, default=None,
        help="Run a single command and exit (non-interactive mode)",
    )
    parser.add_argument(
        "--init", action="store_true",
        help="Initialize a new HSM instance (set master password, create default partition)",
    )
    parser.add_argument(
        "--db", type=str, default=None,
        help="Path to the HSM database file (default: ~/.luna_hsm_emulator/hsm.db)",
    )
    parser.add_argument(
        "--password", type=str, default=None,
        help="Master password (for scripting; will prompt if not provided)",
    )
    parser.add_argument(
        "--version", action="version", version="Luna 7 HSM Emulator v7.13.0 (PKCS#11 v2.40)",
    )

    args = parser.parse_args()

    # Determine master password
    if args.password:
        master_password = args.password
    elif args.init:
        master_password = get_master_password()
    else:
        # Try to use existing — prompt for password
        print(BANNER)
        master_password = getpass.getpass("  Master password (or press Enter for first-time init): ")
        if not master_password:
            master_password = get_master_password()

    # Create storage and API
    db_path = args.db
    storage = Storage(db_path=db_path, master_password=master_password)
    api = PKCS11API(storage)

    # Initialize
    api.C_Initialize()

    if args.init:
        # Create a default partition
        print("\n  Initializing HSM emulator...")
        # Set HSM metadata
        api.storage.set_meta("model", "Luna Network HSM 7")
        api.storage.set_meta("firmware", "7.13.0")
        api.storage.set_meta("initialized", "1")

        # Create default partition
        slot_id = api.tokens.create_partition("partition1", "Default Partition")
        print(f"  Default partition 'partition1' created. Slot ID: {slot_id}")

        # Set SO PIN
        so_pin = getpass.getpass("\n  Set Security Officer (SO) PIN: ")
        api.tokens.init_token(slot_id, so_pin, "Default Partition")
        print(f"  SO PIN set for partition 'partition1'.")

        # Set CO PIN
        co_pin = getpass.getpass("  Set Crypto Officer (CO) PIN: ")
        api.tokens.init_pin(slot_id, co_pin, "CO")
        print(f"  CO PIN set for partition 'partition1'.")

        print("\n  HSM initialization complete!")
        print(f"  Database: {storage.db_path}")
        print("\n  You can now start the emulator with:")
        print(f"    python hsm_emulator.py --password '{master_password}'")
        api.C_Finalize()
        return

    # Run
    if args.command:
        run_command(api, args.command)
        api.C_Finalize()
    else:
        run_shell(api)
        api.C_Finalize()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n  Interrupted.")
        sys.exit(1)
    except Exception as e:
        print(f"\n  Fatal error: {e}")
        sys.exit(1)
