"""Command handlers for the lunacm CLI emulator.

Each handler corresponds to a lunacm command group (slot, partition,
role, key, crypto, audit, hsm).  The interactive shell in lunacm.py
dispatches to these handlers.
"""

import os
import sys
import getpass
import binascii
from typing import Optional

from pkcs11.constants import (
    CKR_OK, PKCS11Error, ckr_name, cka_name, ckm_name, cko_name, ckk_name,
    CKA_CLASS, CKA_TOKEN, CKA_LABEL, CKA_VALUE_LEN, CKA_KEY_TYPE,
    CKA_SENSITIVE, CKA_EXTRACTABLE, CKA_ENCRYPT, CKA_DECRYPT,
    CKA_SIGN, CKA_VERIFY, CKA_WRAP, CKA_UNWRAP, CKA_DERIVE,
    CKA_MODULUS_BITS, CKA_LOCAL, CKA_NEVER_EXTRACTABLE, CKA_ALWAYS_SENSITIVE,
    CKA_MODIFIABLE, CKA_COPYABLE, CKA_DESTROYABLE, CKA_PRIVATE,
    CKA_CHECK_VALUE, CKA_EC_PARAMS, CKA_EC_POINT, CKA_MODULUS, CKA_PUBLIC_EXPONENT,
    CKO_SECRET_KEY, CKO_PUBLIC_KEY, CKO_PRIVATE_KEY,
    CKK_AES, CKK_RSA, CKK_EC, CKK_DES3,
    CKM_AES_KEY_GEN, CKM_RSA_PKCS_KEY_PAIR_GEN, CKM_EC_KEY_PAIR_GEN,
    CKM_DES3_KEY_GEN,
    CKM_AES_GCM, CKM_AES_CBC, CKM_AES_ECB, CKM_AES_CTR,
    CKM_SHA256_RSA_PKCS, CKM_SHA384_RSA_PKCS, CKM_SHA512_RSA_PKCS,
    CKM_SHA256_RSA_PKCS_PSS, CKM_SHA384_RSA_PKCS_PSS, CKM_SHA512_RSA_PKCS_PSS,
    CKM_ECDSA, CKM_SHA256_HMAC, CKM_SHA512_HMAC, CKM_AES_CMAC,
    CKM_SHA_1, CKM_SHA256, CKM_SHA384, CKM_SHA512,
)
from pkcs11.mechanisms import MECHANISM_NAME_TO_ID
from pkcs11.objects import (
    make_aes_key_template, make_rsa_keypair_templates,
    make_ec_keypair_templates, make_des3_key_template, make_hmac_key_template,
)
from hsm.auth import ROLE_CO, ROLE_CU, ROLE_SO, ROLE_HSO, ROLE_MAP


class CommandHandler:
    """Handles all lunacm CLI commands."""

    def __init__(self, api, active_slot: int = None):
        self.api = api
        self.active_slot = active_slot
        self.session_id = None
        self.explain_mode = False

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def _ensure_session(self):
        """Open a session on the active slot if not already open."""
        if self.session_id is None and self.active_slot is not None:
            self.session_id = self.api.C_OpenSession(self.active_slot)
        if self.session_id is None:
            print("  Error: No active session. Use 'slot set' to select a slot.")
            return False
        return True

    def _print_explain(self, lines: list):
        """Print explanation lines if --explain is active."""
        if self.explain_mode:
            for line in lines:
                print(f"  [EXPLAIN] {line}")

    def _parse_flags(self, args: list) -> tuple:
        """Separate --explain flag from other args. Returns (args_without_explain)."""
        self.explain_mode = "--explain" in args
        return [a for a in args if a != "--explain"]

    # ------------------------------------------------------------------
    # Slot commands
    # ------------------------------------------------------------------

    def cmd_slot(self, args: list):
        """Handle 'slot' commands."""
        if not args:
            print("  Usage: slot list | slot set -slot <id>")
            return
        sub = args[0]
        if sub == "list":
            slots = self.api.C_GetSlotList()
            if not slots:
                print("  No slots/partitions available.")
                return
            print(f"  {'Slot':<8} {'Description':<40} {'Partition':<20}")
            print("  " + "-" * 70)
            for sid in slots:
                info = self.api.C_GetSlotInfo(sid)
                p = self.api.storage.get_partition(sid)
                print(f"  {sid:<8} {info['description']:<40} {p['name'] if p else 'N/A':<20}")
            if self.active_slot:
                print(f"\n  Active slot: {self.active_slot}")
            else:
                print(f"\n  No active slot set. Use 'slot set -slot <id>' to select one.")
        elif sub == "set":
            slot_id = None
            for i, a in enumerate(args):
                if a == "-slot" and i + 1 < len(args):
                    slot_id = int(args[i + 1])
            if slot_id is None:
                print("  Usage: slot set -slot <id>")
                return
            if slot_id not in self.api.C_GetSlotList():
                print(f"  Error: Slot {slot_id} does not exist.")
                return
            self.active_slot = slot_id
            if self.session_id is not None:
                self.api.C_CloseSession(self.session_id)
                self.session_id = None
            print(f"  Active slot set to {slot_id}.")
        else:
            print(f"  Unknown slot subcommand: {sub}")

    # ------------------------------------------------------------------
    # Partition commands
    # ------------------------------------------------------------------

    def cmd_partition(self, args: list):
        """Handle 'partition' commands."""
        if not args:
            print("  Usage: partition create | delete | list | showinfo | init | changelabel | clear | contents | showmechanism | showpolicies | changepolicy")
            return
        sub = args[0]
        args = self._parse_flags(args[1:])

        if sub == "create":
            name = self._get_arg(args, "-name")
            if not name:
                print("  Usage: partition create -name <name>")
                return
            slot_id = self.api.tokens.create_partition(name)
            print(f"  Partition '{name}' created. Slot ID: {slot_id}")
            self._print_explain([
                "Creating a new Luna partition (PKCS#11 token).",
                "This allocates a logical storage area on the HSM with independent",
                "authentication, key storage, and audit logging.",
            ])
        elif sub == "delete":
            name = self._get_arg(args, "-name")
            if not name:
                print("  Usage: partition delete -name <name>")
                return
            confirm = input(f"  Are you sure you want to delete partition '{name}'? (yes/no): ")
            if confirm.lower() != "yes":
                print("  Cancelled.")
                return
            self.api.tokens.delete_partition(name)
            print(f"  Partition '{name}' deleted.")
        elif sub == "list":
            print(self.api.tokens.list_partitions())
        elif sub == "showinfo":
            if self.active_slot is None:
                print("  No active slot. Use 'slot set -slot <id>' first.")
                return
            print(self.api.tokens.show_partition_info(self.active_slot))
        elif sub == "init":
            if self.active_slot is None:
                print("  No active slot. Use 'slot set -slot <id>' first.")
                return
            label = self._get_arg(args, "-label")
            print("  [PED Simulation] Enter SO PIN to initialize partition:")
            so_pin = getpass.getpass("  SO PIN: ")
            try:
                self.api.tokens.init_partition(
                    self.active_slot, so_pin, label,
                    audit=self.api.audit, session_id=self.session_id or 0
                )
                print(f"  Partition on slot {self.active_slot} initialized successfully.")
                self._print_explain([
                    "Calling C_InitToken to initialize the application partition.",
                    "This sets the SO PIN and optionally a new label.",
                    "On a real Luna 7, partition init is performed via LunaSH,",
                    "not LunaCM. We simulate it here for training purposes.",
                    "Return code: CKR_OK (0x00000000)",
                ])
            except PKCS11Error as e:
                print(f"  Error: {e}")
                self._print_explain([f"Return code: {ckr_name(e.code)} (0x{e.code:08X})"])
        elif sub == "changelabel":
            if self.active_slot is None:
                print("  No active slot. Use 'slot set -slot <id>' first.")
                return
            new_label = self._get_arg(args, "-label")
            if not new_label:
                print("  Usage: partition changelabel -label <new_label>")
                return
            try:
                self.api.tokens.change_partition_label(
                    self.active_slot, new_label,
                    audit=self.api.audit, session_id=self.session_id or 0
                )
                print(f"  Partition label changed to '{new_label}'.")
                self._print_explain([
                    "Changing a partition label updates the CKA_LABEL of the token.",
                    "This operation requires Crypto Officer (CO) authentication.",
                ])
            except PKCS11Error as e:
                print(f"  Error: {e}")
        elif sub == "clear":
            if self.active_slot is None:
                print("  No active slot. Use 'slot set -slot <id>' first.")
                return
            confirm = input("  Delete ALL objects on this partition? (yes/no): ")
            if confirm.lower() != "yes":
                print("  Cancelled.")
                return
            try:
                count = self.api.tokens.clear_partition(
                    self.active_slot, audit=self.api.audit,
                    session_id=self.session_id or 0
                )
                print(f"  Partition cleared. {count} object(s) deleted.")
                self._print_explain([
                    "Partition clear deletes all token objects (CKA_TOKEN=TRUE)",
                    "from the partition. Session objects are not affected.",
                    "This is a destructive operation and requires CO authentication.",
                ])
            except PKCS11Error as e:
                print(f"  Error: {e}")
        elif sub == "contents":
            if self.active_slot is None:
                print("  No active slot. Use 'slot set -slot <id>' first.")
                return
            print(self.api.tokens.show_partition_contents(self.active_slot))
        elif sub == "showmechanism":
            if self.active_slot is None:
                print("  No active slot. Use 'slot set -slot <id>' first.")
                return
            print(self.api.tokens.show_mechanisms(self.active_slot))
            self._print_explain([
                "This calls C_GetMechanismList and C_GetMechanismInfo for each",
                "supported mechanism on the active partition. The flags show",
                "which operations each mechanism supports (encrypt, sign, etc.).",
            ])
        elif sub == "showpolicies":
            if self.active_slot is None:
                print("  No active slot. Use 'slot set -slot <id>' first.")
                return
            print(self.api.tokens.show_policies(self.active_slot))
            self._print_explain([
                "Partition policies control security behaviors on the Luna 7.",
                "These include key extraction, cloning, PIN rules, and more.",
                "Policies are set at partition creation time and some cannot be",
                "changed afterward, ensuring security invariants are maintained.",
            ])
        elif sub == "changepolicy":
            if self.active_slot is None:
                print("  No active slot. Use 'slot set -slot <id>' first.")
                return
            policy_name = self._get_arg(args, "-name")
            value = self._get_arg(args, "-value")
            if not policy_name or value is None:
                print("  Usage: partition changepolicy -name <policy> -value <value>")
                return
            try:
                self.api.tokens.change_policy(
                    self.active_slot, policy_name, value,
                    audit=self.api.audit, session_id=self.session_id or 0
                )
                print(f"  Policy '{policy_name}' set to '{value}'.")
            except PKCS11Error as e:
                print(f"  Error: {e}")
        else:
            print(f"  Unknown partition subcommand: {sub}")

    # ------------------------------------------------------------------
    # Role / Authentication commands
    # ------------------------------------------------------------------

    def cmd_role(self, args: list):
        """Handle 'role' commands."""
        if not args:
            print("  Usage: role login | logout | changepw | list | show | init | deactivate | resetpw")
            return
        sub = args[0]

        if sub == "login":
            role_name = self._get_arg(args[1:], "-name")
            if not role_name:
                print("  Usage: role login -name <co|cu|so>")
                return
            role_name = role_name.lower()
            if role_name not in ROLE_MAP:
                print(f"  Unknown role: {role_name}. Valid: co, cu, so")
                return
            if not self._ensure_session():
                return
            # PED simulation: prompt for PIN
            print(f"  [PED Simulation] Enter PIN for role '{role_name.upper()}':")
            pin = getpass.getpass("  PIN: ")
            try:
                from pkcs11.constants import CKU_SO, CKU_USER
                user_type = CKU_SO if role_name == "so" else CKU_USER
                self.api.C_Login(self.session_id, user_type, pin)
                print(f"  Logged in as {role_name.upper()}.")
                self._print_explain([
                    f"Calling C_Login with userType={'CKU_SO' if role_name == 'so' else 'CKU_USER'}",
                    f"Role: {ROLE_MAP[role_name]}",
                    "Return code: CKR_OK (0x00000000)",
                    f"Security Note: The {role_name.upper()} role has "
                    + ("full administrative access to the partition." if role_name == "so"
                       else "key management capabilities." if role_name == "co"
                       else "cryptographic operation capabilities only."),
                ])
            except PKCS11Error as e:
                print(f"  Login failed: {e}")
                self._print_explain([
                    f"Return code: {ckr_name(e.code)} (0x{e.code:08X})",
                    f"Security Note: Failed login attempts are tracked. After",
                    f"the configured max attempts, the role PIN is locked.",
                ])
        elif sub == "logout":
            if self.session_id is None:
                print("  Not logged in.")
                return
            self.api.C_Logout(self.session_id)
            print("  Logged out.")
        elif sub == "changepw":
            role_name = self._get_arg(args[1:], "-name")
            if not role_name:
                print("  Usage: role changepw -name <co|cu|so>")
                return
            role_name = role_name.lower()
            if role_name not in ROLE_MAP:
                print(f"  Unknown role: {role_name}. Valid: co, cu, so")
                return
            if self.active_slot is None:
                print("  No active slot. Use 'slot set -slot <id>' first.")
                return
            print(f"  [PED Simulation] Changing PIN for role '{role_name.upper()}'")
            old_pin = getpass.getpass("  Old PIN: ")
            new_pin = getpass.getpass("  New PIN: ")
            confirm_pin = getpass.getpass("  Confirm new PIN: ")
            if new_pin != confirm_pin:
                print("  Error: New PINs do not match.")
                return
            try:
                self.api.auth.change_pin(self.active_slot, ROLE_MAP[role_name], old_pin, new_pin)
                print(f"  PIN changed for {role_name.upper()}.")
            except PKCS11Error as e:
                print(f"  Failed: {e}")
        elif sub == "list":
            if self.active_slot is None:
                print("  No active slot. Use 'slot set -slot <id>' first.")
                return
            print(self.api.tokens.list_roles(self.active_slot))
            self._print_explain([
                "The Luna 7 supports three roles per partition: SO, CO, and CU.",
                "Each role has different capabilities and can be independently",
                "initialized, locked, or deactivated.",
            ])
        elif sub == "show":
            role_name = self._get_arg(args[1:], "-name")
            if not role_name:
                print("  Usage: role show -name <so|co|cu>")
                return
            if self.active_slot is None:
                print("  No active slot. Use 'slot set -slot <id>' first.")
                return
            print(self.api.tokens.show_role(self.active_slot, role_name))
        elif sub == "init":
            role_name = self._get_arg(args[1:], "-name")
            if not role_name:
                print("  Usage: role init -name <co|cu>")
                return
            role_name = role_name.upper()
            if role_name not in ("CO", "CU"):
                print("  Only CO and CU roles can be initialized with 'role init'.")
                return
            if self.active_slot is None:
                print("  No active slot. Use 'slot set -slot <id>' first.")
                return
            print(f"  [PED Simulation] Set PIN for role '{role_name}':")
            pin = getpass.getpass("  New PIN: ")
            confirm = getpass.getpass("  Confirm PIN: ")
            if pin != confirm:
                print("  Error: PINs do not match.")
                return
            try:
                self.api.tokens.init_role(
                    self.active_slot, role_name, pin,
                    audit=self.api.audit, session_id=self.session_id or 0
                )
                print(f"  Role '{role_name}' initialized.")
                self._print_explain([
                    f"Role init sets the PIN for the {role_name} role.",
                    "On a real Luna 7, this requires SO authentication.",
                    "The CU role is optional and provides read-only access",
                    "to cryptographic objects for verify/decrypt operations.",
                ])
            except PKCS11Error as e:
                print(f"  Error: {e}")
        elif sub == "deactivate":
            role_name = self._get_arg(args[1:], "-name")
            if not role_name:
                print("  Usage: role deactivate -name <co|cu>")
                return
            role_name = role_name.upper()
            if self.active_slot is None:
                print("  No active slot. Use 'slot set -slot <id>' first.")
                return
            confirm = input(f"  Deactivate role '{role_name}'? This will clear its PIN. (yes/no): ")
            if confirm.lower() != "yes":
                print("  Cancelled.")
                return
            try:
                self.api.tokens.deactivate_role(
                    self.active_slot, role_name,
                    audit=self.api.audit, session_id=self.session_id or 0
                )
                print(f"  Role '{role_name}' deactivated. PIN cleared.")
                self._print_explain([
                    "Deactivating a role clears its PIN, preventing future logins.",
                    "On a real Luna 7, this requires SO authentication and is",
                    "used as a security measure to disable unused roles.",
                ])
            except PKCS11Error as e:
                print(f"  Error: {e}")
        elif sub == "resetpw":
            role_name = self._get_arg(args[1:], "-name")
            if not role_name:
                print("  Usage: role resetpw -name <co|cu>")
                return
            role_name = role_name.upper()
            if role_name not in ("CO", "CU"):
                print("  Only CO and CU roles can be reset with 'role resetpw'.")
                return
            if self.active_slot is None:
                print("  No active slot. Use 'slot set -slot <id>' first.")
                return
            print(f"  [PED Simulation] Reset PIN for role '{role_name}' (requires SO):")
            new_pin = getpass.getpass("  New PIN: ")
            confirm = getpass.getpass("  Confirm PIN: ")
            if new_pin != confirm:
                print("  Error: PINs do not match.")
                return
            try:
                self.api.tokens.reset_pin(
                    self.active_slot, role_name, new_pin,
                    audit=self.api.audit, session_id=self.session_id or 0
                )
                print(f"  PIN reset for role '{role_name}'.")
                self._print_explain([
                    "Role resetpw sets a new PIN without requiring the old one.",
                    "This is an SO-only operation on a real Luna 7, used when",
                    "a user forgets their PIN or when an account is locked.",
                    "Unlike changepw, this does NOT require the old PIN.",
                ])
            except PKCS11Error as e:
                print(f"  Error: {e}")
        else:
            print(f"  Unknown role subcommand: {sub}")

    # ------------------------------------------------------------------
    # Key commands
    # ------------------------------------------------------------------

    def cmd_key(self, args: list):
        """Handle 'key' commands."""
        if not args:
            print("  Usage: key generate | key list | key show | key delete | key wrap | key unwrap")
            return
        sub = args[0]
        rest = self._parse_flags(args[1:])

        if sub == "generate":
            self._key_generate(rest)
        elif sub == "list":
            self._key_list()
        elif sub == "show":
            label = self._get_arg(rest, "-label")
            if not label:
                print("  Usage: key show -label <name>")
                return
            self._key_show(label)
        elif sub == "delete":
            label = self._get_arg(rest, "-label")
            if not label:
                print("  Usage: key delete -label <name>")
                return
            self._key_delete(label)
        elif sub == "wrap":
            wrap_label = self._get_arg(rest, "-wrap-key")
            target_label = self._get_arg(rest, "-target-key")
            outfile = self._get_arg(rest, "-out")
            if not wrap_label or not target_label:
                print("  Usage: key wrap -wrap-key <label> -target-key <label> [-out <file>]")
                return
            self._key_wrap(wrap_label, target_label, outfile)
        elif sub == "unwrap":
            wrap_label = self._get_arg(rest, "-wrap-key")
            infile = self._get_arg(rest, "-file")
            label = self._get_arg(rest, "-label")
            if not wrap_label or not infile:
                print("  Usage: key unwrap -wrap-key <label> -file <file> [-label <name>]")
                return
            self._key_unwrap(wrap_label, infile, label or "unwrapped_key")
        else:
            print(f"  Unknown key subcommand: {sub}")

    def _key_generate(self, args: list):
        """Generate a key."""
        if not self._ensure_session():
            return
        kt = self._get_arg(args, "-kt")  # key type: aes, rsa, ec, des3
        ks = self._get_arg(args, "-ks")  # key size
        label = self._get_arg(args, "-label")
        curve = self._get_arg(args, "-curve")

        if not kt or not label:
            print("  Usage: key generate -kt <aes|rsa|ec|des3> -label <name> [-ks <size>] [-curve <name>]")
            return

        try:
            if kt.lower() == "aes":
                key_size = int(ks) if ks else 256
                template = make_aes_key_template(label, key_size)
                self._print_explain([
                    "Calling C_GenerateKey with mechanism CKM_AES_KEY_GEN",
                    "Template attributes:",
                    f"          CKA_CLASS = CKO_SECRET_KEY",
                    f"          CKA_KEY_TYPE = CKK_AES",
                    f"          CKA_VALUE_LEN = {key_size // 8} ({key_size} bits)",
                    f"          CKA_TOKEN = TRUE (persistent storage)",
                    f"          CKA_SENSITIVE = TRUE (key cannot be read in plaintext)",
                    f"          CKA_EXTRACTABLE = FALSE (key cannot leave HSM)",
                    "Return code: CKR_OK (0x00000000)",
                    "Security Note: Setting CKA_EXTRACTABLE=FALSE ensures this key",
                    "          never leaves the HSM boundary, a core HSM security guarantee.",
                ])
                handle = self.api.C_GenerateKey(self.session_id, CKM_AES_KEY_GEN, template)
                print(f"\n  Key '{label}' generated successfully. Handle: 0x{handle:08X}")

            elif kt.lower() == "rsa":
                key_size = int(ks) if ks else 2048
                priv_tmpl, pub_tmpl = make_rsa_keypair_templates(label, key_size)
                self._print_explain([
                    "Calling C_GenerateKeyPair with mechanism CKM_RSA_PKCS_KEY_PAIR_GEN",
                    "Template attributes (public):",
                    f"          CKA_CLASS = CKO_PUBLIC_KEY",
                    f"          CKA_KEY_TYPE = CKK_RSA",
                    f"          CKA_MODULUS_BITS = {key_size}",
                    f"          CKA_TOKEN = TRUE",
                    "Template attributes (private):",
                    f"          CKA_CLASS = CKO_PRIVATE_KEY",
                    f"          CKA_KEY_TYPE = CKK_RSA",
                    f"          CKA_SENSITIVE = TRUE",
                    f"          CKA_EXTRACTABLE = FALSE",
                    "Return code: CKR_OK (0x00000000)",
                    "Security Note: The private key is generated inside the HSM and",
                    "          never exposed in plaintext. CKA_EXTRACTABLE=FALSE",
                    "          prevents key extraction even by authenticated users.",
                ])
                priv_h, pub_h = self.api.C_GenerateKeyPair(
                    self.session_id, CKM_RSA_PKCS_KEY_PAIR_GEN, priv_tmpl, pub_tmpl
                )
                print(f"\n  RSA key pair '{label}' generated successfully.")
                print(f"  Private key handle: 0x{priv_h:08X}")
                print(f"  Public  key handle: 0x{pub_h:08X}")

            elif kt.lower() == "ec":
                curve_name = curve or "P-256"
                priv_tmpl, pub_tmpl = make_ec_keypair_templates(label, curve_name)
                self._print_explain([
                    "Calling C_GenerateKeyPair with mechanism CKM_EC_KEY_PAIR_GEN",
                    f"Template attributes:",
                    f"          CKA_CLASS = CKO_PUBLIC_KEY / CKO_PRIVATE_KEY",
                    f"          CKA_KEY_TYPE = CKK_EC",
                    f"          CKA_EC_PARAMS = {curve_name}",
                    f"          CKA_SENSITIVE = TRUE (private key)",
                    f"          CKA_EXTRACTABLE = FALSE (private key)",
                    "Return code: CKR_OK (0x00000000)",
                    "Security Note: EC keys provide equivalent security to RSA at",
                    "          much smaller key sizes, making them ideal for",
                    "          performance-sensitive HSM operations.",
                ])
                priv_h, pub_h = self.api.C_GenerateKeyPair(
                    self.session_id, CKM_EC_KEY_PAIR_GEN, priv_tmpl, pub_tmpl,
                    params={"curve": curve_name}
                )
                print(f"\n  EC key pair '{label}' ({curve_name}) generated successfully.")
                print(f"  Private key handle: 0x{priv_h:08X}")
                print(f"  Public  key handle: 0x{pub_h:08X}")

            elif kt.lower() == "des3":
                key_size = int(ks) if ks else 192
                template = make_des3_key_template(label, key_size)
                self._print_explain([
                    "Calling C_GenerateKey with mechanism CKM_DES3_KEY_GEN",
                    f"          CKA_KEY_TYPE = CKK_DES3",
                    f"          CKA_VALUE_LEN = {key_size // 8} bytes ({key_size} bits)",
                    "Return code: CKR_OK (0x00000000)",
                    "Security Note: 3DES is deprecated (NIST SP 800-131A). Use AES",
                    "          for all new applications. This is for legacy simulation only.",
                ])
                handle = self.api.C_GenerateKey(self.session_id, CKM_DES3_KEY_GEN, template)
                print(f"\n  3DES key '{label}' generated. Handle: 0x{handle:08X}")

            else:
                print(f"  Unknown key type: {kt}. Valid: aes, rsa, ec, des3")
        except PKCS11Error as e:
            print(f"  Error: {e}")
            self._print_explain([f"Return code: {ckr_name(e.code)} (0x{e.code:08X})"])

    def _key_list(self):
        """List all keys on the active partition."""
        if not self._ensure_session():
            return
        objs = self.api.keystore.list_objects(self.active_slot)
        if not objs:
            print("  No objects on this partition.")
            return
        print(f"  {'Handle':<12} {'Label':<25} {'Class':<15} {'Key Type':<15} {'Sensitive':<10} {'Extractable':<12}")
        print("  " + "-" * 90)
        for obj, km in objs:
            cls = cko_name(obj.object_class())
            kt = ckk_name(obj.key_type()) if obj.has(CKA_KEY_TYPE) else "N/A"
            sens = "Yes" if obj.is_sensitive() else "No"
            extr = "Yes" if obj.is_extractable() else "No"
            print(f"  0x{obj.handle:08X}   {obj.label():<25} {cls:<15} {kt:<15} {sens:<10} {extr:<12}")

    def _key_show(self, label: str):
        """Show details of a specific key."""
        if not self._ensure_session():
            return
        try:
            obj, km = self.api.keystore.retrieve_by_label(self.active_slot, label)
            print(obj.display())
        except PKCS11Error as e:
            print(f"  Error: {e}")

    def _key_delete(self, label: str):
        """Delete a key by label."""
        if not self._ensure_session():
            return
        try:
            obj, _ = self.api.keystore.retrieve_by_label(self.active_slot, label)
            confirm = input(f"  Delete key '{label}' (handle 0x{obj.handle:08X})? (yes/no): ")
            if confirm.lower() != "yes":
                print("  Cancelled.")
                return
            self.api.C_DestroyObject(self.session_id, obj.handle)
            print(f"  Key '{label}' deleted.")
        except PKCS11Error as e:
            print(f"  Error: {e}")

    def _key_wrap(self, wrap_label: str, target_label: str, outfile: str = None):
        """Wrap a key."""
        if not self._ensure_session():
            return
        try:
            wrap_obj, _ = self.api.keystore.retrieve_by_label(self.active_slot, wrap_label)
            target_obj, _ = self.api.keystore.retrieve_by_label(self.active_slot, target_label)
            # Use AES-GCM for wrapping by default
            from pkcs11.constants import CKM_AES_GCM
            wrapped = self.api.C_WrapKey(self.session_id, CKM_AES_GCM,
                                          wrap_obj.handle, target_obj.handle)
            print(f"  Key '{target_label}' wrapped with '{wrap_label}'.")
            print(f"  Wrapped key size: {len(wrapped)} bytes")
            if outfile:
                with open(outfile, "wb") as f:
                    f.write(wrapped)
                print(f"  Written to: {outfile}")
            else:
                print(f"  Wrapped data: {wrapped.hex()}")
            self._print_explain([
                "Calling C_WrapKey with mechanism CKM_AES_GCM",
                f"          Wrapping key: '{wrap_label}' (handle 0x{wrap_obj.handle:08X})",
                f"          Target key: '{target_label}' (handle 0x{target_obj.handle:08X})",
                "Return code: CKR_OK (0x00000000)",
                "Security Note: Key wrapping allows secure transport of keys between",
                "          HSMs. The wrapping key must have CKA_WRAP=TRUE and the",
                "          target key must have CKA_EXTRACTABLE=TRUE.",
            ])
        except PKCS11Error as e:
            print(f"  Error: {e}")
            self._print_explain([f"Return code: {ckr_name(e.code)} (0x{e.code:08X})"])

    def _key_unwrap(self, wrap_label: str, infile: str, label: str):
        """Unwrap a key from a file."""
        if not self._ensure_session():
            return
        try:
            wrap_obj, _ = self.api.keystore.retrieve_by_label(self.active_slot, wrap_label)
            with open(infile, "rb") as f:
                wrapped = f.read()
            from pkcs11.constants import CKM_AES_GCM, CKK_AES, CKO_SECRET_KEY
            template = {
                CKA_CLASS: CKO_SECRET_KEY,
                CKA_KEY_TYPE: CKK_AES,
                CKA_LABEL: label.encode("utf-8"),
                CKA_TOKEN: True,
                CKA_PRIVATE: True,
                CKA_SENSITIVE: True,
                CKA_EXTRACTABLE: False,
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
                CKA_MODIFIABLE: True,
                CKA_DESTROYABLE: True,
            }
            from pkcs11.constants import CKM_AES_GCM as _gcm
            handle = self.api.C_UnwrapKey(self.session_id, _gcm,
                                           wrap_obj.handle, wrapped, template)
            print(f"  Key '{label}' unwrapped. Handle: 0x{handle:08X}")
            self._print_explain([
                "Calling C_UnwrapKey with mechanism CKM_AES_GCM",
                f"          Unwrapping key: '{wrap_label}' (handle 0x{wrap_obj.handle:08X})",
                "Return code: CKR_OK (0x00000000)",
                "Security Note: Unwrapped keys inherit the CKA_EXTRACTABLE=FALSE",
                "          policy by default, preventing re-extraction.",
            ])
        except PKCS11Error as e:
            print(f"  Error: {e}")

    # ------------------------------------------------------------------
    # Crypto commands
    # ------------------------------------------------------------------

    def cmd_crypto(self, args: list):
        """Handle 'crypto' commands."""
        if not args:
            print("  Usage: crypto encrypt | crypto decrypt | crypto sign | crypto verify | crypto digest")
            return
        sub = args[0]
        rest = self._parse_flags(args[1:])

        if sub == "encrypt":
            self._crypto_encrypt(rest)
        elif sub == "decrypt":
            self._crypto_decrypt(rest)
        elif sub == "sign":
            self._crypto_sign(rest)
        elif sub == "verify":
            self._crypto_verify(rest)
        elif sub == "digest":
            self._crypto_digest(rest)
        else:
            print(f"  Unknown crypto subcommand: {sub}")

    def _crypto_encrypt(self, args: list):
        """Encrypt a file."""
        if not self._ensure_session():
            return
        label = self._get_arg(args, "-key")
        mech_name = self._get_arg(args, "-mech")
        infile = self._get_arg(args, "-in")
        outfile = self._get_arg(args, "-out")
        if not label or not mech_name or not infile:
            print("  Usage: crypto encrypt -key <label> -mech <MECH> -in <file> [-out <file>]")
            return
        mech = MECHANISM_NAME_TO_ID.get(mech_name.upper())
        if mech is None:
            print(f"  Unknown mechanism: {mech_name}")
            print(f"  Available: {', '.join(sorted(MECHANISM_NAME_TO_ID.keys()))}")
            return
        try:
            obj, km = self.api.keystore.retrieve_by_label(self.active_slot, label)
            with open(infile, "rb") as f:
                data = f.read()
            self._print_explain([
                f"Calling C_EncryptInit with mechanism {ckm_name(mech)}",
                f"          Key: '{label}' (handle 0x{obj.handle:08X})",
                f"Calling C_Encrypt with {len(data)} bytes of data",
            ])
            result = self.api.C_EncryptInit(self.session_id, mech, obj.handle)
            ct = self.api.C_Encrypt(self.session_id, data)
            if outfile:
                with open(outfile, "wb") as f:
                    f.write(ct)
                print(f"  Encrypted {len(data)} bytes -> {len(ct)} bytes. Output: {outfile}")
            else:
                print(f"  Ciphertext ({len(ct)} bytes): {ct[:64].hex()}{'...' if len(ct) > 64 else ''}")
            self._print_explain([
                "Return code: CKR_OK (0x00000000)",
                f"Security Note: Encryption with {ckm_name(mech)} ensures data",
                "          confidentiality. The key never leaves the HSM boundary.",
            ])
        except PKCS11Error as e:
            print(f"  Error: {e}")
            self._print_explain([f"Return code: {ckr_name(e.code)} (0x{e.code:08X})"])
        except FileNotFoundError:
            print(f"  Error: File not found: {infile}")

    def _crypto_decrypt(self, args: list):
        """Decrypt a file."""
        if not self._ensure_session():
            return
        label = self._get_arg(args, "-key")
        mech_name = self._get_arg(args, "-mech")
        infile = self._get_arg(args, "-in")
        outfile = self._get_arg(args, "-out")
        if not label or not mech_name or not infile:
            print("  Usage: crypto decrypt -key <label> -mech <MECH> -in <file> [-out <file>]")
            return
        mech = MECHANISM_NAME_TO_ID.get(mech_name.upper())
        if mech is None:
            print(f"  Unknown mechanism: {mech_name}")
            return
        try:
            obj, km = self.api.keystore.retrieve_by_label(self.active_slot, label)
            with open(infile, "rb") as f:
                data = f.read()
            self._print_explain([
                f"Calling C_DecryptInit with mechanism {ckm_name(mech)}",
                f"          Key: '{label}' (handle 0x{obj.handle:08X})",
                f"Calling C_Decrypt with {len(data)} bytes of ciphertext",
            ])
            self.api.C_DecryptInit(self.session_id, mech, obj.handle)
            pt = self.api.C_Decrypt(self.session_id, data)
            if outfile:
                with open(outfile, "wb") as f:
                    f.write(pt)
                print(f"  Decrypted {len(data)} bytes -> {len(pt)} bytes. Output: {outfile}")
            else:
                try:
                    print(f"  Plaintext: {pt.decode('utf-8')}")
                except UnicodeDecodeError:
                    print(f"  Plaintext ({len(pt)} bytes): {pt[:64].hex()}{'...' if len(pt) > 64 else ''}")
            self._print_explain([
                "Return code: CKR_OK (0x00000000)",
                "Security Note: Decryption is performed inside the HSM. The key",
                "          material never appears in the host process memory.",
            ])
        except PKCS11Error as e:
            print(f"  Error: {e}")
        except FileNotFoundError:
            print(f"  Error: File not found: {infile}")

    def _crypto_sign(self, args: list):
        """Sign a file."""
        if not self._ensure_session():
            return
        label = self._get_arg(args, "-key")
        mech_name = self._get_arg(args, "-mech")
        infile = self._get_arg(args, "-in")
        outfile = self._get_arg(args, "-out")
        if not label or not mech_name or not infile:
            print("  Usage: crypto sign -key <label> -mech <MECH> -in <file> [-out <file>]")
            return
        mech = MECHANISM_NAME_TO_ID.get(mech_name.upper())
        if mech is None:
            print(f"  Unknown mechanism: {mech_name}")
            return
        try:
            obj, km = self.api.keystore.retrieve_by_label(self.active_slot, label)
            with open(infile, "rb") as f:
                data = f.read()
            self._print_explain([
                f"Calling C_SignInit with mechanism {ckm_name(mech)}",
                f"          Key: '{label}' (handle 0x{obj.handle:08X})",
                f"Calling C_Sign with {len(data)} bytes of data",
            ])
            self.api.C_SignInit(self.session_id, mech, obj.handle)
            sig = self.api.C_Sign(self.session_id, data)
            if outfile:
                with open(outfile, "wb") as f:
                    f.write(sig)
                print(f"  Signed {len(data)} bytes. Signature ({len(sig)} bytes) -> {outfile}")
            else:
                print(f"  Signature ({len(sig)} bytes): {sig.hex()}")
            self._print_explain([
                "Return code: CKR_OK (0x00000000)",
                "Security Note: Digital signatures prove authenticity and integrity.",
                "          The private signing key never leaves the HSM, ensuring",
                "          only authorized code can produce valid signatures.",
            ])
        except PKCS11Error as e:
            print(f"  Error: {e}")
        except FileNotFoundError:
            print(f"  Error: File not found: {infile}")

    def _crypto_verify(self, args: list):
        """Verify a signature."""
        if not self._ensure_session():
            return
        label = self._get_arg(args, "-key")
        mech_name = self._get_arg(args, "-mech")
        infile = self._get_arg(args, "-in")
        sigfile = self._get_arg(args, "-sig")
        if not label or not mech_name or not infile or not sigfile:
            print("  Usage: crypto verify -key <label> -mech <MECH> -in <file> -sig <file>")
            return
        mech = MECHANISM_NAME_TO_ID.get(mech_name.upper())
        if mech is None:
            print(f"  Unknown mechanism: {mech_name}")
            return
        try:
            obj, km = self.api.keystore.retrieve_by_label(self.active_slot, label)
            with open(infile, "rb") as f:
                data = f.read()
            with open(sigfile, "rb") as f:
                sig = f.read()
            self._print_explain([
                f"Calling C_VerifyInit with mechanism {ckm_name(mech)}",
                f"          Key: '{label}' (handle 0x{obj.handle:08X})",
                f"Calling C_Verify with {len(data)} bytes of data and {len(sig)} bytes of signature",
            ])
            self.api.C_VerifyInit(self.session_id, mech, obj.handle)
            result = self.api.C_Verify(self.session_id, data, sig)
            if result:
                print("  Signature VALID.")
            else:
                print("  Signature INVALID.")
            self._print_explain([
                "Return code: CKR_OK (0x00000000)",
                "Security Note: Signature verification uses the public key, which",
                "          can be freely distributed. Only the HSM holding the",
                "          private key can create valid signatures.",
            ])
        except PKCS11Error as e:
            print(f"  Verification FAILED: {e}")
            self._print_explain([f"Return code: {ckr_name(e.code)} (0x{e.code:08X})"])
        except FileNotFoundError as e:
            print(f"  Error: File not found: {e.filename}")

    def _crypto_digest(self, args: list):
        """Compute a hash digest."""
        if not self._ensure_session():
            return
        mech_name = self._get_arg(args, "-mech")
        infile = self._get_arg(args, "-in")
        if not mech_name or not infile:
            print("  Usage: crypto digest -mech <SHA256|SHA384|SHA512|SHA_1> -in <file>")
            return
        mech = MECHANISM_NAME_TO_ID.get(mech_name.upper())
        if mech is None:
            print(f"  Unknown mechanism: {mech_name}")
            return
        try:
            with open(infile, "rb") as f:
                data = f.read()
            self._print_explain([
                f"Calling C_DigestInit with mechanism {ckm_name(mech)}",
                f"Calling C_Digest with {len(data)} bytes of data",
            ])
            self.api.C_DigestInit(self.session_id, mech)
            result = self.api.C_Digest(self.session_id, data)
            print(f"  Digest ({len(result)} bytes): {result.hex()}")
            self._print_explain([
                "Return code: CKR_OK (0x00000000)",
                "Security Note: Hashing is a one-way function. Use digest mechanisms",
                "          combined with signing (e.g., SHA256_RSA_PKCS) for",
                "          authenticated integrity verification.",
            ])
        except PKCS11Error as e:
            print(f"  Error: {e}")
        except FileNotFoundError:
            print(f"  Error: File not found: {infile}")

    # ------------------------------------------------------------------
    # Audit commands
    # ------------------------------------------------------------------

    def cmd_audit(self, args: list):
        """Handle 'audit' commands."""
        if not args:
            print("  Usage: audit log show | audit log clear | audit log verify")
            return
        if args[0] == "log":
            if len(args) < 2:
                print("  Usage: audit log show | audit log clear | audit log verify")
                return
            sub = args[1]
            if sub == "show":
                print(self.api.audit.show())
            elif sub == "clear":
                confirm = input("  Clear all audit entries? (yes/no): ")
                if confirm.lower() == "yes":
                    self.api.audit.clear()
                    print("  Audit log cleared.")
                else:
                    print("  Cancelled.")
            elif sub == "verify":
                valid = self.api.audit.verify_chain()
                print(f"  Audit chain integrity: {'VERIFIED' if valid else 'BROKEN'}")
            else:
                print(f"  Unknown audit log subcommand: {sub}")
        else:
            print(f"  Unknown audit subcommand: {args[0]}")

    # ------------------------------------------------------------------
    # HSM commands
    # ------------------------------------------------------------------

    def cmd_hsm(self, args: list):
        """Handle 'hsm' commands."""
        if not args:
            print("  Usage: hsm show | hsm factoryreset | hsm export | hsm import | hsm firmware <subcommand>")
            return
        sub = args[0]
        if sub == "show":
            info = self.api.tokens.get_hsm_info()
            fw_info = self.api.tokens.get_firmware_info()
            print(f"  Model:           {info['model']}")
            print(f"  Firmware:        {info['firmware']}")
            if fw_info["update_available"]:
                print(f"  Latest Firmware: {fw_info['latest_version']} (update available)")
            else:
                print(f"  Latest Firmware: {fw_info['latest_version']} (up to date)")
            print(f"  Serial:          {info['serial']}")
            print(f"  Partitions:      {info['partition_count']} / {info['max_partitions']}")
            print(f"  Crypto Provider: OpenSSL (via pyca/cryptography)")
            print(f"  PKCS#11 Version: v2.40")
            print(f"  Upgrades Done:   {len(fw_info['history'])}")
        elif sub == "firmware":
            self._hsm_firmware(args[1:])
        elif sub == "factoryreset":
            confirm = input("  WARNING: This will delete ALL partitions, keys, and audit logs.\n  Type 'FACTORYRESET' to confirm: ")
            if confirm == "FACTORYRESET":
                self.api.tokens.factory_reset()
                self.active_slot = None
                self.session_id = None
                print("  HSM reset to factory defaults.")
            else:
                print("  Cancelled.")
        elif sub == "export":
            outfile = self._get_arg(args[1:], "-file")
            if not outfile:
                print("  Usage: hsm export -file <path>")
                return
            self.api.storage.export_state(outfile)
            print(f"  HSM state exported to {outfile}")
        elif sub == "import":
            infile = self._get_arg(args[1:], "-file")
            if not infile:
                print("  Usage: hsm import -file <path>")
                return
            self.api.storage.import_state(infile)
            print(f"  HSM state imported from {infile}")
        else:
            print(f"  Unknown hsm subcommand: {sub}")

    def _hsm_firmware(self, args: list):
        """Handle 'hsm firmware' subcommands."""
        if not args:
            print("  Usage: hsm firmware show | hsm firmware list | hsm firmware upgrade -version <ver> | hsm firmware rollback | hsm firmware history")
            return
        sub = args[0]
        rest = self._parse_flags(args[1:])

        if sub == "show":
            info = self.api.tokens.get_firmware_info()
            print(f"  Current Firmware:  {info['current_version']}")
            print(f"  Latest Firmware:   {info['latest_version']}")
            print(f"  Update Available:  {'Yes' if info['update_available'] else 'No'}}")
            print(f"  Available Versions: {info['available_count']}")
            print(f"  Upgrades Performed: {len(info['history'])}")
            self._print_explain([
                "Real HSM firmware contains the cryptographic implementation,",
                "secure boot loader, and access control logic. Updating firmware",
                "on a real Luna 7 requires a signed firmware image from Thales,",
                "a maintenance window, and often a PED-authenticated session.",
            ])

        elif sub == "list":
            firmwares = self.api.tokens.list_available_firmwares()
            current = self.api.tokens._get_firmware_version()
            print(f"  {'Version':<12} {'Release Date':<14} {'Status':<12} {'Notes':<50}")
            print("  " + "-" * 90)
            for fw in firmwares:
                if fw["installed"]:
                    status = "* INSTALLED"
                elif fw["upgradeable"]:
                    status = "upgrade"
                else:
                    status = "older"
                notes = fw["notes"][:50]
                print(f"  {fw['version']:<12} {fw['date']:<14} {status:<12} {notes}")
            print(f"\n  * = current firmware ({current})")
            self._print_explain([
                "Firmware versions are cryptographically signed by the vendor.",
                "Only versions present in the catalog can be installed.",
                "Downgrades are possible but may require special authorization.",
            ])

        elif sub == "upgrade":
            target = self._get_arg(rest, "-version")
            if not target:
                print("  Usage: hsm firmware upgrade -version <version>")
                print("  Use 'hsm firmware list' to see available versions.")
                return

            # Run pre-checks and display them
            print(f"  Running pre-upgrade checks for firmware {target}...\n")
            pre = self.api.tokens.check_firmware_upgrade(target)
            for check_name, passed, detail in pre["checks"]:
                status = "PASS" if passed else "FAIL"
                print(f"    [{status}] {check_name}: {detail}")
            if pre["warnings"]:
                print()
                for w in pre["warnings"]:
                    print(f"    [WARN] {w}")
            print()

            if not pre["can_upgrade"]:
                print(f"  Cannot upgrade: pre-checks failed.")
                self._print_explain([
                    "Pre-upgrade checks verify that the HSM is in a safe state",
                    "for firmware modification. On a real Luna 7, this includes",
                    "checking for active sessions, audit chain integrity, and",
                    "that the firmware image is properly signed.",
                ])
                return

            # Confirm
            confirm = input(f"  Upgrade firmware from {pre['current_version']} to {target}? (yes/no): ")
            if confirm.lower() != "yes":
                print("  Upgrade cancelled.")
                return

            # Perform upgrade with staged progress
            print(f"\n  Starting firmware upgrade: {pre['current_version']} -> {target}")
            print("  " + "-" * 50)
            result = self.api.tokens.perform_firmware_upgrade(target, audit=self.api.audit)
            for stage_name, status in result["stages"]:
                icon = "[OK]" if status == "OK" else "[FAIL]"
                print(f"    {icon:<7} {stage_name}")
            print("  " + "-" * 50)

            if result["success"]:
                print(f"\n  Firmware upgrade successful: {result['previous_version']} -> {result['new_version']}")
                self._print_explain([
                    "Firmware upgrade stages:",
                    "  1. backup       - Snapshot current HSM state",
                    "  2. download     - Fetch signed firmware image",
                    "  3. verify_signature - Verify vendor signature",
                    "  4. maintenance_mode - Suspend normal operations",
                    "  5. flash        - Write firmware to secure storage",
                    "  6. reboot       - Restart HSM with new firmware",
                    "  7. post_verify  - Confirm new version is active",
                    "",
                    "Security Note: On a real Luna 7, the firmware image is",
                    "signed by Thales and verified by the HSM's secure boot",
                    "loader. The HSM will refuse to boot an unsigned or",
                    "tampered firmware image.",
                ])
            else:
                print(f"\n  Firmware upgrade FAILED: {result['error']}")
                self._print_explain([
                    "If a firmware upgrade fails during the flash stage on a",
                    "real HSM, the device enters a fail-safe recovery mode.",
                    "Use 'hsm firmware rollback' to revert to the previous version.",
                ])

        elif sub == "rollback":
            history = self.api.tokens._get_firmware_history()
            if not history:
                print("  No firmware history available for rollback.")
                return
            last = history[-1]
            print(f"  Last upgrade: {last['from_version']} -> {last['to_version']}")
            confirm = input(f"  Roll back to {last['from_version']}? (yes/no): ")
            if confirm.lower() != "yes":
                print("  Rollback cancelled.")
                return

            result = self.api.tokens.rollback_firmware(audit=self.api.audit)
            if result["success"]:
                print(f"\n  Firmware rolled back: {result['previous_version']} -> {result['new_version']}")
                self._print_explain([
                    "Rollback restores the previous firmware version.",
                    "On a real Luna 7, rollback is a privileged operation",
                    "that requires HSO authentication and is audited.",
                ])
            else:
                print(f"\n  Rollback failed: {result['error']}")

        elif sub == "history":
            print(self.api.tokens.show_firmware_history())
            self._print_explain([
                "Every firmware upgrade is recorded in the audit log and",
                "in the firmware history table. This provides a complete",
                "provenance trail for compliance and forensic purposes.",
            ])

        else:
            print(f"  Unknown firmware subcommand: {sub}")
            print("  Available: show, list, upgrade, rollback, history")

    # ------------------------------------------------------------------
    # Help
    # ------------------------------------------------------------------

    def cmd_help(self, args: list = None):
        """Show help."""
        print("""
  LunaCM Emulator v7.x — Command Reference

  Slot/Partition Management:
    slot list                          List all slots/partitions
    slot set -slot <id>                Set active slot
    partition create -name <name>      Create a new partition
    partition delete -name <name>      Delete a partition
    partition list                     List all partitions
    partition showinfo                 Show partition details
    partition init [-label <label>]     Initialize the active partition (set SO PIN)
    partition changelabel -label <l>   Change partition label
    partition clear                    Delete all objects on partition
    partition contents                 Show all objects on partition
    partition showmechanism            Show available PKCS#11 mechanisms
    partition showpolicies             Show partition policies
    partition changepolicy -name <p> -value <v>  Change a partition policy

  Authentication:
    role login -name <co|cu|so>        Login as a role
    role logout                        Logout current role
    role changepw -name <role>         Change role password (requires old PIN)
    role list                          List all roles on the partition
    role show -name <so|co|cu>         Show state of a specific role
    role init -name <co|cu>            Initialize a role (set PIN)
    role deactivate -name <co|cu>      Deactivate a role (clear PIN)
    role resetpw -name <co|cu>         Reset role PIN (SO only, no old PIN needed)

  Key Operations:
    key generate -kt <aes|rsa|ec|des3> -label <name> [-ks <size>] [-curve <name>]
    key list                           List all key objects
    key show -label <name>             Show key attributes
    key delete -label <name>           Delete a key
    key wrap -wrap-key <label> -target-key <label> [-out <file>]
    key unwrap -wrap-key <label> -file <file> [-label <name>]

  Cryptographic Operations:
    crypto encrypt -key <label> -mech <MECH> -in <file> [-out <file>]
    crypto decrypt -key <label> -mech <MECH> -in <file> [-out <file>]
    crypto sign -key <label> -mech <MECH> -in <file> [-out <file>]
    crypto verify -key <label> -mech <MECH> -in <file> -sig <file>
    crypto digest -mech <MECH> -in <file>

  Audit & Logging:
    audit log show                     Display audit log
    audit log clear                    Clear audit log
    audit log verify                   Verify hash chain integrity

  HSM Info:
    hsm show                           Show HSM firmware/model info
    hsm factoryreset                   Reset HSM to factory defaults
    hsm export -file <path>            Export HSM state
    hsm import -file <path>            Import HSM state
    hsm firmware show                  Show current firmware info
    hsm firmware list                  List all available firmware versions
    hsm firmware upgrade -version <v>  Upgrade firmware to specified version
    hsm firmware rollback              Roll back to previous firmware
    hsm firmware history               Show firmware upgrade history

  Other:
    help                               Show this help
    exit / quit                        Exit the emulator

  Add --explain to any command for PKCS#11 educational output.
  Example: key generate -kt aes -ks 256 -label mykey --explain
""")

    # ------------------------------------------------------------------
    # Arg parsing helper
    # ------------------------------------------------------------------

    @staticmethod
    def _get_arg(args: list, flag: str) -> Optional[str]:
        """Extract -flag value from args list."""
        for i, a in enumerate(args):
            if a == flag and i + 1 < len(args):
                return args[i + 1]
        return None
