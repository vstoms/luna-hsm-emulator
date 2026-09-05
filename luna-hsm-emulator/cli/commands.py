"""Command handlers for the lunacm CLI emulator.

The interactive shell dispatches the documented LunaCM command groups to
handlers here. Some legacy handlers remain as internal test/API helpers but
are intentionally not exposed as top-level LunaCM commands.
"""

import os
import sys
import getpass
import binascii
from typing import Optional

from cli.prompts import confirm_proceed

from pkcs11.constants import (
    CKR_OK, CKU_USER, PKCS11Error, ckr_name, cka_name, ckm_name, cko_name, ckk_name,
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
from hsm.domain import CloningDomainError
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
        self._slot_sessions = {}
        self.explain_mode = False

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def _ensure_session(self):
        """Open a session on the active slot if not already open."""
        self.api._check_device()
        self._slot_sessions = {slot: sid for slot, sid in self._slot_sessions.items()
                               if sid in self.api.sessions._sessions}
        if self.session_id not in self.api.sessions._sessions:
            self.session_id = None
        if self.session_id is None and self.active_slot is not None:
            self.session_id = self._slot_sessions.get(self.active_slot)
            if self.session_id is None:
                self.session_id = self.api.C_OpenSession(self.active_slot, include_members=True)
                self._slot_sessions[self.active_slot] = self.session_id
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
        self.explain_mode = any(argument.lower() == "--explain" for argument in args)
        return [argument for argument in args if argument.lower() != "--explain"]

    # ------------------------------------------------------------------
    # Slot commands
    # ------------------------------------------------------------------

    def cmd_slot(self, args: list):
        """Handle 'slot' commands."""
        if not args:
            print("  Usage: slot list | slot set -slot <id>")
            return
        sub = args[0].lower()
        if sub == "list":
            slots = self.api.C_GetSlotList(include_members=True)
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
            if slot_id not in self.api.C_GetSlotList(include_members=True):
                print(f"  Error: Slot {slot_id} does not exist.")
                return
            self.active_slot = slot_id
            # LunaCM preserves each slot's session/login state while switching.
            self.session_id = self._slot_sessions.get(slot_id)
            print(f"  Current Slot Id: {slot_id}")
        else:
            print(f"  Unknown slot subcommand: {sub}")

    # ------------------------------------------------------------------
    # Partition commands
    # ------------------------------------------------------------------

    def cmd_partition(self, args: list):
        """Handle 'partition' commands."""
        if not args:
            print("  Usage: partition create | delete | list | showinfo | init | changelabel | clear | contents |")
            print("         showmechanism | showpolicies | changepolicy | policytemplate | domain | clone")
            return
        sub = args[0].lower()
        args = self._parse_flags(args[1:])

        if sub == "create":
            name = self._get_arg(args, "-name")
            if not name:
                print("  Usage: partition create -name <name>")
                return
            partition_type = (self._get_arg(args, "-type") or "ppso").upper()
            max_objects = int(self._get_arg(args, "-maxobjects") or 1024)
            max_storage = int(self._get_arg(args, "-storage") or 1048576)
            slot_id = self.api.tokens.create_partition(
                name, max_objects=max_objects, max_storage=max_storage,
                partition_type=partition_type)
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
            print("  Error: Partition deletion requires HSM SO authorization in LunaSH.")
            print("  Use: partition delete -name <name> from an HSM SO-authenticated LunaSH session.")
        elif sub == "list":
            print(self.api.tokens.list_partitions())
        elif sub in ("showinfo", "show"):
            requested = self._get_arg(args, "-partition")
            if requested:
                partition = self.api.storage.get_partition_by_name(requested)
                if not partition:
                    print(f"  Partition '{requested}' not found.")
                    return
                print(self.api.tokens.show_partition_info(partition["slot_id"]))
                return
            if self.active_slot is None:
                print("  No active slot. Use 'slot set -slot <id>' first.")
                return
            print(self.api.tokens.show_partition_info(self.active_slot))
        elif sub == "init":
            if self.active_slot is None:
                print("  No active slot. Use 'slot set -slot <id>' first.")
                return
            label = self._get_arg(args, "-label")
            if not confirm_proceed("Initializing the partition sets its PO credential and cloning domain.",
                                   force=self._has_flag(args, "-force", "-f")):
                print("  Command aborted.")
                return
            print("  [PED Simulation] Enter PO credential and cloning domain:")
            so_pin = getpass.getpass("  PO password: ")
            domain = getpass.getpass("  Cloning domain: ")
            try:
                self.api.tokens.init_partition(
                    self.active_slot, so_pin, label, domain,
                    audit=self.api.audit, session_id=self.session_id or 0
                )
                print(f"  Partition on slot {self.active_slot} initialized successfully.")
                self._print_explain([
                    "Calling C_InitToken to initialize the application partition.",
                    "This sets the PO credential and optionally a new label.",
                    "The PO credential and independent cloning domain are now initialized.",
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
        elif sub == "smkclone":
            if not self.session_id or self.api.auth.get_role(self.session_id) != ROLE_CO:
                print("  Error: Source partition CO login is required.")
                return
            destination = self._get_arg(args, "-slot", "-sl")
            if self.active_slot is None or destination is None:
                print("  Usage: partition smkclone -slot <destination_slot> -password <CO_password> [-force]")
                return
            if not confirm_proceed("This command overwrites the SMK in the target partition.",
                                   force=self._has_flag(args, "-force", "-f")):
                print("  Command aborted.")
                return
            password = self._get_arg(args, "-password", "-p") or getpass.getpass(
                "  Target CO password: ")
            target_session = None
            try:
                target_session = self.api.C_OpenSession(int(destination))
                self.api.C_Login(target_session, CKU_USER, password)
                result = self.api.tokens.sks.clone_smk(self.active_slot, int(destination))
                print(f"  SMK cloned using {result['cloning_protocol']}; generation {result['generation']}.")
            except (PKCS11Error, CloningDomainError) as error:
                print(f"  Error: {error}")
            finally:
                if target_session is not None:
                    self.api.C_CloseSession(target_session)
        elif sub == "smkrollover":
            if self.active_slot is None:
                print("  No active slot. Use 'slot set -slot <id>' first.")
                return
            if not self.session_id or self.api.auth.get_role(self.session_id) != ROLE_CO:
                print("  Error: Partition CO login is required.")
                return
            start = self._has_flag(args, "-start", "-s")
            end = self._has_flag(args, "-end", "-e")
            if not start and not end:
                print("  Usage: partition smkrollover [-start|-s] [-end|-e] [-force]")
                return
            if not confirm_proceed("SMK rollover changes or deletes SMK material.",
                                   force=self._has_flag(args, "-force", "-f")):
                print("  Command aborted.")
                return
            try:
                if start:
                    result = self.api.tokens.sks.rollover_start(self.active_slot)
                    if end:
                        result = self.api.tokens.sks.rollover_end(self.active_slot)
                else:
                    result = self.api.tokens.sks.rollover_end(self.active_slot)
                print(f"  SMK generation: {result['generation']}; rollover active: {result['rollover_active']}")
            except PKCS11Error as error:
                print(f"  Error: {error}")
        elif sub == "domainlist":
            if self.active_slot is None:
                print("  No active slot. Use 'slot set -slot <id>' first.")
                return
            domains = self.api.tokens.domains.list_domains(self.active_slot)
            print("  Defined Domains")
            for number, domain in enumerate(domains, 1):
                label = domain["label"] or "Label not set"
                primary = " - primary" if domain.get("primary") else ""
                print(f"    Domain Label[{number - 1}]: {label}{primary}")
                print(f"      Fingerprint: {domain['fingerprint']}")
        elif sub == "domainadd":
            if self.active_slot is None:
                print("  No active slot. Use 'slot set -slot <id>' first.")
                return
            if not self.session_id or self.api.auth.get_role(self.session_id) != ROLE_SO:
                print("  Error: Partition PO login is required.")
                return
            label = self._get_arg(args, "-domainlabel", "-label", "-dl")
            secret = self._get_arg(args, "-domain", "-d")
            try:
                if self._has_flag(args, "-domainped"):
                    key_list = input("  Present Red PED key serials (comma-separated): ")
                    shared = (getpass.getpass("  PED shared secret: ")
                              if self.api.auth.ped.requires_shared_secret("red") else None)
                    domain_id = self.api.auth.ped.authenticate(
                        "red", [key.strip() for key in key_list.split(",") if key.strip()],
                        shared).domain_id
                elif secret:
                    domain_id = self.api.tokens.domains.domain_from_secret(secret)
                else:
                    print("  Usage: partition domainadd {-domain <secret>|-domainped} [-domainlabel <label>] [-primary]")
                    return
                result = self.api.tokens.domains.add_domain(
                    self.active_slot, domain_id, label,
                    primary=self._has_flag(args, "-primary"))
                print(f"  Domain '{label}' added ({result['fingerprint']}).")
            except CloningDomainError as error:
                print(f"  Error: {error}")
        elif sub == "domaindelete":
            if self.active_slot is None:
                print("  No active slot. Use 'slot set -slot <id>' first.")
                return
            if not self.session_id or self.api.auth.get_role(self.session_id) != ROLE_SO:
                print("  Error: Partition PO login is required.")
                return
            label = self._get_arg(args, "-domainlabel", "-label", "-dl")
            try:
                if label is None:
                    removable = [domain for domain in self.api.tokens.domains.list_domains(
                        self.active_slot) if not domain.get("primary")]
                    for number, domain in enumerate(removable, 1):
                        print(f"  {number}: {domain['label'] or 'Label not set'}")
                    selection = int(input("  Enter the domain number to delete: "))
                    label = removable[selection - 1]["label"]
                if not confirm_proceed("You are about to delete a partition cloning domain.",
                                       force=self._has_flag(args, "-force", "-f")):
                    print("  Command aborted.")
                    return
                result = self.api.tokens.domains.delete_domain(self.active_slot, label)
                print(f"  Domain '{result['label'] or 'Label not set'}' deleted.")
            except (CloningDomainError, ValueError, IndexError) as error:
                print(f"  Error: {error}")
        elif sub == "domainchangelabel":
            if self.active_slot is None:
                print("  No active slot. Use 'slot set -slot <id>' first.")
                return
            if not self.session_id or self.api.auth.get_role(self.session_id) != ROLE_SO:
                print("  Error: Partition PO login is required.")
                return
            old_label = self._get_arg(args, "-domainlabel", "-oldlabel", "-ol")
            new_label = self._get_arg(args, "-newlabel", "-nl")
            try:
                result = self.api.tokens.domains.change_domain_label(
                    self.active_slot, old_label, new_label,
                    primary=self._has_flag(args, "-primary", "-p"))
                print(f"  Domain label changed to '{result['label']}'.")
            except CloningDomainError as error:
                print(f"  Error: {error}")
        elif sub == "domain":
            # Legacy emulator alias; documented interfaces use domainlist/add/delete/changelabel.
            if self.active_slot is None:
                print("  No active slot. Use 'slot set -slot <id>' first.")
                return
            action = args[0].lower() if args else "show"
            try:
                if action == "show":
                    info = self.api.tokens.show_cloning_domain(self.active_slot)
                    print(f"  Partition:          {info['partition']} (slot {self.active_slot})")
                    print(f"  Domain Fingerprint: {info['fingerprint']}")
                    print(f"  Domain Source:      {info['source']}")
                elif action == "set":
                    inherit = self._has_flag(args, "-inherit")
                    if inherit:
                        domain_id = None
                    elif self.api.auth.ped.get_auth_mode() == "ped":
                        keys_arg = self._get_arg(args, "-keys") or input(
                            "  Present Red PED key serials (comma-separated): ")
                        secret = getpass.getpass("  PED shared secret: ") if self.api.auth.ped.requires_shared_secret("red") else None
                        result = self.api.auth.ped.authenticate(
                            "red", [key.strip() for key in keys_arg.split(",") if key.strip()], secret)
                        domain_id = result.domain_id
                    else:
                        domain_secret = self._get_arg(args, "-domain") or getpass.getpass(
                            "  Cloning domain secret: ")
                        domain_id = self.api.tokens.domains.domain_from_secret(domain_secret)
                    force = self._has_flag(args, "-force", "-f")
                    result = self.api.tokens.set_cloning_domain(
                        self.active_slot, domain_id, inherit, force,
                        audit=self.api.audit, session_id=self.session_id or 0)
                    print(f"  Cloning domain set: {result['fingerprint']} ({result['source']}).")
                    if result["objects_deleted"]:
                        print(f"  {result['objects_deleted']} object(s) zeroized.")
                else:
                    print("  Usage: partition domain show | set [-inherit|-domain <secret>|-keys <red keys>] [-force]")
            except (CloningDomainError, PKCS11Error) as exc:
                print(f"  Domain operation failed: {exc}")
        elif sub == "clone":
            source = self._get_arg(args, "-source")
            destination = self._get_arg(args, "-destination")
            labels_arg = self._get_arg(args, "-labels")
            if not source or not destination:
                print("  Usage: partition clone -source <slot> -destination <slot> [-labels a,b]")
                return
            try:
                result = self.api.tokens.clone_partition(
                    int(source), int(destination),
                    labels_arg.split(",") if labels_arg else None,
                    audit=self.api.audit, session_id=self.session_id or 0)
                print(f"  Secure clone complete: {len(result['cloned'])} object(s).")
                print(f"  Domain fingerprint: {result['domain_fingerprint']}")
                print(f"  Cloning protocol:   {result['cloning_protocol']}")
                self._print_explain([
                    "Cloning keeps sensitive key material inside the secure boundary and does not require extractability.",
                    "Wrapping exports an encrypted key blob; backup creates an offline recoverable copy.",
                ])
            except (CloningDomainError, PKCS11Error, ValueError) as exc:
                print(f"  Clone failed: {exc}")
        elif sub == "clear":
            if self.active_slot is None:
                print("  No active slot. Use 'slot set -slot <id>' first.")
                return
            if not confirm_proceed(
                    "Are you sure you wish to delete all objects on this partition?",
                    force=self._has_flag(args, "-force", "-f")):
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
            verbose = self._has_flag(args, "-verbose", "-v")
            print(self.api.tokens.show_policies(self.active_slot, verbose=verbose))
            self._print_explain([
                "Partition policies control security behaviors on the Luna 7.",
                "Each policy has a capability (inherited from HSM policies) and",
                "a configurable policy setting. Some changes are destructive —",
                "they delete all objects on the partition.",
                "",
                "Use 'partition showpolicies -verbose' for full descriptions.",
                "Use 'partition changepolicy -policy <id> -value <v>' to change.",
                "Use 'partition policytemplate' for template management.",
            ])
        elif sub == "changepolicy":
            if self.active_slot is None:
                print("  No active slot. Use 'slot set -slot <id>' first.")
                return
            policy_name = self._get_arg(args, "-policy") or self._get_arg(args, "-name")
            value = self._get_arg(args, "-value")
            force = self._has_flag(args, "-force", "-f")
            if not policy_name or value is None:
                print("  Usage: partition changepolicy -policy <id_or_name> -value <value> [-force]")
                print("  Use 'partition showpolicies' to see available policies.")
                return
            try:
                # Pre-check: is this destructive?
                from hsm.policies import get_policy, get_policy_by_name, validate_policy_change_safe
                policy = None
                if policy_name.isdigit():
                    policy = get_policy(int(policy_name))
                else:
                    policy = get_policy_by_name(policy_name)
                if policy:
                    stored = self.api.storage.get_partition_policies(self.active_slot)
                    old_val = stored.get(policy.policy_id, policy.default_value)
                    _, _, is_destr = validate_policy_change_safe(policy, old_val, int(value) if str(value).isdigit() else (1 if str(value).lower() in ("on","1","true","yes") else 0))
                    if is_destr and not force:
                        if not confirm_proceed(
                                f"Changing the policy '{policy.name}' is destructive.",
                                "All objects on the partition will be deleted."):
                            return
                        force = True
                self.api.tokens.change_policy(
                    self.active_slot, policy_name, value,
                    audit=self.api.audit, session_id=self.session_id or 0,
                    force=force
                )
                print(f"  Policy '{policy_name}' set to '{value}'.")
            except PKCS11Error as e:
                print(f"  Error: {e}")
        elif sub == "policytemplate":
            self._partition_policy_template(args[1:])
        else:
            print(f"  Unknown partition subcommand: {sub}")

    def _partition_policy_template(self, args: list):
        """Handle 'partition policytemplate' subcommands."""
        if not args:
            print("  Usage: partition policytemplate list | show -name <name> |")
            print("         create -name <name> -desc <desc> -policies <id=val,...> |")
            print("         delete -name <name> | apply -name <name> [-force]")
            return
        sub = args[0].lower()
        rest = self._parse_flags(args[1:])

        if sub == "list":
            templates = self.api.tokens.list_policy_templates()
            print(f"  {'Name':<20} {'Type':<12} {'Policies':<10} {'Description'}")
            print("  " + "-" * 80)
            for t in templates:
                ttype = "Custom" if t.get("custom") else "Predefined"
                print(f"  {t['name']:<20} {ttype:<12} {t['policy_count']:<10} {t['description'][:50]}")
            self._print_explain([
                "Partition Policy Templates (PPT) allow consistent policy",
                "sets across multiple partitions. Predefined templates cover",
                "common configurations (FIPS, High Security, Development).",
                "Custom templates can be created and saved for reuse.",
            ])

        elif sub == "show":
            name = self._get_arg(rest, "-name")
            if not name:
                print("  Usage: partition policytemplate show -name <name>")
                return
            template = self.api.tokens.get_policy_template(name)
            if template is None:
                print(f"  Template '{name}' not found.")
                return
            print(f"  Template: {name}")
            print(f"  Type: {'Predefined' if template.get('predefined') else 'Custom'}")
            print(f"  Description: {template['description']}")
            print(f"  Policies:")
            from hsm.policies import POLICY_CATALOG
            for pid, val in template["policies"].items():
                policy = POLICY_CATALOG[pid] if pid < len(POLICY_CATALOG) else None
                pname = policy.name if policy else f"Unknown({pid})"
                pval = "On" if val == 1 else "Off" if val == 0 else str(val)
                print(f"    {pid}: {pname} = {pval}")

        elif sub == "create":
            name = self._get_arg(rest, "-name")
            desc = self._get_arg(rest, "-desc") or ""
            policies_str = self._get_arg(rest, "-policies")
            if not name or not policies_str:
                print("  Usage: partition policytemplate create -name <name> -desc <desc> -policies <id=val,...>")
                return
            policies = {}
            for pair in policies_str.split(","):
                if "=" in pair:
                    pid, val = pair.split("=", 1)
                    policies[int(pid)] = int(val)
            try:
                self.api.tokens.create_policy_template(
                    name, desc, policies,
                    audit=self.api.audit, session_id=self.session_id or 0
                )
                print(f"  Template '{name}' created with {len(policies)} policy setting(s).")
            except PKCS11Error as e:
                print(f"  Error: {e}")

        elif sub == "delete":
            name = self._get_arg(rest, "-name")
            if not name:
                print("  Usage: partition policytemplate delete -name <name>")
                return
            try:
                self.api.tokens.delete_policy_template(
                    name, audit=self.api.audit, session_id=self.session_id or 0
                )
                print(f"  Template '{name}' deleted.")
            except PKCS11Error as e:
                print(f"  Error: {e}")

        elif sub == "apply":
            if self.active_slot is None:
                print("  No active slot. Use 'slot set -slot <id>' first.")
                return
            name = self._get_arg(rest, "-name")
            force = self._has_flag(args, "-force", "-f")
            if not name:
                print("  Usage: partition policytemplate apply -name <name> [-force]")
                return
            try:
                self.api.tokens.apply_policy_template(
                    self.active_slot, name,
                    audit=self.api.audit, session_id=self.session_id or 0,
                    force=force
                )
                print(f"  Template '{name}' applied to slot {self.active_slot}.")
                self._print_explain([
                    "Applying a PPT sets all policies defined in the template.",
                    "If any policy change is destructive, all objects on the",
                    "partition will be deleted. The PPT feature is intended",
                    "for consistent setup of new or zeroized partitions.",
                ])
            except PKCS11Error as e:
                print(f"  Error: {e}")
        else:
            print(f"  Unknown policytemplate subcommand: {sub}")
            print("  Available: list, show, create, delete, apply")

    # ------------------------------------------------------------------
    # Role / Authentication commands
    # ------------------------------------------------------------------

    def cmd_role(self, args: list):
        """Handle 'role' commands."""
        if not args:
            print("  Usage: role login | logout | changepw | list | show | init | activate | deactivate | resetpw")
            print("         role createchallenge | changechallenge | resetchallenge -name <co|lco|cu>")
            return
        sub = args[0].lower()

        if sub == "login":
            role_name = self._get_arg(args[1:], "-name")
            if not role_name:
                print("  Usage: role login -name <po|co|lco|cu>")
                return
            role_name = role_name.lower()
            if role_name not in ROLE_MAP:
                print(f"  Unknown role: {role_name}. Valid: po, co, lco, cu")
                return
            mapped_role = ROLE_MAP[role_name]
            if not self._ensure_session():
                return
            ped_keys, ped_secret = None, None
            if self.api.auth.ped.get_auth_mode() == "ped":
                color = {ROLE_SO: "Blue", ROLE_CO: "Black", "LCO": "Black",
                         ROLE_CU: "Gray"}[mapped_role]
                group = self.api.ha.deployment.group_for_slot(self.active_slot)
                auth_slot = group["members"][0]["slot_id"] if group else self.active_slot
                status = self.api.auth.activation.status(auth_slot, mapped_role)
                challenge = status["activation_enabled"] and status["challenge_configured"]
                pin = getpass.getpass("  Challenge secret: ") if challenge else ""
                if not challenge or not status["activated"]:
                    print(f"  Present {color} PED key serials for '{role_name.upper()}'.")
                    serials = input("  Key serials (comma-separated): ")
                    ped_keys = [value.strip() for value in serials.split(",") if value.strip()]
                    if self.api.auth.ped.requires_shared_secret(color.lower(), scope=str(auth_slot)):
                        ped_secret = getpass.getpass("  PED shared secret: ")
            else:
                print(f"  Password-authenticated role '{role_name.upper()}':")
                pin = getpass.getpass("  PIN: ")
            try:
                from pkcs11.constants import CKU_SO, CKU_USER, CKU_CONTEXT_SPECIFIC
                user_type = (CKU_SO if mapped_role == ROLE_SO else
                             CKU_CONTEXT_SPECIFIC if mapped_role == ROLE_CU else CKU_USER)
                if mapped_role == "LCO":
                    self.api.auth.login(self.session_id, self.active_slot, mapped_role, pin,
                                        ped_keys, ped_secret)
                    self.api.sessions.get_session(self.session_id).user_type = CKU_USER
                else:
                    self.api.C_Login(self.session_id, user_type, pin, ped_keys, ped_secret)
                display_role = "PO" if mapped_role == ROLE_SO else mapped_role
                print(f"  Logged in as {display_role}.")
                self._print_explain([
                    f"Calling C_Login with userType={'CKU_SO' if mapped_role == ROLE_SO else 'CKU_USER'}",
                    f"Role: {display_role}",
                    "Return code: CKR_OK (0x00000000)",
                    f"Security Note: The {display_role} role has "
                    + ("full administrative access to the partition." if mapped_role == ROLE_SO
                       else "key management capabilities." if mapped_role in (ROLE_CO, "LCO")
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
        elif sub in ("createchallenge", "changechallenge", "resetchallenge"):
            role_name = (self._get_arg(args[1:], "-name") or "").upper()
            if self.active_slot is None or role_name not in ("CO", "LCO", "CU"):
                print(f"  Usage: role {sub} -name <co|lco|cu> (select a physical partition)")
                return
            actor = self.api.auth.get_role(self.session_id) if self.session_id else None
            try:
                old = getpass.getpass("  Old challenge secret: ") if sub == "changechallenge" else None
                secret = getpass.getpass("  New challenge secret: ")
                if secret != getpass.getpass("  Confirm challenge secret: "):
                    print("  Error: Challenge secrets do not match.")
                    return
                activation = self.api.auth.activation
                if sub == "changechallenge":
                    activation.change_challenge(self.active_slot, role_name, old, secret, actor)
                else:
                    activation.create_challenge(self.active_slot, role_name, secret, actor,
                                                reset=sub == "resetchallenge")
                print("  Challenge secret updated.")
            except PKCS11Error as error:
                print(f"  Error: {error}")
        elif sub == "changepw":
            role_name = self._get_arg(args[1:], "-name")
            if not role_name:
                print("  Usage: role changepw -name <po|co|lco|cu>")
                return
            role_name = role_name.lower()
            if role_name not in ROLE_MAP:
                print(f"  Unknown role: {role_name}. Valid: po, co, lco, cu")
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
                role = ROLE_MAP[role_name]
                if (self.api.auth.ped.get_auth_mode() == "ped" and
                        self.api.auth.activation.status(self.active_slot, role)["challenge_configured"]):
                    self.api.auth.activation.change_challenge(
                        self.active_slot, role, old_pin, new_pin,
                        self.api.auth.get_role(self.session_id))
                else:
                    self.api.auth.change_pin(self.active_slot, role, old_pin, new_pin)
                print(f"  PIN changed for {role_name.upper()}.")
            except PKCS11Error as e:
                print(f"  Failed: {e}")
        elif sub == "list":
            if self.active_slot is None:
                print("  No active slot. Use 'slot set -slot <id>' first.")
                return
            print(self.api.tokens.list_roles(self.active_slot))
            self._print_explain([
                "Luna partitions expose PO, CO, and CU; V1 partitions also expose LCO.",
                "Each role has different capabilities and can be independently",
                "initialized, locked, or deactivated.",
            ])
        elif sub == "show":
            role_name = self._get_arg(args[1:], "-name")
            if not role_name:
                print("  Usage: role show -name <po|co|lco|cu>")
                return
            if self.active_slot is None:
                print("  No active slot. Use 'slot set -slot <id>' first.")
                return
            print(self.api.tokens.show_role(self.active_slot, role_name))
            if self.api.auth.ped.get_auth_mode() == "ped":
                status = self.api.auth.activation.status(self.active_slot, role_name)
                for key, value in status.items():
                    print(f"  {key.replace('_', ' ').title()}: {value}")
        elif sub == "init":
            role_name = self._get_arg(args[1:], "-name")
            if not role_name:
                print("  Usage: role init -name <co|lco|cu>")
                return
            role_name = role_name.upper()
            if role_name not in ("CO", "LCO", "CU"):
                print("  Only CO, LCO, and CU roles can be initialized with 'role init'.")
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
            actor = self.api.auth.get_role(self.session_id) if self.session_id else None
            try:
                self.api.tokens.init_role(
                    self.active_slot, role_name, pin,
                    audit=self.api.audit, session_id=self.session_id or 0,
                    actor_role=actor,
                )
                print(f"  Role '{role_name}' initialized.")
                self._print_explain([
                    f"Role init sets the PIN for the {role_name} role.",
                    "On a real Luna 7, this requires PO authentication.",
                    "The CU role is optional and provides read-only access",
                    "to cryptographic objects for verify/decrypt operations.",
                ])
            except PKCS11Error as e:
                print(f"  Error: {e}")
        elif sub == "deactivate":
            role_name = self._get_arg(args[1:], "-name")
            if not role_name:
                print("  Usage: role deactivate -name <co|lco|cu>")
                return
            role_name = role_name.upper()
            if self.active_slot is None:
                print("  No active slot. Use 'slot set -slot <id>' first.")
                return
            if not confirm_proceed(
                    f"Are you sure you wish to deactivate the role '{role_name}'?",
                    "Its credential will be retained.",
                    force=self._has_flag(args, "-force", "-f")):
                return
            actor = self.api.auth.get_role(self.session_id) if self.session_id else None
            try:
                self.api.tokens.deactivate_role(
                    self.active_slot, role_name,
                    audit=self.api.audit, session_id=self.session_id or 0,
                    actor_role=actor,
                )
                if self.api.auth.ped.get_auth_mode() == "ped":
                    print(f"  Role '{role_name}' PED cache cleared; next login requires quorum again.")
                    return
                print(f"  Role '{role_name}' deactivated. Credential retained for superior-role reactivation.")
                self._print_explain([
                    "Deactivating a role blocks login while retaining its credential.",
                    "On a real Luna 7, this requires PO authentication and is",
                    "used as a security measure to disable unused roles.",
                ])
            except PKCS11Error as e:
                print(f"  Error: {e}")
        elif sub == "activate":
            if self.api.auth.ped.get_auth_mode() == "ped":
                print("  PED roles activate on login with their challenge secret and PED quorum.")
                print("  Enable policy 22, use role createchallenge, then role login.")
                return
            role_name = self._get_arg(args[1:], "-name")
            if not role_name or self.active_slot is None:
                print("  Usage: role activate -name <co|lco|cu>")
                return
            actor = self.api.auth.get_role(self.session_id) if self.session_id else None
            try:
                self.api.tokens.activate_role(
                    self.active_slot, role_name, audit=self.api.audit,
                    session_id=self.session_id or 0, actor_role=actor)
                print(f"  Role '{role_name.upper()}' activated.")
            except PKCS11Error as e:
                print(f"  Error: {e}")
        elif sub == "resetpw":
            role_name = self._get_arg(args[1:], "-name")
            if not role_name:
                print("  Usage: role resetpw -name <co|lco|cu>")
                return
            role_name = role_name.upper()
            if role_name not in ("CO", "LCO", "CU"):
                print("  Only CO, LCO, and CU roles can be reset with 'role resetpw'.")
                return
            if self.active_slot is None:
                print("  No active slot. Use 'slot set -slot <id>' first.")
                return
            print(f"  [PED Simulation] Reset PIN for role '{role_name}' (requires PO):")
            new_pin = getpass.getpass("  New PIN: ")
            confirm = getpass.getpass("  Confirm PIN: ")
            if new_pin != confirm:
                print("  Error: PINs do not match.")
                return
            actor = self.api.auth.get_role(self.session_id) if self.session_id else None
            try:
                self.api.tokens.reset_pin(
                    self.active_slot, role_name, new_pin,
                    audit=self.api.audit, session_id=self.session_id or 0,
                    actor_role=actor,
                )
                print(f"  PIN reset for role '{role_name}'.")
                self._print_explain([
                    "Role resetpw sets a new PIN without requiring the old one.",
                    "This is a PO-only operation on a real Luna 7, used when",
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
        sub = args[0].lower()
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
            if not confirm_proceed(
                    f"Are you sure you wish to destroy the object with label:",
                    f"'{label}' (handle 0x{obj.handle:08X})?"):
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
        sub = args[0].lower()
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
            sub = args[1].lower()
            if sub == "show":
                print(self.api.audit.show())
            elif sub == "clear":
                if confirm_proceed("Are you sure you wish to clear all audit entries?",
                                   force=self._has_flag(args, "-force", "-f")):
                    self.api.audit.clear()
                    print("  Audit log cleared.")
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
        sub = args[0].lower()
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
            if confirm_proceed(
                    "Are you sure you wish to reset this HSM to factory default settings?",
                    "All partitions, keys, and audit logs will be erased.",
                    force=self._has_flag(args, "-force", "-f")):
                self.api.tokens.factory_reset()
                self.active_slot = None
                self.session_id = None
                print("  HSM reset to factory defaults.")
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
        sub = args[0].lower()
        rest = self._parse_flags(args[1:])

        if sub == "show":
            info = self.api.tokens.get_firmware_info()
            print(f"  Current Firmware:  {info['current_version']}")
            print(f"  Latest Firmware:   {info['latest_version']}")
            print(f"  Update Available:  {'Yes' if info['update_available'] else 'No'}")
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
            if not confirm_proceed(
                    f"Are you sure you wish to upgrade the firmware from",
                    f"{pre['current_version']} to {target}?",
                    force=self._has_flag(args, "-force", "-f")):
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
            if not confirm_proceed(
                    f"Are you sure you wish to roll back the firmware to {last['from_version']}?",
                    force=self._has_flag(args, "-force", "-f")):
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
    # Backup HSM commands
    # ------------------------------------------------------------------

    def cmd_hagroup(self, args: list):
        """Handle the documented client-side LunaCM HA group commands."""
        if not args:
            print("  hagroup: addmember addstandby creategroup deletegroup halog haonly")
            print("           interval listgroups recover recoverymode removemember")
            print("           removestandby retry synchronize")
            return
        sub = args[0].lower()
        rest = args[1:]
        from hsm.deployment import DeploymentManager
        deployment = DeploymentManager(self.api.storage)
        group_name = self._get_arg(rest, "-group", "-label", "-g")
        slot = self._get_arg(rest, "-slot", "-sl")

        if sub == "listgroups":
            groups = deployment.list_ha_groups()
            if not groups:
                print("  No HA groups configured.")
            for group in groups:
                print(f"  HA Group Label: {group['name']}  Virtual Slot: {group['virtual_slot']}  Members: {len(group['members'])}  State: {group['state']}")
        elif sub == "creategroup":
            label = self._get_arg(rest, "-label", "-group", "-g")
            if not label or slot is None:
                print("  Usage: hagroup creategroup -label <label> -slot <slot> -password <password>")
                return
            password = self._get_arg(rest, "-password", "-p") or getpass.getpass(
                "  Partition CO password: ")
            validation_session = self.api.C_OpenSession(int(slot))
            try:
                self.api.C_Login(validation_session, CKU_USER, password)
            except PKCS11Error as error:
                self.api.C_CloseSession(validation_session)
                print(f"  Error: {error}")
                return
            self.api.C_CloseSession(validation_session)
            result = deployment.create_ha_group(label, int(slot), label)
            print(f"  HA group '{label}' created." if result["success"] else f"  Error: {result['error']}")
        elif sub == "deletegroup":
            if not group_name:
                print("  Usage: hagroup deletegroup -label <label>")
                return
            result = deployment.delete_ha_group(group_name)
            print(f"  HA group '{group_name}' deleted." if result["success"] else f"  Error: {result['error']}")
        elif sub in ("addmember", "addstandby"):
            if not group_name or slot is None:
                print(f"  Usage: hagroup {sub} -group <label> -slot <slot> -password <password>")
                return
            password = self._get_arg(rest, "-password", "-p") or getpass.getpass(
                "  Member CO password: ")
            validation_session = self.api.C_OpenSession(int(slot))
            try:
                self.api.C_Login(validation_session, CKU_USER, password)
            except PKCS11Error as error:
                self.api.C_CloseSession(validation_session)
                print(f"  Error: {error}")
                return
            self.api.C_CloseSession(validation_session)
            result = deployment.add_ha_member(group_name, int(slot))
            if result["success"] and sub == "addstandby":
                deployment.set_ha_mode(group_name, "active-standby")
            print(f"  Member slot {slot} added to '{group_name}'." if result["success"] else f"  Error: {result['error']}")
        elif sub in ("removemember", "removestandby"):
            if not group_name or slot is None:
                print(f"  Usage: hagroup {sub} -group <label> -slot <slot>")
                return
            result = deployment.remove_ha_member(group_name, int(slot))
            print(f"  Member slot {slot} removed." if result["success"] else f"  Error: {result['error']}")
        elif sub == "synchronize":
            result = deployment.synchronize_ha_group(group_name) if group_name else {
                "success": False, "error": "Specify -group <label>"}
            print(f"  HA group '{group_name}' synchronized." if result["success"] else f"  Error: {result['error']}")
        elif sub == "retry":
            value = self._get_arg(rest, "-count", "-c")
            result = deployment.set_ha_retry(None, int(value)) if value is not None else {
                "success": False, "error": "Specify -count <retries>"}
            print(f"  HA retry count set to {result['retry_count']}." if result["success"] else f"  Error: {result['error']}")
        elif sub == "interval":
            value = self._get_arg(rest, "-interval", "-i")
            result = deployment.set_ha_interval(None, int(value)) if value is not None else {
                "success": False, "error": "Specify -interval <seconds>"}
            print(f"  HA interval set to {result['poll_interval']}." if result["success"] else f"  Error: {result['error']}")
        elif sub == "recoverymode":
            mode = (self._get_arg(rest, "-mode", "-m") or "").lower()
            mapped = {"activebasic": "manual", "activeenhanced": "automatic"}.get(mode)
            if not mapped:
                print("  Error: Specify -mode activeBasic or activeEnhanced")
                return
            results = [deployment.set_ha_recovery_mode(group["name"], mapped)
                       for group in deployment.list_ha_groups()]
            if all(result["success"] for result in results):
                print(f"  Recovery mode: {'activeBasic' if mapped == 'manual' else 'activeEnhanced'}.")
            else:
                print("  Error: Unable to update recovery mode")
        elif sub == "haonly":
            if self._has_flag(rest, "-enable") and self._has_flag(rest, "-disable"):
                print("  Error: Choose -enable or -disable, not both.")
                return
            if self._has_flag(rest, "-enable"):
                deployment.set_ha_only(True)
            elif self._has_flag(rest, "-disable"):
                deployment.set_ha_only(False)
            print(f"  HA Only: {'enabled' if deployment.ha_only() else 'disabled'}")
        elif sub == "recover":
            if not group_name:
                print("  Usage: hagroup recover -group <label> [-slot <id>]")
                return
            group = deployment.get_ha_group(group_name)
            if not group:
                print("  Error: HA group not found")
                return
            for member in group["members"]:
                if slot is None or member["slot_id"] == int(slot):
                    result = deployment.recover_ha_member(group_name, member["slot_id"])
                    print(f"  Slot {member['slot_id']}: " + ("recovered" if result["success"] else result["error"]))
        elif sub == "halog":
            print("  hagroup halog is recognized but not implemented yet.")
        else:
            print(f"  Unknown hagroup subcommand: {sub}")

    def cmd_backup(self, args: list):
        """Legacy emulator backup interface; canonical operations use partition archive."""
        if not args:
            print("  Usage: backup connect | disconnect | show | init | login | logout |")
            print("         backup list | backup create-partition | backup objects |")
            print("         backup backup -slot <id> -domain <dom> |")
            print("         backup restore -slot <id> -domain <dom> |")
            print("         backup stm show | backup stm recover -string <s> |")
            print("         backup firmware show | backup firmware upgrade -version <v> |")
            print("         backup firmware rollback | backup factoryreset")
            return
        sub = args[0].lower()
        rest = self._parse_flags(args[1:])

        if sub == "connect":
            result = self.api.backup.connect()
            if result.get("already_connected"):
                print(f"  Backup HSM already connected. Serial: {result['serial']}")
            else:
                print(f"  Luna Backup HSM 7 connected.")
                print(f"  Serial:     {result['serial']}")
                print(f"  Firmware:   {result['firmware']}")
                print(f"  STM State:  {result['stm_state']}")
                self._print_explain([
                    "The Luna Backup HSM 7 is a USB-connected HSM used to store",
                    "backup copies of cryptographic objects from Luna Network",
                    "HSM 7 application partitions. It appears as a slot in LunaCM.",
                    "",
                    "When first shipped, the backup HSM is in Secure Transport Mode",
                    "(STM). You must recover from STM and initialize it before use.",
                ])

        elif sub == "disconnect":
            self.api.backup.disconnect()
            print("  Backup HSM disconnected.")
            self._print_explain([
                "Disconnecting the backup HSM simulates unplugging the USB device.",
                "All backup data remains persisted in the database.",
            ])

        elif sub == "show":
            if not self.api.backup.is_connected():
                print("  No backup HSM connected. Use 'backup connect' first.")
                return
            print(self.api.backup.show_info())
            self._print_explain([
                "Backup HSM status shows the connection state, firmware version,",
                "Secure Transport Mode state, login status, and storage usage.",
            ])

        elif sub == "stm":
            self._backup_stm(args[1:])

        elif sub == "init":
            if not self.api.backup.is_connected():
                print("  No backup HSM connected. Use 'backup connect' first.")
                return
            print("  [PED Simulation] Set SO PIN for the backup HSM:")
            so_pin = getpass.getpass("  SO PIN: ")
            confirm = getpass.getpass("  Confirm SO PIN: ")
            if so_pin != confirm:
                print("  Error: PINs do not match.")
                return
            try:
                result = self.api.backup.initialize(
                    so_pin, audit=self.api.audit, session_id=self.session_id or 0
                )
                print(f"  Backup HSM initialized. State: {result['stm_state']}")
                self._print_explain([
                    "Initializing the backup HSM sets the SO PIN and transitions",
                    "it from Secure Transport Mode to active state.",
                    "On a real Luna 7, this is done with 'token backup init'.",
                ])
            except PKCS11Error as e:
                print(f"  Error: {e}")

        elif sub == "login":
            if not self.api.backup.is_connected():
                print("  No backup HSM connected. Use 'backup connect' first.")
                return
            print("  [PED Simulation] Enter SO PIN for the backup HSM:")
            so_pin = getpass.getpass("  SO PIN: ")
            try:
                result = self.api.backup.login(
                    so_pin, audit=self.api.audit, session_id=self.session_id or 0
                )
                print(f"  Logged in to backup HSM. Serial: {result['serial']}")
                self._print_explain([
                    "Logging in to the backup HSM as SO is required before any",
                    "backup or restore operation. On a real Luna 7, this is",
                    "done with 'token backup login -serial <serial>'.",
                ])
            except PKCS11Error as e:
                print(f"  Login failed: {e}")

        elif sub == "logout":
            self.api.backup.logout(audit=self.api.audit, session_id=self.session_id or 0)
            print("  Logged out of backup HSM.")

        elif sub == "list":
            if not self.api.backup.is_connected():
                print("  No backup HSM connected. Use 'backup connect' first.")
                return
            try:
                print(self.api.backup.list_backups())
                self._print_explain([
                    "Backup partitions are organized by cloning domain. Each",
                    "domain corresponds to a set of HSMs that share the same",
                    "cloning secret. Objects can only be cloned between",
                    "partitions that share the same domain.",
                ])
            except PKCS11Error as e:
                print(f"  Error: {e}")

        elif sub == "create-partition":
            if not self.api.backup.is_connected():
                print("  No backup HSM connected. Use 'backup connect' first.")
                return
            domain = self._get_arg(rest, "-domain")
            label = self._get_arg(rest, "-label") or ""
            if not domain:
                print("  Usage: backup create-partition -domain <domain> [-label <label>]")
                return
            try:
                result = self.api.backup.create_backup_partition(
                    domain, label, audit=self.api.audit,
                    session_id=self.session_id or 0
                )
                print(f"  Backup partition created. ID: {result['partition_id']}, Domain: {result['domain']}")
            except PKCS11Error as e:
                print(f"  Error: {e}")

        elif sub == "backup":
            if not self.api.backup.is_connected():
                print("  No backup HSM connected. Use 'backup connect' first.")
                return
            slot = self._get_arg(rest, "-slot")
            domain = self._get_arg(rest, "-domain")
            labels_str = self._get_arg(rest, "-labels")
            if not slot:
                print("  Usage: backup backup -slot <src_slot> [-domain <domain-id>] [-labels lbl1,lbl2]")
                return
            domain = domain or self.api.tokens.domains.get_partition_domain(int(slot))["domain_id"]
            labels = labels_str.split(",") if labels_str else None
            try:
                result = self.api.backup.backup_objects(
                    int(slot), domain, labels=labels,
                    audit=self.api.audit, session_id=self.session_id or 0
                )
                print(f"  Backup complete.")
                print(f"  Backed up: {len(result['backed_up'])} object(s)")
                for lbl in result["backed_up"]:
                    print(f"    - {lbl}")
                if result.get("skipped_by_cloning_policy"):
                    print(f"  Skipped by cloning policy: {len(result['skipped_by_cloning_policy'])}")
                    for lbl in result["skipped_by_cloning_policy"]:
                        print(f"    - {lbl}")
                print(f"  Domain fingerprint: {self.api.tokens.domains.fingerprint(result['domain'])}")
                print(f"  Backup Partition ID: {result['partition_id']}")
                self._print_explain([
                    "Backup clones objects from the source partition to the backup HSM.",
                    "Backup uses secure cloning and can protect non-extractable objects.",
                    "Cloning policies must allow each key type and domains must match.",
                    "",
                    "On a real Luna 7, this uses the cloning protocol which",
                    "securely transfers encrypted key material over a secure",
                    "channel between the HSM and the backup device.",
                ])
            except PKCS11Error as e:
                print(f"  Backup failed: {e}")

        elif sub == "restore":
            if not self.api.backup.is_connected():
                print("  No backup HSM connected. Use 'backup connect' first.")
                return
            slot = self._get_arg(rest, "-slot")
            domain = self._get_arg(rest, "-domain")
            labels_str = self._get_arg(rest, "-labels")
            if not slot:
                print("  Usage: backup restore -slot <dest_slot> [-domain <domain-id>] [-labels lbl1,lbl2]")
                return
            domain = domain or self.api.tokens.domains.get_partition_domain(int(slot))["domain_id"]
            labels = labels_str.split(",") if labels_str else None
            if not confirm_proceed(
                    f"Are you sure you wish to restore objects to slot {slot}?",
                    "Existing objects with matching labels may be affected.",
                    force=self._has_flag(rest, "-force", "-f")):
                return
            try:
                result = self.api.backup.restore_objects(
                    int(slot), domain, labels=labels,
                    audit=self.api.audit, session_id=self.session_id or 0
                )
                print(f"  Restore complete.")
                print(f"  Restored: {len(result['restored'])} object(s)")
                for lbl in result["restored"]:
                    print(f"    - {lbl}")
                print(f"  Domain fingerprint: {self.api.tokens.domains.fingerprint(result['domain'])}")
                print(f"  From Backup Partition ID: {result['partition_id']}")
                self._print_explain([
                    "Restore clones objects from the backup HSM back to a",
                    "destination partition. The cloning domain must match.",
                    "",
                    "On a real Luna 7, restored objects are injected into the",
                    "destination partition's key store with the same attributes",
                    "they had when backed up, including sensitivity and",
                    "extractability flags.",
                ])
            except PKCS11Error as e:
                print(f"  Restore failed: {e}")

        elif sub == "firmware":
            self._backup_firmware(args[1:])

        elif sub == "factoryreset":
            if not self.api.backup.is_connected():
                print("  No backup HSM connected. Use 'backup connect' first.")
                return
            if confirm_proceed(
                    "Are you sure you wish to reset the backup HSM to factory default settings?",
                    "All backup partitions and data will be erased.",
                    force=self._has_flag(args, "-force", "-f")):
                self.api.backup.factory_reset(
                    audit=self.api.audit, session_id=self.session_id or 0
                )
                print("  Backup HSM reset to factory defaults.")

        else:
            print(f"  Unknown backup subcommand: {sub}")
            print("  Available: connect, disconnect, show, init, login, logout, list,")
            print("              create-partition, backup, restore, stm, firmware, factoryreset")

    def _backup_stm(self, args: list):
        """Handle 'backup stm' subcommands."""
        if not args:
            print("  Usage: backup stm show | backup stm recover -string <random_user_string>")
            return
        sub = args[0].lower()
        rest = self._parse_flags(args[1:])

        if sub == "show":
            if not self.api.backup.is_connected():
                print("  No backup HSM connected.")
                return
            info = self.api.backup.stm_show()
            print(f"  Serial:     {info['serial']}")
            print(f"  STM State:   {info['stm_state']}")
            print(f"  Description: {info['description']}")
            self._print_explain([
                "Secure Transport Mode (STM) provides a logical check on the",
                "firmware and critical security parameters so the authorized",
                "recipient can determine if the HSM was tampered with in transit.",
                "",
                "The backup HSM ships in STM and must be recovered before use.",
            ])

        elif sub == "recover":
            rus = self._get_arg(rest, "-string")
            if not rus:
                print("  Usage: backup stm recover -string <random_user_string>")
                return
            try:
                result = self.api.backup.stm_recover(
                    rus, audit=self.api.audit, session_id=self.session_id or 0
                )
                print(f"  STM recovered. State: {result['stm_state']}")
                self._print_explain([
                    "Recovering from Secure Transport Mode verifies that the",
                    "backup HSM has not been tampered with during shipping.",
                    "The Random User String is set during manufacturing and",
                    "verified during the recovery process.",
                ])
            except PKCS11Error as e:
                print(f"  Error: {e}")
        else:
            print(f"  Unknown stm subcommand: {sub}")

    def _backup_firmware(self, args: list):
        """Handle 'backup firmware' subcommands."""
        if not args:
            print("  Usage: backup firmware show | backup firmware upgrade -version <v> | backup firmware rollback")
            return
        sub = args[0].lower()
        rest = self._parse_flags(args[1:])

        if sub == "show":
            if not self.api.backup.is_connected():
                print("  No backup HSM connected.")
                return
            try:
                info = self.api.backup.get_firmware_info()
                print(f"  Current Firmware:  {info['current_version']}")
                print(f"  Latest Firmware:   {info['latest_version']}")
                print(f"  Update Available:  {'Yes' if info['update_available'] else 'No'}")
                print(f"  Model:             {info['model']}")
                print(f"  Serial:            {info['serial']}")
                self._print_explain([
                    "The Luna Backup HSM 7 has its own firmware, separate from",
                    "the Luna Network HSM 7 appliance firmware. Updates require",
                    "a signed firmware update file (.fuf) from Thales.",
                ])
            except PKCS11Error as e:
                print(f"  Error: {e}")

        elif sub == "upgrade":
            target = self._get_arg(rest, "-version")
            if not target:
                print("  Usage: backup firmware upgrade -version <version>")
                return
            if not confirm_proceed(
                    f"Are you sure you wish to upgrade the backup HSM firmware to {target}?",
                    force=self._has_flag(rest, "-force", "-f")):
                return
            try:
                result = self.api.backup.upgrade_firmware(
                    target, audit=self.api.audit, session_id=self.session_id or 0
                )
                print(f"  Firmware upgraded: {result['previous_version']} -> {result['new_version']}")
                self._print_explain([
                    "The previous firmware version is stored in reserve on the",
                    "backup HSM for potential rollback. On a real Luna 7, the",
                    "firmware update is applied with 'hsm updatefw -fuf <file>".replace('"', '') + " -authcode <file>'.",
                ])
            except PKCS11Error as e:
                print(f"  Error: {e}")

        elif sub == "rollback":
            if not confirm_proceed(
                    "Are you sure you wish to roll back the backup HSM firmware?",
                    "Rollback will zeroize the backup HSM and erase all backup partitions.",
                    force=self._has_flag(rest, "-force", "-f")):
                return
            try:
                result = self.api.backup.rollback_firmware(
                    audit=self.api.audit, session_id=self.session_id or 0
                )
                print(f"  Firmware rolled back: {result['previous_version']} -> {result['new_version']}")
                print(f"  WARNING: {result['warning']}")
                self._print_explain([
                    "Firmware rollback on the backup HSM is destructive — it",
                    "zeroizes the HSM and erases all backups. This is because",
                    "earlier firmware may have older mechanisms and security",
                    "vulnerabilities. On a real Luna 7: 'hsm rollbackfw'.",
                ])
            except PKCS11Error as e:
                print(f"  Error: {e}")
        else:
            print(f"  Unknown firmware subcommand: {sub}")

    def cmd_help(self, args: list = None):
        """Show the canonical LunaCM command hierarchy."""
        print("""
  LunaCM Commands

    appid          Application IDs              clientconfig   Client configuration
    file           File display                 hagroup        High-availability groups
    partition      Partition operations         ped            Remote PED
    remotebackup   Remote Backup server         role           Partition roles
    slot           Slot selection/status        srk            Secure Recovery Key
    stc            Secure Trusted Channel       stcconfig      STC configuration
    stm            Secure Transport Mode

  Documented shortcuts: a, ccfg, f, ha, par, p, rb, ro, s, r, stc, stcc.
  Commands and options are case-insensitive. The prompt is lunacm:>.
""")

    # ------------------------------------------------------------------
    # Arg parsing helper
    # ------------------------------------------------------------------

    def cmd_unavailable(self, args: list):
        print("  This documented LunaCM command group is not implemented yet.")

    @staticmethod
    def _has_flag(args: list, *flags: str) -> bool:
        wanted = {flag.lower() for flag in flags}
        return any(argument.lower() in wanted for argument in args)

    @staticmethod
    def _get_arg(args: list, *flags: str) -> Optional[str]:
        """Extract an option value; Luna commands and options ignore case."""
        wanted = {flag.lower() for flag in flags}
        for index, argument in enumerate(args):
            if argument.lower() in wanted and index + 1 < len(args):
                return args[index + 1]
        return None
