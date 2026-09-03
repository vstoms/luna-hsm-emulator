"""Documentation-aligned Luna 7 compatibility behavior."""

import io
import os
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from cli.commands import CommandHandler
from cli.lunacm import LunaCMShell
from cli.lunash import LunaSHShell
from hsm.appliance import Appliance
from hsm.auth import ROLE_LCO, ROLE_SO
from pkcs11.api import PKCS11API
from pkcs11.constants import CKM_AES_KEY_GEN
from pkcs11.objects import make_aes_key_template
from storage.db import Storage


class CompatibilityTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.storage = Storage(os.path.join(self.tmpdir, "test.db"), "master")
        self.api = PKCS11API(self.storage)
        self.api.C_Initialize()

    def tearDown(self):
        self.api.C_Finalize()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_hsm_so_is_independent_and_third_failure_zeroizes(self):
        appliance = Appliance(self.storage)
        appliance.login("admin", "appliance-password")
        appliance.hsm_state.initialize("Luna", "password", "correct-password")
        slot = self.api.tokens.create_partition("partition")
        self.api.tokens.init_token(slot, "partition-password", "Partition", "domain")
        self.assertFalse(appliance.hsm_login(so_pin="bad-password")["success"])
        self.assertFalse(appliance.hsm_login(so_pin="bad-password")["success"])
        result = appliance.hsm_login(so_pin="bad-password")
        self.assertTrue(result["zeroized"])
        self.assertEqual(self.storage.get_all_partitions(), [])

    def test_zeroize_preserves_firmware_and_hsm_policies(self):
        self.storage.set_meta("firmware_version", "7.15.0")
        self.api.tokens.change_hsm_policy(57, 1)
        self.api.tokens.zeroize()
        self.assertEqual(self.storage.get_meta("firmware_version"), "7.15.0")
        self.assertEqual(self.api.tokens._hsm_policy_values()[57], 1)

    def test_v1_sks_extract_insert_clone_and_rollover(self):
        source = self.api.tokens.create_partition("source", version=1)
        target = self.api.tokens.create_partition("target", version=1)
        self.api.tokens.init_token(source, "source-password", "Source", "shared")
        self.api.tokens.init_token(target, "target-password", "Target", "shared")
        session = self.api.C_OpenSession(source)
        handle = self.api.C_GenerateKey(
            session, CKM_AES_KEY_GEN, make_aes_key_template("sks-key", 256))
        blob = self.api.tokens.sks.extract(source, handle)
        with self.assertRaises(Exception):
            self.api.tokens.sks.insert(target, blob)
        self.api.tokens.sks.clone_smk(source, target)
        inserted = self.api.tokens.sks.insert(target, blob)
        self.assertIsNotNone(self.storage.get_object(inserted)[0])
        self.api.tokens.sks.rollover_start(target)
        # Old blobs remain readable during the rollover window.
        self.api.tokens.sks.insert(target, blob)
        self.api.tokens.sks.rollover_end(target)
        with self.assertRaises(Exception):
            self.api.tokens.sks.insert(target, blob)

    def test_lunacm_po_and_lco_role_names_authenticate_correctly(self):
        slot = self.api.tokens.create_partition("v1", version=1)
        self.api.tokens.init_token(slot, "partition-password", "V1", "domain")
        self.api.tokens.init_role(slot, "LCO", "limited-password", actor_role=ROLE_SO)
        handler = CommandHandler(self.api, slot)
        handler._ensure_session()
        with patch("cli.commands.getpass.getpass", return_value="partition-password"), \
                redirect_stdout(io.StringIO()):
            handler.cmd_role(["login", "-name", "PO"])
        self.assertEqual(self.api.auth.get_role(handler.session_id), ROLE_SO)
        self.api.C_Logout(handler.session_id)
        with patch("cli.commands.getpass.getpass", return_value="limited-password"), \
                redirect_stdout(io.StringIO()):
            handler.cmd_role(["login", "-name", "LCO"])
        self.assertEqual(self.api.auth.get_role(handler.session_id), ROLE_LCO)

    def test_shell_parsers_preserve_quoted_values_and_documented_prompts(self):
        luna = LunaCMShell(self.api)
        self.assertEqual(luna.prompt, "lunacm:> ")
        parsed = []
        luna.handler.cmd_partition = lambda args: parsed.extend(args)
        with redirect_stdout(io.StringIO()):
            luna._run("PAR showinfo -label \"Finance Production\"")
        self.assertEqual(parsed[-1], "Finance Production")

        captured = io.StringIO()
        with redirect_stdout(captured):
            luna._run("audit show")
        self.assertIn("Unknown command: audit", captured.getvalue())

        appliance = Appliance(self.storage)
        shell = LunaSHShell(appliance, self.api)
        self.assertEqual(shell.prompt, "login as: ")


if __name__ == "__main__":
    unittest.main()
