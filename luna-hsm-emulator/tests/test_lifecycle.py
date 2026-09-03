"""Partition lifecycle, authorization, and quota tests."""

import os
import shutil
import sys
import tempfile
import unittest

EMULATOR_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if EMULATOR_DIR not in sys.path:
    sys.path.insert(0, EMULATOR_DIR)

from hsm.auth import ROLE_CO, ROLE_HSO, ROLE_SO
from pkcs11.api import PKCS11API
from pkcs11.constants import (
    CKF_SERIAL_SESSION, CKM_AES_KEY_GEN, CKR_ACTION_PROHIBITED,
    CKR_DEVICE_MEMORY, CKR_USER_NOT_LOGGED_IN, CKU_CONTEXT_SPECIFIC, CKU_USER,
    PKCS11Error,
)
from pkcs11.objects import make_aes_key_template
from storage.db import Storage


class TestPartitionLifecycle(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.storage = Storage(os.path.join(self.tmpdir, "test.db"), "master")
        self.api = PKCS11API(self.storage)
        self.api.C_Initialize()

    def tearDown(self):
        self.api.C_Finalize()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_ppso_lifecycle_and_separate_role_initialization(self):
        slot = self.api.tokens.create_partition("application", partition_type="ppso")
        self.assertEqual(self.api.tokens.lifecycle.status(slot)["state"], "UNINITIALIZED")

        self.api.tokens.init_token(slot, "partition-so")
        status = self.api.tokens.lifecycle.status(slot)
        self.assertEqual(status["type"], "PPSO")
        self.assertEqual(status["state"], "INITIALIZED_ROLES_PENDING")
        self.assertEqual(status["roles"]["SO"]["state"], "ACTIVE")
        self.assertEqual(status["roles"]["CO"]["state"], "UNINITIALIZED")
        self.assertEqual(status["roles"]["CU"]["state"], "UNINITIALIZED")

        self.api.tokens.init_role(slot, "CO", "crypto-officer", actor_role=ROLE_SO)
        self.assertEqual(self.api.tokens.lifecycle.status(slot)["state"], "READY")
        self.api.tokens.init_role(slot, "CU", "crypto-user", actor_role=ROLE_SO)
        self.assertEqual(self.api.tokens.lifecycle.status(slot)["roles"]["CU"]["state"], "ACTIVE")
        session = self.api.C_OpenSession(slot)
        self.api.C_Login(session, CKU_CONTEXT_SPECIFIC, "crypto-user")
        self.assertEqual(self.api.auth.get_role(session), "CU")

    def test_legacy_partition_has_combined_partition_owner(self):
        slot = self.api.tokens.create_partition("legacy", partition_type="legacy")
        self.api.tokens.init_token(slot, "partition-owner")
        status = self.api.tokens.lifecycle.status(slot)
        self.assertEqual(status["type"], "LEGACY")
        self.assertEqual(status["state"], "READY")
        self.assertEqual(status["roles"]["SO"]["state"], "NOT_APPLICABLE")
        self.assertEqual(status["roles"]["CO"]["state"], "ACTIVE")

    def test_deactivation_blocks_login_and_superior_can_reactivate(self):
        slot = self.api.tokens.create_partition("roles")
        self.api.tokens.init_token(slot, "partition-so")
        self.api.tokens.init_role(slot, "CO", "crypto-officer", actor_role=ROLE_SO)
        self.api.tokens.deactivate_role(slot, "CO", actor_role=ROLE_SO)
        session = self.api.C_OpenSession(slot)
        with self.assertRaises(PKCS11Error) as error:
            self.api.C_Login(session, CKU_USER, "crypto-officer")
        self.assertEqual(error.exception.code, CKR_USER_NOT_LOGGED_IN)
        with self.assertRaises(PKCS11Error) as error:
            self.api.tokens.activate_role(slot, "CO", actor_role=ROLE_CO)
        self.assertEqual(error.exception.code, CKR_ACTION_PROHIBITED)
        self.api.tokens.activate_role(slot, "CO", actor_role=ROLE_SO)
        self.api.C_Login(session, CKU_USER, "crypto-officer")

    def test_correct_superior_role_is_required_for_reset(self):
        slot = self.api.tokens.create_partition("reset")
        self.api.tokens.init_token(slot, "partition-so")
        self.api.tokens.init_role(slot, "CO", "old-password", actor_role=ROLE_SO)
        with self.assertRaises(PKCS11Error):
            self.api.tokens.reset_pin(slot, "CO", "new-password", actor_role=ROLE_CO)
        self.api.tokens.reset_pin(slot, "CO", "new-password", actor_role=ROLE_SO)
        with self.assertRaises(PKCS11Error):
            self.api.tokens.reset_pin(slot, "SO", "new-so", actor_role=ROLE_SO)
        self.api.tokens.reset_pin(slot, "SO", "new-so", actor_role=ROLE_HSO)

    def test_locked_role_is_reset_by_partition_so(self):
        slot = self.api.tokens.create_partition("locked")
        self.api.tokens.init_token(slot, "partition-so")
        self.api.tokens.init_role(slot, "CO", "correct-pin", actor_role=ROLE_SO)
        self.storage.update_partition(slot, max_login_attempts=2)
        session = self.api.C_OpenSession(slot)
        for _ in range(2):
            with self.assertRaises(PKCS11Error):
                self.api.C_Login(session, CKU_USER, "wrong-pin")
        self.assertEqual(
            self.api.tokens.lifecycle.status(slot)["roles"]["CO"]["state"], "LOCKED")
        with self.assertRaises(PKCS11Error):
            self.api.tokens.reset_pin(slot, "CO", "replacement", actor_role=ROLE_CO)
        self.api.tokens.reset_pin(slot, "CO", "replacement", actor_role=ROLE_SO)
        self.assertEqual(
            self.api.tokens.lifecycle.status(slot)["roles"]["CO"]["state"], "ACTIVE")
        self.api.C_Login(session, CKU_USER, "replacement")

    def test_partition_deletion_requires_hsm_so_authorization(self):
        self.api.tokens.create_partition("delete-me")
        with self.assertRaises(PKCS11Error) as error:
            self.api.tokens.delete_partition("delete-me")
        self.assertEqual(error.exception.code, CKR_ACTION_PROHIBITED)
        self.api.tokens.delete_partition("delete-me", hsm_so_authorized=True)
        self.assertIsNone(self.storage.get_partition_by_name("delete-me"))

    def test_object_count_quota_is_enforced_centrally(self):
        slot = self.api.tokens.create_partition("small", max_objects=1)
        session = self.api.C_OpenSession(slot, CKF_SERIAL_SESSION)
        template = make_aes_key_template("first", 128)
        self.api.C_GenerateKey(session, CKM_AES_KEY_GEN, template)
        with self.assertRaises(PKCS11Error) as error:
            self.api.C_GenerateKey(
                session, CKM_AES_KEY_GEN, make_aes_key_template("second", 128))
        self.assertEqual(error.exception.code, CKR_DEVICE_MEMORY)
        self.assertEqual(self.storage.count_objects(slot), 1)

    def test_storage_byte_quota_is_enforced(self):
        slot = self.api.tokens.create_partition("tiny", max_storage=32)
        session = self.api.C_OpenSession(slot)
        with self.assertRaises(PKCS11Error) as error:
            self.api.C_GenerateKey(
                session, CKM_AES_KEY_GEN, make_aes_key_template("too-large", 128))
        self.assertEqual(error.exception.code, CKR_DEVICE_MEMORY)
        self.assertEqual(self.storage.count_objects(slot), 0)

    def test_partition_status_exposes_complete_state(self):
        slot = self.api.tokens.create_partition("app1", max_objects=7, max_storage=4096)
        output = self.api.tokens.show_partition_info(slot)
        for text in ("Partition Type:", "Lifecycle State:", "Domain Initialized:",
                     "Object Quota:", "Storage Quota:", "SO  UNINITIALIZED",
                     "CO  UNINITIALIZED", "CU  UNINITIALIZED"):
            self.assertIn(text, output)


if __name__ == "__main__":
    unittest.main()
