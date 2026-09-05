"""Real PKCS#11 operations through HA virtual slots (no mocked crypto)."""
import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from cli.commands import CommandHandler
from pkcs11.api import PKCS11API
from pkcs11.constants import *
from pkcs11.objects import make_aes_key_template, make_rsa_keypair_templates
from storage.db import Storage


class HAOperationsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.api = PKCS11API(Storage(os.path.join(self.tmp.name, "hsm.db"), "master"))
        self.api.C_Initialize()
        self.dm = self.api.ha.deployment
        self.slots = []
        for name in ("one", "two"):
            slot = self.api.tokens.create_partition(name)
            self.api.tokens.init_token(slot, "password-so", name, "shared-domain")
            self.api.tokens.init_pin(slot, "password-co")
            self.slots.append(slot)
        self.group = self.dm.create_ha_group("test", self.slots[0])["group"]
        self.dm.add_ha_member("test", self.slots[1])
        self.virtual = self.group["virtual_slot"]
        self.session = self.api.C_OpenSession(self.virtual, CKF_SERIAL_SESSION | CKF_RW_SESSION)
        self.api.C_Login(self.session, CKU_USER, "password-co")

    def tearDown(self):
        self.api.C_Finalize()
        self.tmp.cleanup()

    def key(self, label="key", token=True):
        template = make_aes_key_template(label, 256)
        template[CKA_TOKEN] = token
        return self.api.C_GenerateKey(self.session, CKM_AES_KEY_GEN, template)

    def encrypt(self, handle, data=b"hello"):
        self.api.C_EncryptInit(self.session, CKM_AES_GCM, handle)
        return self.api.C_Encrypt(self.session, data)

    def test_virtual_slots_and_haonly_survive_reopen(self):
        self.dm.set_ha_only(True)
        self.assertEqual(self.api.C_GetSlotList(), [self.virtual])
        self.assertEqual(len(self.api.C_GetSlotList(include_members=True)), 3)
        with self.assertRaises(PKCS11Error):
            self.api.C_OpenSession(self.slots[0])
        output = io.StringIO()
        with redirect_stdout(output):
            CommandHandler(self.api).cmd_slot(["list"])
        self.assertIn("Luna HA", output.getvalue())
        self.api.C_Finalize()
        self.api.C_Initialize()
        self.assertEqual(self.api.C_GetSlotList(), [self.virtual])
        self.assertTrue(self.api.C_GetTokenInfo(self.virtual)["virtual"])

    def test_encrypt_decrypt_load_balance_and_member_failure(self):
        handle = self.key()
        self.assertGreater(handle, 1 << 32)
        ct = self.encrypt(handle)
        first = self.dm.get_ha_status("test")["last_operation"]["slot_id"]
        self.api.C_DecryptInit(self.session, CKM_AES_GCM, handle)
        second = self.dm.get_ha_status("test")["last_operation"]["slot_id"]
        self.assertNotEqual(first, second)
        self.dm.set_ha_network_partition("test", second, True)
        self.assertEqual(self.api.C_Decrypt(self.session, ct), b"hello")
        self.assertNotEqual(self.dm.get_ha_status("test")["last_operation"]["slot_id"], second)
        self.dm.set_ha_network_partition("test", first, True)
        with self.assertRaises(PKCS11Error) as error:
            self.encrypt(handle)
        self.assertEqual(error.exception.code, CKR_DEVICE_ERROR)

    def test_rsa_pair_same_label_and_multipart_failover(self):
        priv, pub = make_rsa_keypair_templates("same-label", 2048)
        private, public = self.api.C_GenerateKeyPair(
            self.session, CKM_RSA_PKCS_KEY_PAIR_GEN, priv, pub)
        for slot in self.slots:
            self.assertEqual(self.api.storage.count_objects(slot), 2)
        self.api.C_SignInit(self.session, CKM_SHA256_RSA_PKCS, private)
        self.api.C_SignUpdate(self.session, b"part1")
        source = self.dm.get_ha_status("test")["last_operation"]["slot_id"]
        self.dm.set_ha_network_partition("test", source, True)
        self.api.C_SignUpdate(self.session, b"part2")
        signature = self.api.C_SignFinal(self.session)
        self.api.C_VerifyInit(self.session, CKM_SHA256_RSA_PKCS, public)
        self.assertTrue(self.api.C_Verify(self.session, b"part1part2", signature))

    def test_find_deduplicates_by_identity_not_label(self):
        one, two = self.key("duplicate"), self.key("duplicate")
        self.api.C_FindObjectsInit(self.session, {CKA_LABEL: "duplicate"})
        self.assertEqual(set(self.api.C_FindObjects(self.session)), {one, two})
        self.api.C_FindObjectsFinal(self.session)
        self.assertEqual(self.api.C_GetAttributeValue(self.session, one, [CKA_LABEL])[CKA_LABEL], b"duplicate")

    def test_session_objects_are_local_and_deleted_on_close(self):
        handle = self.key(token=False)
        self.assertEqual(sum(self.api.storage.count_objects(s) for s in self.slots), 1)
        self.encrypt(handle)
        source = self.dm.get_ha_status("test")["last_operation"]["slot_id"]
        self.dm.set_ha_network_partition("test", source, True)
        with self.assertRaises(PKCS11Error):
            self.encrypt(handle)
        other = self.api.C_OpenSession(self.virtual)
        with self.assertRaises(PKCS11Error):
            self.api.C_GetAttributeValue(other, handle, [CKA_LABEL])
        self.api.C_CloseSession(self.session)
        self.assertEqual(sum(self.api.storage.count_objects(s) for s in self.slots), 0)

    def test_delete_tombstone_prevents_resurrection(self):
        handle = self.key()
        self.dm.set_ha_network_partition("test", self.slots[1], True)
        self.api.C_DestroyObject(self.session, handle)
        self.assertEqual(self.api.storage.count_objects(self.slots[1]), 1)
        self.dm.set_ha_network_partition("test", self.slots[1], False)
        self.assertEqual(self.api.storage.count_objects(self.slots[1]), 0)
        new = self.key()
        self.assertNotEqual(handle, new)
        with self.assertRaises(PKCS11Error):
            self.api.C_GetAttributeValue(self.session, handle, [CKA_LABEL])

    def test_attribute_replication_and_manual_recovery(self):
        handle = self.key()
        self.dm.set_ha_recovery_mode("test", "manual")
        self.dm.set_ha_network_partition("test", self.slots[1], True)
        self.api.C_SetAttributeValue(self.session, handle, {CKA_LABEL: "renamed"})
        self.dm.set_ha_network_partition("test", self.slots[1], False)
        self.assertEqual(self.dm.get_ha_group("test")["members"][1]["state"], "recovering")
        self.encrypt(handle)
        self.dm.recover_ha_member("test", self.slots[1])
        obj = self.api.storage.get_all_objects(self.slots[1])[0][0]
        self.assertEqual(obj.label(), "renamed")

    def test_application_driven_retry_budget_and_interval(self):
        handle = self.key()
        self.dm.set_ha_retry("test", 1)
        self.dm.set_ha_interval("test", 30)
        self.dm.set_ha_network_partition("test", self.slots[1], True)
        member = self.dm.get_ha_group("test")["members"][1]
        with patch("hsm.deployment.time.time", return_value=member["last_retry"] + 1):
            self.encrypt(handle)
        self.assertEqual(self.dm.get_ha_group("test")["members"][1]["retry_attempts"], 0)
        with patch("hsm.deployment.time.time", return_value=member["last_retry"] + 31):
            self.encrypt(handle)
            self.encrypt(handle)
        self.assertEqual(self.dm.get_ha_group("test")["members"][1]["retry_attempts"], 1)

    def test_device_error_during_crypto_retries_another_member(self):
        import crypto.symmetric as sym
        handle = self.key()
        self.api.C_EncryptInit(self.session, CKM_AES_GCM, handle)
        failed = self.dm.get_ha_status("test")["last_operation"]["slot_id"]
        real_encrypt = sym.encrypt
        attempts = []
        def flaky(*args, **kwargs):
            attempts.append(True)
            if len(attempts) == 1:
                raise PKCS11Error(CKR_DEVICE_ERROR, "injected transport failure")
            return real_encrypt(*args, **kwargs)
        with patch("crypto.symmetric.encrypt", side_effect=flaky):
            ciphertext = self.api.C_Encrypt(self.session, b"retry")
        self.assertEqual(len(attempts), 2)
        self.assertNotEqual(self.dm.get_ha_status("test")["last_operation"]["slot_id"], failed)
        self.api.C_DecryptInit(self.session, CKM_AES_GCM, handle)
        self.assertEqual(self.api.C_Decrypt(self.session, ciphertext), b"retry")

    def test_login_failure_is_not_bypassed(self):
        self.api.C_Logout(self.session)
        with self.assertRaises(PKCS11Error):
            self.api.C_Login(self.session, CKU_USER, "wrong-password")
        self.assertFalse(self.api.auth.is_logged_in(self.session))
        self.api.C_Login(self.session, CKU_USER, "password-co")
        self.api.C_CloseAllSessions(self.virtual)
        self.assertEqual(self.api.sessions.count_sessions(), 0)
        self.assertFalse(self.api.auth._sessions)


if __name__ == "__main__":
    unittest.main()
