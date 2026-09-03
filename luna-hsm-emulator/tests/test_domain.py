"""Tests for first-class cloning domains and secure cloning."""

import os
import shutil
import sys
import tempfile
import unittest

EMULATOR_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if EMULATOR_DIR not in sys.path:
    sys.path.insert(0, EMULATOR_DIR)

from hsm.appliance import Appliance
from hsm.domain import CloningDomainError, DOMAIN_MISMATCH_CODE
from pkcs11.api import PKCS11API
from pkcs11.constants import CKM_AES_KEY_GEN, CKF_SERIAL_SESSION
from pkcs11.objects import make_aes_key_template
from storage.db import Storage


class TestCloningDomains(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.storage = Storage(os.path.join(self.tmpdir, "test.db"), "master")
        self.api = PKCS11API(self.storage)
        self.api.C_Initialize()
        self.source = self.api.tokens.create_partition("source", "Source")
        self.destination = self.api.tokens.create_partition("destination", "Destination")

    def tearDown(self):
        self.api.C_Finalize()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _generate_key(self, label="non_extractable"):
        session = self.api.C_OpenSession(self.source, CKF_SERIAL_SESSION)
        self.api.C_GenerateKey(
            session, CKM_AES_KEY_GEN,
            make_aes_key_template(label, 256, sensitive=True, extractable=False),
        )
        return session

    def test_new_partitions_inherit_hsm_domain(self):
        source = self.api.tokens.show_cloning_domain(self.source)
        destination = self.api.tokens.show_cloning_domain(self.destination)
        self.assertTrue(source["inherited"])
        self.assertEqual(source["domain_id"], destination["domain_id"])

    def test_direct_clone_preserves_non_extractable_key(self):
        self._generate_key()
        result = self.api.tokens.clone_partition(self.source, self.destination)
        self.assertEqual(result["cloned"], ["non_extractable"])
        cloned, material = self.storage.get_object_by_label(self.destination, "non_extractable")
        self.assertFalse(cloned.is_extractable())
        self.assertTrue(cloned.is_sensitive())
        self.assertIsNotNone(material)

    def test_domain_mismatch_has_luna_style_failure(self):
        self.api.tokens.set_cloning_domain(
            self.destination,
            self.api.tokens.domains.domain_from_secret("different-domain"),
        )
        with self.assertRaisesRegex(CloningDomainError, DOMAIN_MISMATCH_CODE):
            self.api.tokens.clone_partition(self.source, self.destination)

    def test_domain_change_requires_or_performs_zeroization(self):
        self._generate_key()
        replacement = self.api.tokens.domains.domain_from_secret("replacement")
        with self.assertRaisesRegex(CloningDomainError, "REQUIRES_ZEROIZE"):
            self.api.tokens.set_cloning_domain(self.source, replacement)
        result = self.api.tokens.set_cloning_domain(self.source, replacement, force=True)
        self.assertEqual(result["objects_deleted"], 1)
        self.assertEqual(self.storage.count_objects(self.source), 0)

    def test_partition_can_return_to_hsm_inheritance(self):
        explicit = self.api.tokens.domains.domain_from_secret("explicit")
        self.api.tokens.set_cloning_domain(self.destination, explicit)
        result = self.api.tokens.set_cloning_domain(self.destination, inherit=True)
        self.assertTrue(result["inherited"])
        self.assertEqual(result["domain_id"], self.api.tokens.domains.get_hsm_domain())

    def test_ha_synchronization_uses_secure_clone(self):
        self._generate_key("ha-key")
        deployment = Appliance(self.storage).deployment
        self.assertTrue(deployment.create_ha_group("training-ha", self.source)["success"])
        self.assertTrue(deployment.add_ha_member("training-ha", self.destination)["success"])
        result = deployment.synchronize_ha_group("training-ha")
        self.assertTrue(result["success"])
        self.assertEqual(result["cloned"], 1)
        self.assertIsNotNone(self.storage.get_object_by_label(self.destination, "ha-key")[0])

    def test_ha_rejects_and_does_not_sync_mismatched_domains(self):
        appliance = Appliance(self.storage)
        deployment = appliance.deployment
        deployment.create_ha_group("training-ha", self.source)
        self.api.tokens.set_cloning_domain(
            self.destination,
            self.api.tokens.domains.domain_from_secret("wrong-ha-domain"),
        )
        result = deployment.add_ha_member("training-ha", self.destination)
        self.assertFalse(result["success"])
        self.assertEqual(result["code"], DOMAIN_MISMATCH_CODE)


if __name__ == "__main__":
    unittest.main()
