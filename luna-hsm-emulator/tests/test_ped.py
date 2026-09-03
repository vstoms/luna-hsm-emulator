"""Tests for PED authentication, quorum, duplication, and connection state."""

import os
import shutil
import sys
import tempfile
import unittest

EMULATOR_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if EMULATOR_DIR not in sys.path:
    sys.path.insert(0, EMULATOR_DIR)

from hsm.appliance import Appliance
from hsm.ped import PEDManager, PEDError
from storage.db import Storage


class TestPEDManager(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.storage = Storage(os.path.join(self.tmpdir, "test.db"), "master")
        self.storage.open()
        self.ped = PEDManager(self.storage)
        self.ped.configure_hsm("TrainingHSM", "ped")

    def tearDown(self):
        self.storage.close()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _serials(self, key_set):
        return [share["copies"][0]["serial"] for share in key_set["shares"]]

    def test_local_connection_and_m_of_n_authentication(self):
        self.ped.connect()
        blue = self.ped.create_key_set("blue", 2, 3, "shared")
        serials = self._serials(blue)
        with self.assertRaisesRegex(PEDError, "PED_QUORUM_NOT_MET"):
            self.ped.authenticate("blue", serials[:1], "shared")
        with self.assertRaisesRegex(PEDError, "PED_SHARED_SECRET_INCORRECT"):
            self.ped.authenticate("blue", serials[:2], "wrong")
        result = self.ped.authenticate("blue", serials[:2], "shared")
        self.assertEqual(result.shares_presented, 2)

    def test_duplicate_is_same_share_not_an_extra_quorum_member(self):
        self.ped.connect()
        blue = self.ped.create_key_set("blue", 2, 2)
        serials = self._serials(blue)
        duplicate = self.ped.duplicate_key(serials[0])[0]
        with self.assertRaisesRegex(PEDError, "PED_QUORUM_NOT_MET"):
            self.ped.authenticate("blue", [serials[0], duplicate])
        self.ped.mark_lost(serials[0])
        self.ped.authenticate("blue", [duplicate, serials[1]])

    def test_wrong_color_and_cloning_domain_errors(self):
        self.ped.connect()
        blue = self.ped.create_key_set("blue")
        red = self.ped.create_key_set("red")
        with self.assertRaisesRegex(PEDError, "PED_WRONG_KEY"):
            self.ped.authenticate("blue", self._serials(red))
        with self.assertRaisesRegex(PEDError, "PED_CLONING_DOMAIN_MISMATCH"):
            self.ped.verify_cloning_domain(self._serials(red), "DOM-WRONG")
        self.ped.verify_cloning_domain(self._serials(red), red["domain_id"])
        self.assertTrue(self._serials(blue))

    def test_lost_key_reports_irrecoverable_identity(self):
        self.ped.connect()
        key_set = self.ped.create_key_set("black", 2, 2)
        consequence = self.ped.mark_lost(self._serials(key_set)[0])
        self.assertFalse(consequence["recoverable"])
        self.assertEqual(consequence["available_shares"], 1)

    def test_remote_ped_requires_orange_vector(self):
        self.ped.connect()
        orange = self.ped.create_key_set("orange")
        self.ped.disconnect()
        connection = self.ped.connect("ped.example.test", self._serials(orange))
        self.assertEqual(connection["mode"], "remote")
        self.assertEqual(connection["host"], "ped.example.test")

    def test_remote_ped_without_orange_vector_fails(self):
        with self.assertRaisesRegex(PEDError, "PED_REMOTE_VECTOR_REQUIRED"):
            self.ped.connect("ped.example.test")
        self.ped.connect()
        self.ped.create_key_set("orange")
        self.ped.disconnect()
        with self.assertRaisesRegex(PEDError, "PED_REMOTE_VECTOR_REQUIRED"):
            self.ped.connect("ped.example.test")

    def test_appliance_hsm_and_audit_logins_use_colored_keys(self):
        self.ped.connect()
        blue = self.ped.create_key_set("blue", 2, 2)
        white = self.ped.create_key_set("white")
        appliance = Appliance(self.storage)
        self.assertTrue(appliance.login("admin", "appliance-password")["success"])
        bad = appliance.hsm_login(ped_keys=self._serials(white))
        self.assertEqual(bad["code"], "PED_WRONG_KEY")
        login = appliance.hsm_login(ped_keys=self._serials(blue))
        self.assertTrue(login["success"])
        self.assertEqual(login["quorum"], 2)
        self.assertTrue(appliance.audit_login(ped_keys=self._serials(white))["success"])


if __name__ == "__main__":
    unittest.main()
