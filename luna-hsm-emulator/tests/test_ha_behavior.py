"""Behavioral tests for Luna-style HA routing, failover, and synchronization."""

import os
import shutil
import sys
import tempfile
import unittest

EMULATOR_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if EMULATOR_DIR not in sys.path:
    sys.path.insert(0, EMULATOR_DIR)

from hsm.appliance import Appliance
from pkcs11.api import PKCS11API
from pkcs11.constants import CKM_AES_KEY_GEN
from pkcs11.objects import make_aes_key_template
from storage.db import Storage


class TestHABehavior(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.storage = Storage(os.path.join(self.tmpdir, "test.db"), "master")
        self.api = PKCS11API(self.storage)
        self.api.C_Initialize()
        self.slots = [self.api.tokens.create_partition(f"member-{n}") for n in range(1, 4)]
        self.dm = Appliance(self.storage).deployment
        self.assertTrue(self.dm.create_ha_group("ha", self.slots[0])["success"])
        self.assertTrue(self.dm.add_ha_member("ha", self.slots[1])["success"])
        self.assertTrue(self.dm.add_ha_member("ha", self.slots[2])["success"])

    def tearDown(self):
        self.api.C_Finalize()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _generate(self, label: str, token: bool = True):
        session = self.api.C_OpenSession(self.slots[0])
        return self.api.C_GenerateKey(
            session, CKM_AES_KEY_GEN,
            make_aes_key_template(label, 128, token=token),
        )

    def test_round_robin_load_balancing(self):
        routed = [self.dm.route_ha_operation("ha", "sign")["slot_id"] for _ in range(4)]
        self.assertEqual(routed, [self.slots[0], self.slots[1], self.slots[2], self.slots[0]])
        self.assertEqual(self.dm.get_ha_status("ha")["operation_count"], 4)

    def test_active_standby_automatic_failover(self):
        self.dm.set_ha_mode("ha", "active-standby")
        self.dm.fail_ha_member("ha", self.slots[0], "power failure")
        routed = self.dm.route_ha_operation("ha", "decrypt")
        self.assertTrue(routed["success"])
        self.assertEqual(routed["slot_id"], self.slots[1])
        status = self.dm.get_ha_status("ha")
        self.assertEqual(status["state"], "degraded")
        self.assertEqual(status["failover_count"], 1)

    def test_network_partition_and_automatic_recovery(self):
        self.dm.set_ha_network_partition("ha", self.slots[1], True)
        member = self.dm.get_ha_status("ha")["member_status"][1]
        self.assertEqual(member["state"], "unavailable")
        self.assertTrue(member["network_partition"])
        result = self.dm.set_ha_network_partition("ha", self.slots[1], False)
        self.assertTrue(result["success"])
        recovered = self.dm.get_ha_status("ha")["member_status"][1]
        self.assertEqual(recovered["state"], "active")
        self.assertEqual(recovered["sync_status"], "current")

    def test_manual_recovery_and_retry_tracking(self):
        self.dm.set_ha_recovery_mode("ha", "manual")
        self.dm.fail_ha_member("ha", self.slots[1], "link down")
        result = self.dm.synchronize_ha_group("ha")
        self.assertFalse(result["success"])
        self.assertTrue(result["partial"])
        member = self.dm.get_ha_status("ha")["member_status"][1]
        self.assertEqual(member["retry_attempts"], 1)
        self.assertTrue(self.dm.recover_ha_member("ha", self.slots[1])["success"])

    def test_partial_synchronization_failure_is_per_member(self):
        self._generate("replicated-key")
        self.dm.set_ha_network_partition("ha", self.slots[2], True)
        result = self.dm.synchronize_ha_group("ha")
        self.assertFalse(result["success"])
        self.assertTrue(result["partial"])
        self.assertEqual(result["failures"][0]["slot_id"], self.slots[2])
        status = self.dm.get_ha_status("ha")["member_status"]
        self.assertEqual(status[1]["sync_status"], "current")
        self.assertEqual(status[2]["sync_status"], "out-of-sync")

    def test_only_persistent_objects_are_replicated(self):
        self._generate("token-key", token=True)
        self._generate("session-key", token=False)
        result = self.dm.synchronize_ha_group("ha")
        self.assertTrue(result["success"])
        for slot in self.slots[1:]:
            self.assertIsNotNone(self.storage.get_object_by_label(slot, "token-key")[0])
            self.assertIsNone(self.storage.get_object_by_label(slot, "session-key")[0])
        routed = self.dm.route_ha_operation("ha", "generate", session_object=True)
        self.assertFalse(routed["session_object_replicated"])

    def test_firmware_incompatibility_causes_partial_sync(self):
        self.dm.set_ha_member_firmware("ha", self.slots[2], "7.11.0")
        result = self.dm.synchronize_ha_group("ha")
        self.assertTrue(result["partial"])
        member = self.dm.get_ha_status("ha")["member_status"][2]
        self.assertEqual(member["state"], "incompatible")
        self.assertIn("FIRMWARE_MISMATCH", member["failure_reason"])

    def test_policy_incompatibility_causes_partial_sync(self):
        self.api.tokens.change_policy(self.slots[1], "ALLOW_SECRET_KEY_CLONING", 0)
        result = self.dm.synchronize_ha_group("ha")
        self.assertTrue(result["partial"])
        member = self.dm.get_ha_status("ha")["member_status"][1]
        self.assertEqual(member["state"], "incompatible")
        self.assertIn("POLICY_MISMATCH", member["failure_reason"])


if __name__ == "__main__":
    unittest.main()
