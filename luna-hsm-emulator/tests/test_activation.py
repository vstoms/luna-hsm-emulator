"""PED challenge secrets and cache lifetime across simulated device events."""
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from cli.commands import CommandHandler
from hsm.appliance import Appliance
from pkcs11.api import PKCS11API
from pkcs11.constants import *
from storage.db import Storage


class ActivationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.api = PKCS11API(Storage(os.path.join(self.tmp.name, "test.db"), "master"))
        self.api.C_Initialize()
        self.slot = self.api.tokens.create_partition("ped", version=1)
        self.api.tokens.init_token(self.slot, "password-so", "PED", "shared")
        for role in ("CO", "CU", "LCO"):
            self.api.tokens.init_pin(self.slot, "password-role", role)
        self.ped = self.api.auth.ped
        self.ped.configure_hsm("PED", "ped")
        self.ped.connect()
        self.keys = {}
        for role, color in (("SO", "blue"), ("CO", "black"), ("CU", "gray")):
            keyset = self.ped.create_key_set(color, m=2, n=3, scope=str(self.slot))
            self.keys[role] = [s["copies"][0]["serial"] for s in keyset["shares"][:2]]
        self.activation = self.api.auth.activation
        self.api.tokens.change_policy(self.slot, 22, 1)
        self.activation.create_challenge(self.slot, "CO", "challenge-co", "SO")

    def tearDown(self):
        self.api.C_Finalize()
        self.tmp.cleanup()

    def login(self, keys=None, secret="challenge-co"):
        session = self.api.C_OpenSession(self.slot)
        self.api.C_Login(session, CKU_USER, secret, ped_keys=keys)
        return session

    def test_initial_login_requires_both_factors_then_cache_allows_no_ped(self):
        with self.assertRaises(PKCS11Error):
            self.login()
        with self.assertRaises(PKCS11Error):
            self.login(self.keys["CO"][:1])
        self.assertFalse(self.activation.status(self.slot, "CO")["activated"])
        session = self.login(self.keys["CO"])
        self.api.C_Logout(session)
        self.api.C_CloseSession(session)
        self.ped.disconnect()
        session = self.login()
        self.assertTrue(self.api.auth.is_logged_in(session))
        self.assertTrue(self.activation.status(self.slot, "CO")["activated"])

    def test_wrong_challenge_cannot_use_cached_credential(self):
        self.api.C_CloseSession(self.login(self.keys["CO"]))
        self.ped.disconnect()
        with self.assertRaises(PKCS11Error) as error:
            self.login(secret="wrong-secret")
        self.assertEqual(error.exception.code, CKR_PIN_INCORRECT)

    def test_challenge_and_cache_are_not_plaintext(self):
        self.login(self.keys["CO"])
        raw = self.api.storage.get_meta(self.activation.META_KEY)
        self.assertNotIn("challenge-co", raw)
        for serial in self.keys["CO"]:
            self.assertNotIn(serial, raw)
        self.assertNotIn("hash", self.activation.status(self.slot, "CO"))
        audit = str(self.api.storage.get_audit_logs(100))
        self.assertNotIn("challenge-co", audit)

    def test_no_challenge_retains_legacy_ped_login(self):
        session = self.api.C_OpenSession(self.slot)
        self.api.C_Login(session, CKU_CONTEXT_SPECIFIC, ",".join(self.keys["CU"]))
        self.assertFalse(self.activation.status(self.slot, "CU")["activated"])

    def test_superior_role_hierarchy_and_po_cannot_activate(self):
        for role, actor in (("SO", "SO"), ("CO", "CU"), ("CU", "SO"), ("LCO", "CU")):
            with self.assertRaises(PKCS11Error):
                self.activation.create_challenge(self.slot, role, "new-challenge", actor, reset=True)
        for role in ("CU", "LCO"):
            self.activation.create_challenge(self.slot, role, "new-challenge", "CO")
        self.assertTrue(self.activation.status(self.slot, "LCO")["challenge_configured"])

    def test_client_restart_is_not_a_power_event(self):
        self.api.C_CloseSession(self.login(self.keys["CO"]))
        self.ped.disconnect()
        self.api.C_Finalize()
        self.api.C_Initialize()
        self.assertTrue(self.api.auth.is_logged_in(self.login()))

    def test_reboot_without_auto_requires_fresh_quorum_and_invalidates_sessions(self):
        session = self.login(self.keys["CO"])
        Appliance(self.api.storage).reboot()
        with self.assertRaises(PKCS11Error):
            self.api.C_GetSessionInfo(session)
        self.assertFalse(self.activation.status(self.slot, "CO")["activated"])
        with self.assertRaises(PKCS11Error):
            self.login()
        self.login(self.keys["CO"])

    def test_auto_activation_two_hour_boundary(self):
        self.api.tokens.change_policy(self.slot, 23, 1)
        self.login(self.keys["CO"])
        self.api.simulate_reboot(7200)
        self.ped.disconnect()
        self.login()
        self.api.simulate_reboot(7201)
        self.assertFalse(self.activation.status(self.slot, "CO")["activated"])
        with self.assertRaises(PKCS11Error):
            self.login()

    def test_auto_activation_arms_only_on_next_login(self):
        self.api.C_CloseSession(self.login(self.keys["CO"]))
        self.api.tokens.change_policy(self.slot, 23, 1)
        self.assertFalse(self.activation.status(self.slot, "CO")["auto_activation_armed"])
        self.api.simulate_reboot()
        with self.assertRaises(PKCS11Error):
            self.login()

    def test_poweroff_uses_elapsed_time_and_does_not_reset_timer(self):
        self.api.tokens.change_policy(self.slot, 23, 1)
        self.login(self.keys["CO"])
        appliance = Appliance(self.api.storage)
        with patch("hsm.activation.time.time", return_value=1000):
            appliance.poweroff()
        with patch("hsm.activation.time.time", return_value=2000):
            appliance.poweroff()
        self.assertEqual(self.activation.device_status()["off_since"], 1000)
        with self.assertRaises(PKCS11Error) as error:
            self.api.C_OpenSession(self.slot)
        self.assertEqual(error.exception.code, CKR_DEVICE_ERROR)
        with patch("hsm.activation.time.time", return_value=8300):
            appliance.reboot()
        self.assertFalse(self.activation.status(self.slot, "CO")["activated"])

    def test_tamper_zeros_cache_even_with_auto_activation(self):
        self.api.tokens.change_policy(self.slot, 23, 1)
        session = self.login(self.keys["CO"])
        self.api.simulate_tamper()
        self.assertFalse(self.activation.status(self.slot, "CO")["activated"])
        with self.assertRaises(PKCS11Error):
            self.api.C_Login(session, CKU_USER, "challenge-co")
        self.api.simulate_reboot(1)
        with self.assertRaises(PKCS11Error):
            self.api.C_OpenSession(self.slot)
        self.activation.clear_tamper()
        with self.assertRaises(PKCS11Error):
            self.login()
        self.login(self.keys["CO"])

    def test_deactivation_clears_cache_not_role_initialization(self):
        session = self.login(self.keys["CO"])
        self.api.tokens.deactivate_role(self.slot, "CO", actor_role="CO")
        self.assertTrue(self.api.tokens.lifecycle.role_active(self.slot, "CO"))
        self.assertFalse(self.activation.status(self.slot, "CO")["activated"])
        self.api.C_Logout(session)
        self.login(self.keys["CO"])

    def test_policy_disable_and_reenable_cannot_revive_cache(self):
        self.login(self.keys["CO"])
        self.api.tokens.change_policy(self.slot, 22, 0)
        self.api.tokens.change_policy(self.slot, 22, 1)
        self.assertFalse(self.activation.status(self.slot, "CO")["activated"])

    def test_failed_challenge_lockout_and_superior_reset(self):
        self.api.storage.set_partition_policy(self.slot, 20, 2)
        self.api.storage.set_partition_policy(self.slot, 15, 0)
        for _ in range(2):
            with self.assertRaises(PKCS11Error):
                self.login(secret="wrong-secret")
        with self.assertRaises(PKCS11Error) as error:
            self.login(self.keys["CO"])
        self.assertEqual(error.exception.code, CKR_PIN_LOCKED)
        self.activation.create_challenge(self.slot, "CO", "reset-secret", "SO", reset=True)
        self.login(self.keys["CO"], "reset-secret")

    def test_change_challenge_and_cli_cached_login(self):
        session = self.login(self.keys["CO"])
        self.activation.change_challenge(self.slot, "CO", "challenge-co", "changed-secret", "CO")
        self.api.C_CloseSession(session)
        self.ped.disconnect()
        handler = CommandHandler(self.api, self.slot)
        with patch("cli.commands.getpass.getpass", return_value="changed-secret"), \
                patch("builtins.input", side_effect=AssertionError("Must not prompt for PED")), \
                redirect_stdout(io.StringIO()):
            handler.cmd_role(["login", "-name", "co"])
        self.assertEqual(self.api.auth.get_role(handler.session_id), "CO")

    def test_invalid_downtime_and_secret_length(self):
        for value in (-1, float("nan"), float("inf")):
            with self.assertRaises(ValueError):
                self.activation.reboot(value)
        with self.assertRaises(PKCS11Error):
            self.activation.create_challenge(self.slot, "CU", "short", "CO")


if __name__ == "__main__":
    unittest.main()
