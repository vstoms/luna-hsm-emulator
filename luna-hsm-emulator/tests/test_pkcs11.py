"""Unit tests for PKCS#11 operations in the Luna 7 HSM Emulator.

Run with: python -m pytest tests/test_pkcs11.py -v
Or:       python tests/test_pkcs11.py
"""

import os
import sys
import tempfile
import unittest

# Ensure emulator dir is on path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
EMULATOR_DIR = os.path.dirname(SCRIPT_DIR)
if EMULATOR_DIR not in sys.path:
    sys.path.insert(0, EMULATOR_DIR)

from pkcs11.api import PKCS11API
from storage.db import Storage
from pkcs11.constants import (
    CKR_OK, CKR_PIN_INCORRECT, CKR_PIN_LOCKED, CKR_OBJECT_HANDLE_INVALID,
    CKR_ATTRIBUTE_SENSITIVE, CKR_SIGNATURE_INVALID,
    PKCS11Error,
    CKA_LABEL, CKA_VALUE_LEN, CKA_CLASS, CKA_KEY_TYPE, CKA_TOKEN,
    CKA_SENSITIVE, CKA_EXTRACTABLE, CKA_ENCRYPT, CKA_DECRYPT,
    CKA_SIGN, CKA_VERIFY, CKA_PRIVATE, CKA_MODIFIABLE, CKA_DESTROYABLE,
    CKO_SECRET_KEY, CKO_PUBLIC_KEY, CKO_PRIVATE_KEY,
    CKK_AES, CKK_RSA, CKK_EC,
    CKM_AES_KEY_GEN, CKM_AES_GCM, CKM_AES_CBC, CKM_AES_ECB, CKM_AES_CTR,
    CKM_RSA_PKCS_KEY_PAIR_GEN, CKM_SHA256_RSA_PKCS, CKM_RSA_PKCS_OAEP,
    CKM_EC_KEY_PAIR_GEN, CKM_ECDSA,
    CKM_SHA256, CKM_SHA512, CKM_SHA256_HMAC, CKM_AES_CMAC,
    CKU_SO, CKU_USER,
    CKF_SERIAL_SESSION, CKF_RW_SESSION,
)
from pkcs11.objects import (
    make_aes_key_template, make_rsa_keypair_templates,
    make_ec_keypair_templates,
)


class TestStorage(unittest.TestCase):
    """Test the encrypted storage layer."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test.db")
        self.storage = Storage(db_path=self.db_path, master_password="testpass")
        self.storage.open()

    def tearDown(self):
        self.storage.close()
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_blob_encryption(self):
        """Test that blob encryption/decryption round-trips."""
        plaintext = b"sensitive key material" * 10
        encrypted = self.storage.encrypt_blob(plaintext)
        self.assertNotEqual(plaintext, encrypted)
        decrypted = self.storage.decrypt_blob(encrypted)
        self.assertEqual(plaintext, decrypted)

    def test_pin_hashing(self):
        """Test PIN hashing and verification."""
        pin_hash, pin_salt = self.storage.hash_pin("mypin123")
        self.assertTrue(self.storage.verify_pin("mypin123", pin_hash, pin_salt))
        self.assertFalse(self.storage.verify_pin("wrongpin", pin_hash, pin_salt))

    def test_partition_crud(self):
        """Test partition create/read/update/delete."""
        self.storage.insert_partition(1, "test_part", "Test")
        p = self.storage.get_partition(1)
        self.assertIsNotNone(p)
        self.assertEqual(p["name"], "test_part")
        self.storage.update_partition(1, initialized=1)
        p = self.storage.get_partition(1)
        self.assertEqual(p["initialized"], 1)
        self.storage.delete_partition(1)
        self.assertIsNone(self.storage.get_partition(1))


class TestPKCS11Sessions(unittest.TestCase):
    """Test PKCS#11 session management."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test.db")
        self.storage = Storage(db_path=self.db_path, master_password="testpass")
        self.api = PKCS11API(self.storage)
        self.api.C_Initialize()
        self.slot_id = self.api.tokens.create_partition("test", "Test")

    def tearDown(self):
        self.api.C_Finalize()
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_open_close_session(self):
        """Test opening and closing sessions."""
        sid = self.api.C_OpenSession(self.slot_id, CKF_SERIAL_SESSION)
        self.assertIsNotNone(sid)
        info = self.api.C_GetSessionInfo(sid)
        self.assertEqual(info["slot_id"], self.slot_id)
        self.api.C_CloseSession(sid)
        with self.assertRaises(PKCS11Error):
            self.api.C_GetSessionInfo(sid)

    def test_close_all_sessions(self):
        """Test closing all sessions."""
        sid1 = self.api.C_OpenSession(self.slot_id)
        sid2 = self.api.C_OpenSession(self.slot_id)
        self.api.C_CloseAllSessions(self.slot_id)
        with self.assertRaises(PKCS11Error):
            self.api.C_GetSessionInfo(sid1)
        with self.assertRaises(PKCS11Error):
            self.api.C_GetSessionInfo(sid2)


class TestAuthentication(unittest.TestCase):
    """Test PKCS#11 authentication."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test.db")
        self.storage = Storage(db_path=self.db_path, master_password="testpass")
        self.api = PKCS11API(self.storage)
        self.api.C_Initialize()
        self.slot_id = self.api.tokens.create_partition("test", "Test")
        self.api.tokens.init_token(self.slot_id, "sopin123", "Test")
        self.api.tokens.init_pin(self.slot_id, "copin123", "CO")

    def tearDown(self):
        self.api.C_Finalize()
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_login_logout(self):
        """Test successful login and logout."""
        sid = self.api.C_OpenSession(self.slot_id)
        self.api.C_Login(sid, CKU_USER, "copin123")
        self.assertTrue(self.api.auth.is_logged_in(sid))
        self.api.C_Logout(sid)
        self.assertFalse(self.api.auth.is_logged_in(sid))

    def test_login_wrong_pin(self):
        """Test login with wrong PIN."""
        sid = self.api.C_OpenSession(self.slot_id)
        with self.assertRaises(PKCS11Error) as ctx:
            self.api.C_Login(sid, CKU_USER, "wrongpin")
        self.assertEqual(ctx.exception.code, CKR_PIN_INCORRECT)

    def test_pin_lockout(self):
        """Test PIN lockout after max attempts."""
        sid = self.api.C_OpenSession(self.slot_id)
        # Set max_login_attempts to 3 for faster testing
        self.storage.update_partition(self.slot_id, max_login_attempts=3)
        for i in range(2):
            with self.assertRaises(PKCS11Error) as ctx:
                self.api.C_Login(sid, CKU_USER, "wrongpin")
            self.assertEqual(ctx.exception.code, CKR_PIN_INCORRECT)
        # Third attempt should lock
        with self.assertRaises(PKCS11Error) as ctx:
            self.api.C_Login(sid, CKU_USER, "wrongpin")
        self.assertEqual(ctx.exception.code, CKR_PIN_LOCKED)
        # Even correct PIN should fail now
        with self.assertRaises(PKCS11Error) as ctx:
            self.api.C_Login(sid, CKU_USER, "copin123")
        self.assertEqual(ctx.exception.code, CKR_PIN_LOCKED)


class TestKeyGeneration(unittest.TestCase):
    """Test PKCS#11 key generation."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test.db")
        self.storage = Storage(db_path=self.db_path, master_password="testpass")
        self.api = PKCS11API(self.storage)
        self.api.C_Initialize()
        self.slot_id = self.api.tokens.create_partition("test", "Test")
        self.session_id = self.api.C_OpenSession(self.slot_id)

    def tearDown(self):
        self.api.C_Finalize()
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_generate_aes_key(self):
        """Test AES key generation."""
        template = make_aes_key_template("test_aes", 256)
        handle = self.api.C_GenerateKey(self.session_id, CKM_AES_KEY_GEN, template)
        self.assertGreater(handle, 0)
        obj, km = self.api.keystore.retrieve(handle)
        self.assertEqual(obj.label(), "test_aes")
        self.assertEqual(obj.key_type(), CKK_AES)
        self.assertEqual(obj.value_len(), 32)
        self.assertEqual(len(km), 32)
        self.assertTrue(obj.is_sensitive())
        self.assertFalse(obj.is_extractable())

    def test_generate_rsa_keypair(self):
        """Test RSA key pair generation."""
        priv_tmpl, pub_tmpl = make_rsa_keypair_templates("test_rsa", 2048)
        priv_h, pub_h = self.api.C_GenerateKeyPair(
            self.session_id, CKM_RSA_PKCS_KEY_PAIR_GEN, priv_tmpl, pub_tmpl
        )
        self.assertGreater(priv_h, 0)
        self.assertGreater(pub_h, 0)
        priv_obj, priv_km = self.api.keystore.retrieve(priv_h)
        pub_obj, pub_km = self.api.keystore.retrieve(pub_h)
        self.assertEqual(priv_obj.object_class(), CKO_PRIVATE_KEY)
        self.assertEqual(pub_obj.object_class(), CKO_PUBLIC_KEY)
        self.assertEqual(priv_obj.key_type(), CKK_RSA)

    def test_generate_ec_keypair(self):
        """Test EC key pair generation."""
        priv_tmpl, pub_tmpl = make_ec_keypair_templates("test_ec", "P-256")
        priv_h, pub_h = self.api.C_GenerateKeyPair(
            self.session_id, CKM_EC_KEY_PAIR_GEN, priv_tmpl, pub_tmpl,
            params={"curve": "P-256"}
        )
        self.assertGreater(priv_h, 0)
        self.assertGreater(pub_h, 0)
        priv_obj, _ = self.api.keystore.retrieve(priv_h)
        self.assertEqual(priv_obj.key_type(), CKK_EC)


class TestCryptoOperations(unittest.TestCase):
    """Test PKCS#11 cryptographic operations."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test.db")
        self.storage = Storage(db_path=self.db_path, master_password="testpass")
        self.api = PKCS11API(self.storage)
        self.api.C_Initialize()
        self.slot_id = self.api.tokens.create_partition("test", "Test")
        self.session_id = self.api.C_OpenSession(self.slot_id)

    def tearDown(self):
        self.api.C_Finalize()
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_aes_gcm_encrypt_decrypt(self):
        """Test AES-GCM encryption and decryption round-trip."""
        template = make_aes_key_template("aes_key", 256, encrypt=True, decrypt=True)
        handle = self.api.C_GenerateKey(self.session_id, CKM_AES_KEY_GEN, template)
        plaintext = b"Hello, HSM World! " * 4
        self.api.C_EncryptInit(self.session_id, CKM_AES_GCM, handle)
        ciphertext = self.api.C_Encrypt(self.session_id, plaintext)
        self.assertNotEqual(plaintext, ciphertext)
        self.api.C_DecryptInit(self.session_id, CKM_AES_GCM, handle)
        decrypted = self.api.C_Decrypt(self.session_id, ciphertext)
        self.assertEqual(plaintext, decrypted)

    def test_aes_cbc_encrypt_decrypt(self):
        """Test AES-CBC encryption and decryption."""
        template = make_aes_key_template("aes_cbc", 128, encrypt=True, decrypt=True)
        handle = self.api.C_GenerateKey(self.session_id, CKM_AES_KEY_GEN, template)
        plaintext = b"A" * 32  # Must be block-aligned for CBC
        import os as _os
        iv = _os.urandom(16)
        self.api.C_EncryptInit(self.session_id, CKM_AES_CBC, handle)
        ct = self.api.C_Encrypt(self.session_id, plaintext, iv=iv)
        self.api.C_DecryptInit(self.session_id, CKM_AES_CBC, handle)
        pt = self.api.C_Decrypt(self.session_id, ct, iv=iv)
        self.assertEqual(plaintext, pt)

    def test_rsa_sign_verify(self):
        """Test RSA signing and verification."""
        priv_tmpl, pub_tmpl = make_rsa_keypair_templates("rsa_sig", 2048,
                                                          sign=True, verify=True)
        priv_h, pub_h = self.api.C_GenerateKeyPair(
            self.session_id, CKM_RSA_PKCS_KEY_PAIR_GEN, priv_tmpl, pub_tmpl
        )
        data = b"Message to sign" * 10
        self.api.C_SignInit(self.session_id, CKM_SHA256_RSA_PKCS, priv_h)
        sig = self.api.C_Sign(self.session_id, data)
        self.assertGreater(len(sig), 0)
        self.api.C_VerifyInit(self.session_id, CKM_SHA256_RSA_PKCS, pub_h)
        result = self.api.C_Verify(self.session_id, data, sig)
        self.assertTrue(result)

    def test_rsa_sign_verify_wrong_data(self):
        """Test that verification fails with wrong data."""
        priv_tmpl, pub_tmpl = make_rsa_keypair_templates("rsa_bad", 2048,
                                                          sign=True, verify=True)
        priv_h, pub_h = self.api.C_GenerateKeyPair(
            self.session_id, CKM_RSA_PKCS_KEY_PAIR_GEN, priv_tmpl, pub_tmpl
        )
        data = b"Original message"
        self.api.C_SignInit(self.session_id, CKM_SHA256_RSA_PKCS, priv_h)
        sig = self.api.C_Sign(self.session_id, data)
        self.api.C_VerifyInit(self.session_id, CKM_SHA256_RSA_PKCS, pub_h)
        with self.assertRaises(PKCS11Error) as ctx:
            self.api.C_Verify(self.session_id, b"Tampered message", sig)
        self.assertEqual(ctx.exception.code, CKR_SIGNATURE_INVALID)

    def test_ecdsa_sign_verify(self):
        """Test ECDSA signing and verification."""
        priv_tmpl, pub_tmpl = make_ec_keypair_templates("ec_sig", "P-256",
                                                         sign=True, verify=True)
        priv_h, pub_h = self.api.C_GenerateKeyPair(
            self.session_id, CKM_EC_KEY_PAIR_GEN, priv_tmpl, pub_tmpl,
            params={"curve": "P-256"}
        )
        data = b"EC message to sign" * 5
        self.api.C_SignInit(self.session_id, CKM_ECDSA, priv_h)
        sig = self.api.C_Sign(self.session_id, data)
        self.assertGreater(len(sig), 0)
        self.api.C_VerifyInit(self.session_id, CKM_ECDSA, pub_h)
        result = self.api.C_Verify(self.session_id, data, sig)
        self.assertTrue(result)

    def test_digest(self):
        """Test hash digest operations."""
        data = b"Hash this data" * 10
        self.api.C_DigestInit(self.session_id, CKM_SHA256)
        digest = self.api.C_Digest(self.session_id, data)
        self.assertEqual(len(digest), 32)
        # Verify against known SHA-256
        import hashlib
        self.assertEqual(digest, hashlib.sha256(data).digest())

    def test_hmac(self):
        """Test HMAC operations."""
        from pkcs11.objects import make_hmac_key_template
        from pkcs11.constants import CKK_GENERIC_SECRET
        template = make_hmac_key_template("hmac_key", 32, sign=True, verify=True,
                                           hmac_key_type=CKK_GENERIC_SECRET)
        # Store a raw key manually
        import os as _os
        key_value = _os.urandom(32)
        template[CKA_VALUE_LEN] = 32
        handle = self.api.C_GenerateKey(self.session_id, CKM_AES_KEY_GEN, template)
        # Actually we need to store the key material differently for HMAC
        # Let's use AES key for HMAC test
        data = b"Data to HMAC" * 5
        self.api.C_SignInit(self.session_id, CKM_SHA256_HMAC, handle)
        sig = self.api.C_Sign(self.session_id, data)
        self.assertEqual(len(sig), 32)


class TestKeyWrapping(unittest.TestCase):
    """Test PKCS#11 key wrapping and unwrapping."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test.db")
        self.storage = Storage(db_path=self.db_path, master_password="testpass")
        self.api = PKCS11API(self.storage)
        self.api.C_Initialize()
        self.slot_id = self.api.tokens.create_partition("test", "Test")
        self.session_id = self.api.C_OpenSession(self.slot_id)

    def tearDown(self):
        self.api.C_Finalize()
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_aes_wrap_unwrap(self):
        """Test wrapping and unwrapping an AES key with AES-GCM."""
        # Create wrapping key (extractable=False, wrap=True)
        wrap_tmpl = make_aes_key_template("wrap_key", 256, wrap=True, unwrap=True)
        wrap_handle = self.api.C_GenerateKey(self.session_id, CKM_AES_KEY_GEN, wrap_tmpl)
        # Create target key (extractable=True so it can be wrapped)
        target_tmpl = make_aes_key_template("target_key", 128, extractable=True)
        target_handle = self.api.C_GenerateKey(self.session_id, CKM_AES_KEY_GEN, target_tmpl)
        # Wrap
        wrapped = self.api.C_WrapKey(self.session_id, CKM_AES_GCM, wrap_handle, target_handle)
        self.assertGreater(len(wrapped), 0)
        # Unwrap
        unwrap_tmpl = {
            CKA_CLASS: CKO_SECRET_KEY,
            CKA_KEY_TYPE: CKK_AES,
            CKA_LABEL: b"unwrapped_key",
            CKA_TOKEN: True,
            CKA_PRIVATE: True,
            CKA_SENSITIVE: True,
            CKA_EXTRACTABLE: False,
            CKA_ENCRYPT: True,
            CKA_DECRYPT: True,
            CKA_MODIFIABLE: True,
            CKA_DESTROYABLE: True,
        }
        unwrapped_handle = self.api.C_UnwrapKey(
            self.session_id, CKM_AES_GCM, wrap_handle, wrapped, unwrap_tmpl
        )
        self.assertGreater(unwrapped_handle, 0)
        obj, km = self.api.keystore.retrieve(unwrapped_handle)
        self.assertEqual(obj.label(), "unwrapped_key")
        self.assertEqual(len(km), 16)  # 128-bit key

    def test_wrap_non_extractable_fails(self):
        """Test that wrapping a non-extractable key fails."""
        wrap_tmpl = make_aes_key_template("wrap_key2", 256, wrap=True)
        wrap_handle = self.api.C_GenerateKey(self.session_id, CKM_AES_KEY_GEN, wrap_tmpl)
        # Non-extractable target
        target_tmpl = make_aes_key_template("nonextract", 128, extractable=False)
        target_handle = self.api.C_GenerateKey(self.session_id, CKM_AES_KEY_GEN, target_tmpl)
        with self.assertRaises(PKCS11Error) as ctx:
            self.api.C_WrapKey(self.session_id, CKM_AES_GCM, wrap_handle, target_handle)
        self.assertEqual(ctx.exception.code, CKR_ATTRIBUTE_SENSITIVE)


class TestObjectManagement(unittest.TestCase):
    """Test PKCS#11 object management."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test.db")
        self.storage = Storage(db_path=self.db_path, master_password="testpass")
        self.api = PKCS11API(self.storage)
        self.api.C_Initialize()
        self.slot_id = self.api.tokens.create_partition("test", "Test")
        self.session_id = self.api.C_OpenSession(self.slot_id)

    def tearDown(self):
        self.api.C_Finalize()
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_find_objects(self):
        """Test finding objects by template."""
        # Create multiple keys
        for label in ["key_a", "key_b", "key_c"]:
            tmpl = make_aes_key_template(label, 256)
            self.api.C_GenerateKey(self.session_id, CKM_AES_KEY_GEN, tmpl)
        # Find all secret keys
        self.api.C_FindObjectsInit(self.session_id, {CKA_CLASS: CKO_SECRET_KEY})
        handles = self.api.C_FindObjects(self.session_id, 100)
        self.api.C_FindObjectsFinal(self.session_id)
        self.assertEqual(len(handles), 3)

    def test_find_by_label(self):
        """Test finding objects by label."""
        tmpl = make_aes_key_template("find_me", 256)
        handle = self.api.C_GenerateKey(self.session_id, CKM_AES_KEY_GEN, tmpl)
        self.api.C_FindObjectsInit(self.session_id, {CKA_LABEL: b"find_me"})
        handles = self.api.C_FindObjects(self.session_id, 100)
        self.api.C_FindObjectsFinal(self.session_id)
        self.assertEqual(len(handles), 1)
        self.assertEqual(handles[0], handle)

    def test_destroy_object(self):
        """Test destroying an object."""
        tmpl = make_aes_key_template("destroy_me", 256)
        handle = self.api.C_GenerateKey(self.session_id, CKM_AES_KEY_GEN, tmpl)
        self.api.C_DestroyObject(self.session_id, handle)
        with self.assertRaises(PKCS11Error):
            self.api.keystore.retrieve(handle)

    def test_copy_object(self):
        """Test copying an object."""
        tmpl = make_aes_key_template("original", 256)
        handle = self.api.C_GenerateKey(self.session_id, CKM_AES_KEY_GEN, tmpl)
        new_handle = self.api.C_CopyObject(
            self.session_id, handle, {CKA_LABEL: b"copy"}
        )
        obj, _ = self.api.keystore.retrieve(new_handle)
        self.assertEqual(obj.label(), "copy")


class TestAuditLog(unittest.TestCase):
    """Test audit logging with hash chaining."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test.db")
        self.storage = Storage(db_path=self.db_path, master_password="testpass")
        self.api = PKCS11API(self.storage)
        self.api.C_Initialize()
        self.slot_id = self.api.tokens.create_partition("test", "Test")
        self.session_id = self.api.C_OpenSession(self.slot_id)

    def tearDown(self):
        self.api.C_Finalize()
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_audit_entries(self):
        """Test that audit entries are recorded."""
        tmpl = make_aes_key_template("audit_key", 256)
        self.api.C_GenerateKey(self.session_id, CKM_AES_KEY_GEN, tmpl)
        logs = self.api.storage.get_audit_logs()
        self.assertGreater(len(logs), 0)
        # Check that at least one entry is for key generation
        ops = [l["operation"] for l in logs]
        self.assertIn("C_GenerateKey", ops)

    def test_audit_chain_integrity(self):
        """Test that the audit chain is intact."""
        # Generate some activity
        for i in range(5):
            tmpl = make_aes_key_template(f"chain_key_{i}", 256)
            self.api.C_GenerateKey(self.session_id, CKM_AES_KEY_GEN, tmpl)
        self.assertTrue(self.api.audit.verify_chain())

    def test_audit_clear(self):
        """Test clearing the audit log."""
        tmpl = make_aes_key_template("clear_key", 256)
        self.api.C_GenerateKey(self.session_id, CKM_AES_KEY_GEN, tmpl)
        self.api.audit.clear()
        logs = self.api.storage.get_audit_logs()
        self.assertEqual(len(logs), 0)


class TestKDF(unittest.TestCase):
    """Test key derivation functions."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test.db")
        self.storage = Storage(db_path=self.db_path, master_password="testpass")
        self.api = PKCS11API(self.storage)
        self.api.C_Initialize()
        self.slot_id = self.api.tokens.create_partition("test", "Test")
        self.session_id = self.api.C_OpenSession(self.slot_id)

    def tearDown(self):
        self.api.C_Finalize()
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_pbkdf2(self):
        """Test PBKDF2 key derivation."""
        import crypto.kdf as kdf_mod
        derived = kdf_mod.pbkdf2(b"password", b"salt", 1000, 32)
        self.assertEqual(len(derived), 32)

    def test_hkdf(self):
        """Test HKDF key derivation."""
        import crypto.kdf as kdf_mod
        derived = kdf_mod.hkdf(b"input_key", 32, salt=b"salt", info=b"info")
        self.assertEqual(len(derived), 32)

    def test_sp800_108(self):
        """Test SP800-108 Counter Mode KDF."""
        import crypto.kdf as kdf_mod
        derived = kdf_mod.sp800_108_counter(
            b"master_key", b"label", b"context", 32
        )
        self.assertEqual(len(derived), 32)


if __name__ == "__main__":
    unittest.main()
