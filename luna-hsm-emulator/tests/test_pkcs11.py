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


class TestFirmwareUpgrade(unittest.TestCase):
    """Test HSM firmware upgrade, rollback, and history."""

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

    def test_default_firmware(self):
        """Test that the default firmware version is set."""
        info = self.api.tokens.get_hsm_info()
        self.assertEqual(info["firmware"], "7.13.0")

    def test_firmware_info(self):
        """Test firmware info retrieval."""
        info = self.api.tokens.get_firmware_info()
        self.assertEqual(info["current_version"], "7.13.0")
        self.assertTrue(info["update_available"])
        self.assertGreater(info["available_count"], 1)
        self.assertEqual(info["history"], [])

    def test_list_available_firmwares(self):
        """Test listing available firmware versions."""
        firmwares = self.api.tokens.list_available_firmwares()
        self.assertGreater(len(firmwares), 1)
        installed = [f for f in firmwares if f["installed"]]
        self.assertEqual(len(installed), 1)
        self.assertEqual(installed[0]["version"], "7.13.0")

    def test_upgrade_pre_check_nonexistent(self):
        """Test that pre-check fails for nonexistent version."""
        pre = self.api.tokens.check_firmware_upgrade("99.99.99")
        self.assertFalse(pre["can_upgrade"])

    def test_upgrade_pre_check_same_version(self):
        """Test that pre-check fails when target equals current."""
        pre = self.api.tokens.check_firmware_upgrade("7.13.0")
        self.assertFalse(pre["can_upgrade"])

    def test_upgrade_pre_check_valid(self):
        """Test that pre-check passes for a valid upgrade target."""
        pre = self.api.tokens.check_firmware_upgrade("7.14.0")
        self.assertTrue(pre["can_upgrade"])
        self.assertEqual(len(pre["checks"]), 6)

    def test_perform_upgrade(self):
        """Test a successful firmware upgrade."""
        result = self.api.tokens.perform_firmware_upgrade("7.14.0", audit=self.api.audit)
        self.assertTrue(result["success"])
        self.assertEqual(result["previous_version"], "7.13.0")
        self.assertEqual(result["new_version"], "7.14.0")
        self.assertEqual(len(result["stages"]), 7)
        # Verify version persisted
        self.assertEqual(self.api.tokens._get_firmware_version(), "7.14.0")
        # Verify history recorded
        history = self.api.tokens._get_firmware_history()
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["from_version"], "7.13.0")
        self.assertEqual(history[0]["to_version"], "7.14.0")

    def test_upgrade_persists_across_reopen(self):
        """Test that firmware version persists after DB close/reopen."""
        self.api.tokens.perform_firmware_upgrade("7.15.0", audit=self.api.audit)
        self.api.C_Finalize()
        storage2 = Storage(db_path=self.db_path, master_password="testpass")
        api2 = PKCS11API(storage2)
        api2.C_Initialize()
        self.assertEqual(api2.tokens._get_firmware_version(), "7.15.0")
        history = api2.tokens._get_firmware_history()
        self.assertEqual(len(history), 1)
        api2.C_Finalize()

    def test_rollback(self):
        """Test firmware rollback after upgrade."""
        # First upgrade
        self.api.tokens.perform_firmware_upgrade("7.14.0", audit=self.api.audit)
        self.assertEqual(self.api.tokens._get_firmware_version(), "7.14.0")
        # Roll back
        result = self.api.tokens.rollback_firmware(audit=self.api.audit)
        self.assertTrue(result["success"])
        self.assertEqual(result["previous_version"], "7.14.0")
        self.assertEqual(result["new_version"], "7.13.0")
        # Verify history has rollback marker
        history = self.api.tokens._get_firmware_history()
        self.assertGreaterEqual(len(history), 2)

    def test_rollback_no_history(self):
        """Test that rollback fails when there's no history."""
        result = self.api.tokens.rollback_firmware()
        self.assertFalse(result["success"])
        self.assertIn("No firmware history", result["error"])

    def test_downgrade(self):
        """Test that downgrade (to older version) works with warnings."""
        # First upgrade to 7.14.0
        self.api.tokens.perform_firmware_upgrade("7.14.0", audit=self.api.audit)
        # Now downgrade to 7.12.0
        pre = self.api.tokens.check_firmware_upgrade("7.12.0")
        self.assertTrue(pre["can_upgrade"])
        self.assertTrue(any("Downgrading" in w for w in pre["warnings"]))
        result = self.api.tokens.perform_firmware_upgrade("7.12.0", audit=self.api.audit)
        self.assertTrue(result["success"])
        self.assertEqual(result["new_version"], "7.12.0")

    def test_factory_reset_clears_firmware(self):
        """Test that factory reset restores default firmware version."""
        self.api.tokens.perform_firmware_upgrade("7.15.0", audit=self.api.audit)
        self.api.tokens.factory_reset()
        self.assertEqual(self.api.tokens._get_firmware_version(), "7.13.0")
        self.assertEqual(self.api.tokens._get_firmware_history(), [])

    def test_firmware_upgrade_audited(self):
        """Test that firmware upgrade is recorded in audit log."""
        self.api.tokens.perform_firmware_upgrade("7.14.0", audit=self.api.audit)
        logs = self.api.storage.get_audit_logs()
        ops = [l["operation"] for l in logs]
        self.assertIn("FirmwareUpgrade", ops)

    def test_show_firmware_history(self):
        """Test formatted firmware history output."""
        self.api.tokens.perform_firmware_upgrade("7.14.0", audit=self.api.audit)
        self.api.tokens.perform_firmware_upgrade("7.15.0", audit=self.api.audit)
        output = self.api.tokens.show_firmware_history()
        self.assertIn("7.13.0", output)
        self.assertIn("7.14.0", output)
        self.assertIn("7.15.0", output)


class TestPartitionCommands(unittest.TestCase):
    """Test the new LunaCM partition commands."""

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

    def test_partition_init(self):
        """Test partition init (initialize with SO PIN)."""
        self.api.tokens.init_partition(
            self.slot_id, "sopin123", "NewLabel",
            audit=self.api.audit, session_id=self.session_id
        )
        p = self.storage.get_partition(self.slot_id)
        self.assertTrue(p["initialized"])
        self.assertEqual(p["label"], "NewLabel")

    def test_partition_init_already_initialized(self):
        """Test that init fails on already-initialized partition."""
        self.api.tokens.init_partition(self.slot_id, "sopin123", audit=self.api.audit)
        with self.assertRaises(PKCS11Error):
            self.api.tokens.init_partition(self.slot_id, "sopin456")

    def test_partition_changelabel(self):
        """Test changing partition label."""
        self.api.tokens.init_partition(self.slot_id, "sopin123", "OldLabel", audit=self.api.audit)
        self.api.tokens.change_partition_label(self.slot_id, "NewLabel", audit=self.api.audit)
        p = self.storage.get_partition(self.slot_id)
        self.assertEqual(p["label"], "NewLabel")

    def test_partition_clear(self):
        """Test clearing all objects from a partition."""
        tmpl = make_aes_key_template("k1", 256)
        self.api.C_GenerateKey(self.session_id, CKM_AES_KEY_GEN, tmpl)
        tmpl2 = make_aes_key_template("k2", 256)
        self.api.C_GenerateKey(self.session_id, CKM_AES_KEY_GEN, tmpl2)
        count = self.api.tokens.clear_partition(self.slot_id, audit=self.api.audit)
        self.assertEqual(count, 2)
        self.assertEqual(self.storage.count_objects(self.slot_id), 0)

    def test_partition_contents(self):
        """Test showing partition contents."""
        tmpl = make_aes_key_template("contents_key", 256)
        self.api.C_GenerateKey(self.session_id, CKM_AES_KEY_GEN, tmpl)
        output = self.api.tokens.show_partition_contents(self.slot_id)
        self.assertIn("contents_key", output)
        self.assertIn("CKO_SECRET_KEY", output)

    def test_partition_contents_empty(self):
        """Test showing empty partition contents."""
        output = self.api.tokens.show_partition_contents(self.slot_id)
        self.assertIn("empty", output)

    def test_partition_showmechanism(self):
        """Test showing available mechanisms."""
        output = self.api.tokens.show_mechanisms(self.slot_id)
        self.assertIn("CKM_AES_GCM", output)
        self.assertIn("CKM_SHA256_RSA_PKCS", output)
        self.assertIn("enc", output)
        self.assertIn("sign", output)

    def test_partition_showpolicies(self):
        """Test showing partition policies."""
        output = self.api.tokens.show_policies(self.slot_id)
        self.assertIn("ALLOW_KEY_CLONE", output)
        self.assertIn("MAX_LOGIN_ATTEMPTS", output)

    def test_partition_changepolicy(self):
        """Test changing a partition policy."""
        self.api.tokens.change_policy(self.slot_id, "MAX_LOGIN_ATTEMPTS", "5",
                                        audit=self.api.audit)
        p = self.storage.get_partition(self.slot_id)
        self.assertEqual(p["max_login_attempts"], 5)

    def test_partition_changepolicy_invalid(self):
        """Test that changing an invalid policy fails."""
        with self.assertRaises(PKCS11Error):
            self.api.tokens.change_policy(self.slot_id, "NONEXISTENT_POLICY", "1")


class TestRoleCommands(unittest.TestCase):
    """Test the new LunaCM role commands."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test.db")
        self.storage = Storage(db_path=self.db_path, master_password="testpass")
        self.api = PKCS11API(self.storage)
        self.api.C_Initialize()
        self.slot_id = self.api.tokens.create_partition("test", "Test")
        self.api.tokens.init_token(self.slot_id, "sopin123", "Test")
        self.session_id = self.api.C_OpenSession(self.slot_id)

    def tearDown(self):
        self.api.C_Finalize()
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_role_list(self):
        """Test listing roles on a partition."""
        output = self.api.tokens.list_roles(self.slot_id)
        self.assertIn("SO", output)
        self.assertIn("CO", output)
        self.assertIn("CU", output)
        self.assertIn("Security Officer", output)

    def test_role_show(self):
        """Test showing a specific role."""
        output = self.api.tokens.show_role(self.slot_id, "SO")
        self.assertIn("Security Officer", output)
        self.assertIn("PIN Initialized: Yes", output)

    def test_role_show_unknown(self):
        """Test showing an unknown role."""
        output = self.api.tokens.show_role(self.slot_id, "UNKNOWN")
        self.assertIn("Unknown role", output)

    def test_role_init_cu(self):
        """Test initializing the CU role."""
        self.api.tokens.init_role(self.slot_id, "CU", "cupin123",
                                   audit=self.api.audit, session_id=self.session_id)
        p = self.storage.get_partition(self.slot_id)
        self.assertIsNotNone(p["cu_pin_hash"])

    def test_role_init_invalid_role(self):
        """Test that init fails for SO role."""
        with self.assertRaises(PKCS11Error):
            self.api.tokens.init_role(self.slot_id, "SO", "newpin123")

    def test_role_deactivate(self):
        """Test deactivating a role."""
        self.api.tokens.init_pin(self.slot_id, "copin123", "CO")
        self.api.tokens.deactivate_role(self.slot_id, "CO",
                                         audit=self.api.audit, session_id=self.session_id)
        p = self.storage.get_partition(self.slot_id)
        self.assertIsNone(p["co_pin_hash"])

    def test_role_resetpw(self):
        """Test resetting a role PIN."""
        self.api.tokens.init_pin(self.slot_id, "copin123", "CO")
        self.api.tokens.reset_pin(self.slot_id, "CO", "newcopin456",
                                   audit=self.api.audit, session_id=self.session_id)
        # Verify the new PIN works
        sid = self.api.C_OpenSession(self.slot_id)
        from pkcs11.constants import CKU_USER
        self.api.C_Login(sid, CKU_USER, "newcopin456")
        self.assertTrue(self.api.auth.is_logged_in(sid))

    def test_role_resetpw_invalid_role(self):
        """Test that resetpw fails for SO role."""
        with self.assertRaises(PKCS11Error):
            self.api.tokens.reset_pin(self.slot_id, "SO", "newpin123")


if __name__ == "__main__":
    unittest.main()
