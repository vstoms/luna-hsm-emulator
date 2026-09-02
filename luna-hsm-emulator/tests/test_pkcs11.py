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
from hsm.backup import BackupHSM, BACKUP_HSM_MODEL, BACKUP_HSM_DEFAULT_FW


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
        self.assertIn("ALLOW_PRIVATE_KEY_CLONING", output)
        self.assertIn("MAX_LOGIN_ATTEMPTS", output)

    def test_partition_changepolicy(self):
        """Test changing a partition policy."""
        self.api.tokens.change_policy(self.slot_id, "MAX_LOGIN_ATTEMPTS", "5",
                                        audit=self.api.audit, force=True)
        self.assertEqual(self.api.tokens.get_policy_value(self.slot_id, "MAX_LOGIN_ATTEMPTS"), 5)

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


class TestBackupHSM(unittest.TestCase):
    """Test Luna Backup HSM 7 operations."""

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

    def _setup_backup_hsm(self):
        """Helper: connect, recover STM, init, and login to backup HSM."""
        self.api.backup.connect()
        self.api.backup.stm_recover("test_random_string", audit=self.api.audit)
        self.api.backup.initialize("bkupso123", audit=self.api.audit)
        self.api.backup.login("bkupso123", audit=self.api.audit)

    def test_backup_connect(self):
        """Test connecting a backup HSM."""
        result = self.api.backup.connect()
        self.assertTrue(result["serial"])
        self.assertIn("model", result)

    def test_backup_connect_already_connected(self):
        """Test that connecting twice returns already_connected."""
        self.api.backup.connect()
        result = self.api.backup.connect()
        self.assertTrue(result["already_connected"])

    def test_backup_disconnect(self):
        """Test disconnecting the backup HSM."""
        self.api.backup.connect()
        self.assertTrue(self.api.backup.is_connected())
        self.api.backup.disconnect()
        self.assertFalse(self.api.backup.is_connected())

    def test_stm_recover(self):
        """Test recovering from Secure Transport Mode."""
        self.api.backup.connect()
        result = self.api.backup.stm_recover("my_random_string", audit=self.api.audit)
        self.assertTrue(result["success"])
        self.assertEqual(result["stm_state"], "initialized")

    def test_stm_recover_already_recovered(self):
        """Test that STM recover fails when not in STM."""
        self.api.backup.connect()
        self.api.backup.stm_recover("test_string", audit=self.api.audit)
        with self.assertRaises(PKCS11Error):
            self.api.backup.stm_recover("test_string2", audit=self.api.audit)

    def test_stm_show(self):
        """Test showing STM status."""
        self.api.backup.connect()
        info = self.api.backup.stm_show()
        self.assertEqual(info["stm_state"], "secure_transport")
        self.assertIn("description", info)

    def test_backup_initialize(self):
        """Test initializing the backup HSM."""
        self.api.backup.connect()
        self.api.backup.stm_recover("test_string", audit=self.api.audit)
        result = self.api.backup.initialize("bkupso123", audit=self.api.audit)
        self.assertTrue(result["success"])
        self.assertEqual(result["stm_state"], "active")

    def test_backup_init_requires_stm_recover(self):
        """Test that init fails without STM recovery."""
        self.api.backup.connect()
        with self.assertRaises(PKCS11Error):
            self.api.backup.initialize("bkupso123", audit=self.api.audit)

    def test_backup_login(self):
        """Test logging in to the backup HSM."""
        self._setup_backup_hsm()
        self.assertTrue(self.api.backup.is_logged_in())

    def test_backup_login_wrong_pin(self):
        """Test that login with wrong PIN fails."""
        self.api.backup.connect()
        self.api.backup.stm_recover("test_string", audit=self.api.audit)
        self.api.backup.initialize("correct_pin", audit=self.api.audit)
        with self.assertRaises(PKCS11Error):
            self.api.backup.login("wrong_pin", audit=self.api.audit)

    def test_backup_login_not_initialized(self):
        """Test that login fails when not initialized."""
        self.api.backup.connect()
        with self.assertRaises(PKCS11Error):
            self.api.backup.login("somepin", audit=self.api.audit)

    def test_backup_requires_login(self):
        """Test that backup operations require login."""
        self.api.backup.connect()
        with self.assertRaises(PKCS11Error):
            self.api.backup.backup_objects(self.slot_id, "domain1")

    def test_backup_objects(self):
        """Test backing up objects to the backup HSM."""
        self._setup_backup_hsm()
        # Generate an extractable AES key
        tmpl = make_aes_key_template("backup_key", 256, extractable=True)
        self.api.C_GenerateKey(self.session_id, CKM_AES_KEY_GEN, tmpl)
        # Back it up
        result = self.api.backup.backup_objects(
            self.slot_id, "my_domain", audit=self.api.audit
        )
        self.assertIn("backup_key", result["backed_up"])
        self.assertEqual(result["domain"], "my_domain")

    def test_backup_skips_non_extractable(self):
        """Test that non-extractable objects are skipped during backup."""
        self._setup_backup_hsm()
        # Generate a non-extractable AES key (default)
        tmpl = make_aes_key_template("secret_key", 256)
        self.api.C_GenerateKey(self.session_id, CKM_AES_KEY_GEN, tmpl)
        # Generate an extractable key
        tmpl2 = make_aes_key_template("extractable_key", 256, extractable=True)
        self.api.C_GenerateKey(self.session_id, CKM_AES_KEY_GEN, tmpl2)
        # Back up
        result = self.api.backup.backup_objects(
            self.slot_id, "my_domain", audit=self.api.audit
        )
        self.assertIn("extractable_key", result["backed_up"])
        self.assertIn("secret_key", result["skipped_non_extractable"])

    def test_backup_specific_labels(self):
        """Test backing up specific objects by label."""
        self._setup_backup_hsm()
        tmpl1 = make_aes_key_template("key_one", 256, extractable=True)
        self.api.C_GenerateKey(self.session_id, CKM_AES_KEY_GEN, tmpl1)
        tmpl2 = make_aes_key_template("key_two", 256, extractable=True)
        self.api.C_GenerateKey(self.session_id, CKM_AES_KEY_GEN, tmpl2)
        result = self.api.backup.backup_objects(
            self.slot_id, "domain1", labels=["key_one"], audit=self.api.audit
        )
        self.assertEqual(len(result["backed_up"]), 1)
        self.assertIn("key_one", result["backed_up"])

    def test_backup_no_clonable_objects(self):
        """Test that backup fails when no clonable objects exist."""
        self._setup_backup_hsm()
        # Generate only non-extractable keys
        tmpl = make_aes_key_template("secret_key", 256)
        self.api.C_GenerateKey(self.session_id, CKM_AES_KEY_GEN, tmpl)
        with self.assertRaises(PKCS11Error):
            self.api.backup.backup_objects(self.slot_id, "domain1")

    def test_restore_objects(self):
        """Test restoring objects from backup HSM to a partition."""
        self._setup_backup_hsm()
        # Generate and backup an extractable key
        tmpl = make_aes_key_template("restore_key", 256, extractable=True)
        self.api.C_GenerateKey(self.session_id, CKM_AES_KEY_GEN, tmpl)
        self.api.backup.backup_objects(
            self.slot_id, "restore_domain", audit=self.api.audit
        )
        # Delete the key from the source partition
        obj, _ = self.api.keystore.retrieve_by_label(self.slot_id, "restore_key")
        self.api.keystore.delete(obj.handle)
        self.assertEqual(self.storage.count_objects(self.slot_id), 0)
        # Restore from backup
        result = self.api.backup.restore_objects(
            self.slot_id, "restore_domain", audit=self.api.audit
        )
        self.assertIn("restore_key", result["restored"])
        self.assertEqual(self.storage.count_objects(self.slot_id), 1)

    def test_restore_wrong_domain(self):
        """Test that restore fails with wrong domain."""
        self._setup_backup_hsm()
        tmpl = make_aes_key_template("rkey", 256, extractable=True)
        self.api.C_GenerateKey(self.session_id, CKM_AES_KEY_GEN, tmpl)
        self.api.backup.backup_objects(
            self.slot_id, "domain_a", audit=self.api.audit
        )
        with self.assertRaises(PKCS11Error):
            self.api.backup.restore_objects(
                self.slot_id, "domain_b", audit=self.api.audit
            )

    def test_restore_specific_labels(self):
        """Test restoring specific objects by label."""
        self._setup_backup_hsm()
        for lbl in ["rkey1", "rkey2", "rkey3"]:
            tmpl = make_aes_key_template(lbl, 256, extractable=True)
            self.api.C_GenerateKey(self.session_id, CKM_AES_KEY_GEN, tmpl)
        self.api.backup.backup_objects(
            self.slot_id, "domain_x", audit=self.api.audit
        )
        # Delete all keys
        for lbl in ["rkey1", "rkey2", "rkey3"]:
            obj, _ = self.api.keystore.retrieve_by_label(self.slot_id, lbl)
            self.api.keystore.delete(obj.handle)
        # Restore only rkey2
        result = self.api.backup.restore_objects(
            self.slot_id, "domain_x", labels=["rkey2"], audit=self.api.audit
        )
        self.assertEqual(len(result["restored"]), 1)
        self.assertIn("rkey2", result["restored"])

    def test_backup_update_existing(self):
        """Test that backing up an existing object updates it."""
        self._setup_backup_hsm()
        tmpl = make_aes_key_template("update_key", 256, extractable=True)
        self.api.C_GenerateKey(self.session_id, CKM_AES_KEY_GEN, tmpl)
        self.api.backup.backup_objects(
            self.slot_id, "domain_u", audit=self.api.audit
        )
        # Backup again — should update, not duplicate
        self.api.backup.backup_objects(
            self.slot_id, "domain_u", audit=self.api.audit
        )
        partitions = self.api.backup._get_backup_partitions()
        bp = [p for p in partitions if p.domain == "domain_u"][0]
        self.assertEqual(len(bp.objects), 1)

    def test_list_backups(self):
        """Test listing backup partitions."""
        self._setup_backup_hsm()
        tmpl = make_aes_key_template("list_key", 256, extractable=True)
        self.api.C_GenerateKey(self.session_id, CKM_AES_KEY_GEN, tmpl)
        self.api.backup.backup_objects(
            self.slot_id, "list_domain", audit=self.api.audit
        )
        output = self.api.backup.list_backups()
        self.assertIn("list_domain", output)
        self.assertIn("list_key", output)

    def test_list_backup_partitions(self):
        """Test listing backup partitions as data."""
        self._setup_backup_hsm()
        tmpl = make_aes_key_template("pkey", 256, extractable=True)
        self.api.C_GenerateKey(self.session_id, CKM_AES_KEY_GEN, tmpl)
        self.api.backup.backup_objects(
            self.slot_id, "d1", audit=self.api.audit
        )
        parts = self.api.backup.list_backup_partitions()
        self.assertEqual(len(parts), 1)
        self.assertEqual(parts[0]["domain"], "d1")
        self.assertEqual(parts[0]["object_count"], 1)

    def test_backup_status(self):
        """Test getting backup HSM status."""
        self._setup_backup_hsm()
        status = self.api.backup.get_status()
        self.assertTrue(status["connected"])
        self.assertTrue(status["logged_in"])
        self.assertEqual(status["stm_state"], "active")

    def test_backup_show_info(self):
        """Test formatted backup HSM info."""
        self._setup_backup_hsm()
        output = self.api.backup.show_info()
        self.assertIn(BACKUP_HSM_MODEL, output)
        self.assertIn("Serial:", output)

    def test_backup_firmware_show(self):
        """Test showing backup HSM firmware info."""
        self._setup_backup_hsm()
        info = self.api.backup.get_firmware_info()
        self.assertEqual(info["current_version"], BACKUP_HSM_DEFAULT_FW)

    def test_backup_firmware_upgrade(self):
        """Test upgrading backup HSM firmware."""
        self._setup_backup_hsm()
        result = self.api.backup.upgrade_firmware("7.14.0", audit=self.api.audit)
        self.assertTrue(result["success"])
        self.assertEqual(result["new_version"], "7.14.0")
        # Verify persisted
        self.assertEqual(self.api.backup._get_firmware_version(), "7.14.0")

    def test_backup_firmware_rollback(self):
        """Test rolling back backup HSM firmware."""
        self._setup_backup_hsm()
        self.api.backup.upgrade_firmware("7.14.0", audit=self.api.audit)
        # Create a backup partition with data
        tmpl = make_aes_key_template("rbkey", 256, extractable=True)
        self.api.C_GenerateKey(self.session_id, CKM_AES_KEY_GEN, tmpl)
        self.api.backup.backup_objects(
            self.slot_id, "rb_domain", audit=self.api.audit
        )
        # Rollback — should erase all backup partitions
        result = self.api.backup.rollback_firmware(audit=self.api.audit)
        self.assertTrue(result["success"])
        self.assertEqual(result["new_version"], BACKUP_HSM_DEFAULT_FW)
        self.assertIn("warning", result)
        # Verify backup partitions were erased
        self.assertEqual(len(self.api.backup._get_backup_partitions()), 0)

    def test_backup_factory_reset(self):
        """Test factory reset of backup HSM."""
        self._setup_backup_hsm()
        tmpl = make_aes_key_template("frkey", 256, extractable=True)
        self.api.C_GenerateKey(self.session_id, CKM_AES_KEY_GEN, tmpl)
        self.api.backup.backup_objects(
            self.slot_id, "fr_domain", audit=self.api.audit
        )
        self.api.backup.factory_reset(audit=self.api.audit)
        status = self.api.backup.get_status()
        self.assertEqual(status["stm_state"], "secure_transport")
        self.assertEqual(status["partition_count"], 0)

    def test_backup_persists_across_reopen(self):
        """Test that backup data persists after DB close/reopen."""
        self._setup_backup_hsm()
        tmpl = make_aes_key_template("persist_key", 256, extractable=True)
        self.api.C_GenerateKey(self.session_id, CKM_AES_KEY_GEN, tmpl)
        self.api.backup.backup_objects(
            self.slot_id, "persist_domain", audit=self.api.audit
        )
        serial = self.api.backup._serial
        self.api.C_Finalize()
        storage2 = Storage(db_path=self.db_path, master_password="testpass")
        api2 = PKCS11API(storage2)
        api2.C_Initialize()
        api2.backup.connect()
        self.assertEqual(api2.backup._serial, serial)
        api2.backup.login("bkupso123", audit=api2.audit)
        parts = api2.backup.list_backup_partitions()
        self.assertEqual(len(parts), 1)
        self.assertEqual(parts[0]["domain"], "persist_domain")
        api2.C_Finalize()

    def test_backup_audited(self):
        """Test that backup operations are recorded in audit log."""
        self._setup_backup_hsm()
        tmpl = make_aes_key_template("audited_key", 256, extractable=True)
        self.api.C_GenerateKey(self.session_id, CKM_AES_KEY_GEN, tmpl)
        self.api.backup.backup_objects(
            self.slot_id, "audit_domain", audit=self.api.audit
        )
        logs = self.api.storage.get_audit_logs()
        ops = [l["operation"] for l in logs]
        self.assertIn("BackupObjects", ops)

    def test_restore_audited(self):
        """Test that restore operations are recorded in audit log."""
        self._setup_backup_hsm()
        tmpl = make_aes_key_template("audited_rkey", 256, extractable=True)
        self.api.C_GenerateKey(self.session_id, CKM_AES_KEY_GEN, tmpl)
        self.api.backup.backup_objects(
            self.slot_id, "audit_rdomain", audit=self.api.audit
        )
        obj, _ = self.api.keystore.retrieve_by_label(self.slot_id, "audited_rkey")
        self.api.keystore.delete(obj.handle)
        self.api.backup.restore_objects(
            self.slot_id, "audit_rdomain", audit=self.api.audit
        )
        logs = self.api.storage.get_audit_logs()
        ops = [l["operation"] for l in logs]
        self.assertIn("RestoreObjects", ops)


class TestPartitionPolicies(unittest.TestCase):
    """Test the full partition capabilities and policies system."""

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

    def test_policy_catalog_exists(self):
        """Test that the policy catalog has all expected policies."""
        from hsm.policies import POLICY_CATALOG
        self.assertGreater(len(POLICY_CATALOG), 20)
        # Check key policies exist
        ids = [p.policy_id for p in POLICY_CATALOG]
        self.assertIn(0, ids)  # ALLOW_PRIVATE_KEY_CLONING
        self.assertIn(1, ids)  # ALLOW_PRIVATE_KEY_WRAPPING
        self.assertIn(23, ids)  # MIN_PIN_LENGTH
        self.assertIn(25, ids)  # MAX_LOGIN_ATTEMPTS

    def test_show_policies_default(self):
        """Test showing policies with default values."""
        output = self.api.tokens.show_policies(self.slot_id)
        self.assertIn("ALLOW_PRIVATE_KEY_CLONING", output)
        self.assertIn("ALLOW_PRIVATE_KEY_WRAPPING", output)
        self.assertIn("MIN_PIN_LENGTH", output)

    def test_show_policies_verbose(self):
        """Test showing policies in verbose mode."""
        output = self.api.tokens.show_policies(self.slot_id, verbose=True)
        self.assertIn("Destructive", output)
        self.assertIn("Description", output)
        self.assertIn("Default", output)

    def test_change_policy_by_id(self):
        """Test changing a policy by numeric ID."""
        self.api.tokens.change_policy(
            self.slot_id, "25", "5", audit=self.api.audit, force=True
        )
        self.assertEqual(self.api.tokens.get_policy_value(self.slot_id, "MAX_LOGIN_ATTEMPTS"), 5)

    def test_change_policy_by_name(self):
        """Test changing a policy by name."""
        self.api.tokens.change_policy(
            self.slot_id, "MAX_LOGIN_ATTEMPTS", "3", audit=self.api.audit, force=True
        )
        self.assertEqual(self.api.tokens.get_policy_value(self.slot_id, "MAX_LOGIN_ATTEMPTS"), 3)

    def test_change_policy_min_pin_length(self):
        """Test changing MIN_PIN_LENGTH."""
        self.api.tokens.change_policy(
            self.slot_id, "MIN_PIN_LENGTH", "8", audit=self.api.audit, force=True
        )
        self.assertEqual(self.api.tokens.get_policy_value(self.slot_id, "MIN_PIN_LENGTH"), 8)

    def test_change_policy_invalid_value(self):
        """Test that invalid policy value fails."""
        with self.assertRaises(PKCS11Error):
            self.api.tokens.change_policy(self.slot_id, "MIN_PIN_LENGTH", "2", force=True)

    def test_change_non_modifiable_policy(self):
        """Test that non-modifiable policies cannot be changed."""
        with self.assertRaises(PKCS11Error):
            self.api.tokens.change_policy(self.slot_id, "MAX_PIN_LENGTH", "16", force=True)

    def test_change_policy_unknown(self):
        """Test that unknown policy fails."""
        with self.assertRaises(PKCS11Error):
            self.api.tokens.change_policy(self.slot_id, "999", "1", force=True)

    def test_destructive_policy_requires_force(self):
        """Test that destructive policy change requires force."""
        # ALLOW_PRIVATE_KEY_WRAPPING (id=1) is destructive off-to-on
        # Default is 0 (Off), changing to 1 (On) is destructive
        with self.assertRaises(PKCS11Error):
            self.api.tokens.change_policy(self.slot_id, "1", "1")

    def test_destructive_policy_with_force(self):
        """Test that destructive policy change works with force."""
        # Generate a key first
        tmpl = make_aes_key_template("test_key", 256)
        self.api.C_GenerateKey(self.session_id, CKM_AES_KEY_GEN, tmpl)
        self.assertGreater(self.storage.count_objects(self.slot_id), 0)
        # Disable cloning first (mutual exclusion), then enable wrapping (destructive)
        self.api.tokens.change_policy(
            self.slot_id, "0", "0", audit=self.api.audit, force=True
        )
        # Change wrapping to On (destructive) with force
        self.api.tokens.change_policy(
            self.slot_id, "1", "1", audit=self.api.audit, force=True
        )
        # Objects should be deleted
        self.assertEqual(self.storage.count_objects(self.slot_id), 0)
        self.assertEqual(self.api.tokens.get_policy_value(self.slot_id, "ALLOW_PRIVATE_KEY_WRAPPING"), 1)

    def test_mutual_exclusion_cloning_wrapping(self):
        """Test that cloning and wrapping cannot both be On."""
        # Default: cloning=1, wrapping=0
        # Try to enable wrapping while cloning is on
        with self.assertRaises(PKCS11Error):
            self.api.tokens.change_policy(self.slot_id, "1", "1", force=True)
        # Disable cloning first, then enable wrapping
        self.api.tokens.change_policy(self.slot_id, "0", "0", force=True)
        self.api.tokens.change_policy(self.slot_id, "1", "1", force=True)
        self.assertEqual(self.api.tokens.get_policy_value(self.slot_id, "ALLOW_PRIVATE_KEY_WRAPPING"), 1)

    def test_policy_persistence(self):
        """Test that policy changes persist across DB reopen."""
        self.api.tokens.change_policy(
            self.slot_id, "MAX_LOGIN_ATTEMPTS", "7", audit=self.api.audit, force=True
        )
        self.api.C_Finalize()
        storage2 = Storage(db_path=self.db_path, master_password="testpass")
        api2 = PKCS11API(storage2)
        api2.C_Initialize()
        self.assertEqual(api2.tokens.get_policy_value(self.slot_id, "MAX_LOGIN_ATTEMPTS"), 7)
        api2.C_Finalize()

    def test_is_cloning_allowed(self):
        """Test cloning policy check."""
        self.assertTrue(self.api.tokens.is_cloning_allowed(self.slot_id))

    def test_is_wrapping_allowed(self):
        """Test wrapping policy check."""
        self.assertFalse(self.api.tokens.is_wrapping_allowed(self.slot_id))

    def test_policy_change_audited(self):
        """Test that policy changes are recorded in audit log."""
        self.api.tokens.change_policy(
            self.slot_id, "MAX_LOGIN_ATTEMPTS", "5", audit=self.api.audit, force=True
        )
        logs = self.api.storage.get_audit_logs()
        ops = [l["operation"] for l in logs]
        self.assertIn("PartitionChangePolicy", ops)

    # --- Policy Templates ---

    def test_list_predefined_templates(self):
        """Test listing predefined PPT templates."""
        templates = self.api.tokens.list_policy_templates()
        names = [t["name"] for t in templates]
        self.assertIn("DEFAULT", names)
        self.assertIn("FIPS_STRICT", names)
        self.assertIn("HIGH_SECURITY", names)
        self.assertIn("DEVELOPMENT", names)
        self.assertIn("BACKUP_READY", names)

    def test_get_predefined_template(self):
        """Test getting a predefined template."""
        template = self.api.tokens.get_policy_template("FIPS_STRICT")
        self.assertIsNotNone(template)
        self.assertTrue(template["predefined"])
        self.assertIn("description", template)
        self.assertIn("policies", template)

    def test_create_custom_template(self):
        """Test creating a custom PPT template."""
        policies = {0: 1, 1: 0, 25: 5}
        self.api.tokens.create_policy_template(
            "MY_TEMPLATE", "My custom template", policies,
            audit=self.api.audit, session_id=self.session_id
        )
        template = self.api.tokens.get_policy_template("MY_TEMPLATE")
        self.assertIsNotNone(template)
        self.assertFalse(template["predefined"])
        self.assertEqual(template["policies"][25], 5)

    def test_delete_custom_template(self):
        """Test deleting a custom PPT template."""
        self.api.tokens.create_policy_template(
            "TO_DELETE", "Temp", {25: 3}, audit=self.api.audit
        )
        self.api.tokens.delete_policy_template("TO_DELETE", audit=self.api.audit)
        self.assertIsNone(self.api.tokens.get_policy_template("TO_DELETE"))

    def test_cannot_delete_predefined_template(self):
        """Test that predefined templates cannot be deleted."""
        with self.assertRaises(PKCS11Error):
            self.api.tokens.delete_policy_template("FIPS_STRICT")

    def test_apply_predefined_template(self):
        """Test applying a predefined template to a partition."""
        # Apply FIPS_STRICT template
        self.api.tokens.apply_policy_template(
            self.slot_id, "FIPS_STRICT",
            audit=self.api.audit, force=True
        )
        # Check that some policies were changed
        self.assertEqual(self.api.tokens.get_policy_value(self.slot_id, "ALLOW_PRIVATE_KEY_WRAPPING"), 0)
        self.assertEqual(self.api.tokens.get_policy_value(self.slot_id, "ALLOW_RAW_RSA_OPERATIONS"), 0)
        self.assertEqual(self.api.tokens.get_policy_value(self.slot_id, "ALLOW_RESTRICTED_TO_V1"), 1)

    def test_apply_template_destructive(self):
        """Test that applying a destructive template clears objects."""
        # Generate a key
        tmpl = make_aes_key_template("destr_key", 256)
        self.api.C_GenerateKey(self.session_id, CKM_AES_KEY_GEN, tmpl)
        self.assertGreater(self.storage.count_objects(self.slot_id), 0)
        # Apply DEVELOPMENT template (disables cloning which is destructive on-to-off)
        self.api.tokens.apply_policy_template(
            self.slot_id, "DEVELOPMENT",
            audit=self.api.audit, force=True
        )
        # Objects should be deleted due to destructive policy change
        self.assertEqual(self.storage.count_objects(self.slot_id), 0)

    def test_apply_template_audited(self):
        """Test that applying a template is audited."""
        self.api.tokens.apply_policy_template(
            self.slot_id, "FIPS_STRICT",
            audit=self.api.audit, force=True
        )
        logs = self.api.storage.get_audit_logs()
        ops = [l["operation"] for l in logs]
        self.assertIn("ApplyPolicyTemplate", ops)

    def test_custom_template_persists(self):
        """Test that custom templates persist across DB reopen."""
        self.api.tokens.create_policy_template(
            "PERSIST_T", "Persistent template", {25: 8},
            audit=self.api.audit
        )
        self.api.C_Finalize()
        storage2 = Storage(db_path=self.db_path, master_password="testpass")
        api2 = PKCS11API(storage2)
        api2.C_Initialize()
        template = api2.tokens.get_policy_template("PERSIST_T")
        self.assertIsNotNone(template)
        self.assertEqual(template["policies"][25], 8)
        api2.C_Finalize()

    def test_template_validation_mutual_exclusion(self):
        """Test that templates with mutual exclusion violations fail."""
        # Policies 0 and 1 cannot both be 1
        with self.assertRaises(PKCS11Error):
            self.api.tokens.create_policy_template(
                "INVALID", "Bad template", {0: 1, 1: 1},
                audit=self.api.audit
            )


if __name__ == "__main__":
    unittest.main()
