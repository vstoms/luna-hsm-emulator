"""PKCS#11 v2.40 API implementation.

This module implements the full PKCS#11 API surface, mapping each
C_* function to emulator operations.  Every function returns a CKR_
return code (CKR_OK on success) and raises PKCS11Error on failure.

The implementation bridges the PKCS#11 conceptual model to the
underlying HSM modules (session, token, auth, keystore, audit) and
the crypto layer.
"""

import os
import time
import hashlib
from typing import Optional

from pkcs11.constants import (
    CKR_OK, CKR_FUNCTION_FAILED, CKR_ARGUMENTS_BAD,
    CKR_SESSION_HANDLE_INVALID, CKR_SESSION_READ_ONLY,
    CKR_OPERATION_NOT_INITIALIZED, CKR_OPERATION_ACTIVE,
    CKR_OBJECT_HANDLE_INVALID, CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID, CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT, CKR_KEY_SIZE_RANGE, CKR_KEY_TYPE_INCONSISTENT,
    CKR_BUFFER_TOO_SMALL, CKR_DATA_LEN_RANGE, CKR_DATA_INVALID, CKR_DEVICE_MEMORY,
    CKR_USER_NOT_LOGGED_IN, CKR_ATTRIBUTE_SENSITIVE,
    CKR_FUNCTION_NOT_SUPPORTED, CKR_PIN_INCORRECT, CKR_PIN_LOCKED,
    CKR_TOKEN_NOT_PRESENT, CKR_ACTION_PROHIBITED,
    PKCS11Error,
    # Attributes
    CKA_CLASS, CKA_TOKEN, CKA_LABEL, CKA_VALUE, CKA_KEY_TYPE,
    CKA_VALUE_LEN, CKA_SENSITIVE, CKA_EXTRACTABLE, CKA_ENCRYPT,
    CKA_DECRYPT, CKA_SIGN, CKA_VERIFY, CKA_WRAP, CKA_UNWRAP, CKA_DERIVE,
    CKA_MODULUS, CKA_MODULUS_BITS, CKA_PUBLIC_EXPONENT,
    CKA_PRIVATE_EXPONENT, CKA_EC_PARAMS, CKA_EC_POINT,
    CKA_LOCAL, CKA_NEVER_EXTRACTABLE, CKA_ALWAYS_SENSITIVE,
    CKA_MODIFIABLE, CKA_COPYABLE, CKA_DESTROYABLE,
    CKA_CHECK_VALUE, CKA_PRIVATE, CKA_START_DATE, CKA_END_DATE,
    # Object classes
    CKO_SECRET_KEY, CKO_PUBLIC_KEY, CKO_PRIVATE_KEY, CKO_DATA,
    # Key types
    CKK_AES, CKK_RSA, CKK_EC, CKK_DES, CKK_DES3, CKK_DSA,
    CKK_GENERIC_SECRET,
    # Mechanisms
    CKM_AES_KEY_GEN, CKM_AES_ECB, CKM_AES_CBC, CKM_AES_CTR, CKM_AES_GCM,
    CKM_RSA_PKCS_KEY_PAIR_GEN, CKM_RSA_PKCS, CKM_RSA_PKCS_OAEP,
    CKM_RSA_PKCS_PSS,
    CKM_SHA256_RSA_PKCS, CKM_SHA384_RSA_PKCS, CKM_SHA512_RSA_PKCS,
    CKM_SHA256_RSA_PKCS_PSS, CKM_SHA384_RSA_PKCS_PSS, CKM_SHA512_RSA_PKCS_PSS,
    CKM_EC_KEY_PAIR_GEN, CKM_ECDSA, CKM_ECDH1_DERIVE,
    CKM_DES3_KEY_GEN, CKM_DES3_ECB, CKM_DES3_CBC,
    CKM_SHA_1, CKM_SHA256, CKM_SHA384, CKM_SHA512,
    CKM_SHA256_HMAC, CKM_SHA512_HMAC, CKM_AES_CMAC,
    CKM_PBKDF2, CKM_HKDF_DERIVE,
    # User types
    CKU_SO, CKU_USER,
    # Flags
    CKF_SERIAL_SESSION, CKF_RW_SESSION,
    # Helpers
    ckr_name, cka_name, ckm_name, cko_name, ckk_name,
)
from pkcs11.mechanisms import MECHANISMS, get_mechanism_info, MF_GENERATE, MF_GENERATE_KEY_PAIR
from pkcs11.objects import (
    CKObject,
    make_aes_key_template, make_rsa_keypair_templates,
    make_ec_keypair_templates, make_des3_key_template, make_hmac_key_template,
)
from hsm.session import SessionManager
from hsm.token import TokenManager
from hsm.auth import AuthManager, ROLE_CO, ROLE_CU, ROLE_SO, ROLE_HSO
from hsm.keystore import KeyStore
from hsm.audit import AuditLogger
from hsm.backup import BackupHSM
from storage.db import Storage

import crypto.symmetric as sym
import crypto.asymmetric as asym
import crypto.digest as dig
import crypto.kdf as kdf_mod


class PKCS11API:
    """Full PKCS#11 v2.40 API implementation for the Luna 7 emulator."""

    def __init__(self, storage: Storage):
        self.storage = storage
        self.sessions = SessionManager()
        self.tokens = TokenManager(storage, AuthManager(storage))
        self.auth = AuthManager(storage)
        self.keystore = KeyStore(storage)
        self.audit = AuditLogger(storage)
        self.backup = BackupHSM(storage)
        self._initialized = False

    # ==================================================================
    # Initialization / Finalization
    # ==================================================================

    def C_Initialize(self, init_args=None) -> int:
        """Initialize the PKCS#11 library."""
        if self._initialized:
            return CKR_OK
        self.storage.open()
        self._initialized = True
        return CKR_OK

    def C_Finalize(self) -> int:
        """Finalize the PKCS#11 library."""
        if not self._initialized:
            return CKR_OK
        self.sessions.close_all_sessions()
        self.storage.close()
        self._initialized = False
        return CKR_OK

    # ==================================================================
    # Session Management
    # ==================================================================

    def C_OpenSession(self, slot_id: int, flags: int = CKF_SERIAL_SESSION) -> int:
        """Open a session with a token. Returns session handle."""
        if not self._initialized:
            raise PKCS11Error(CKR_FUNCTION_FAILED, "Library not initialized")
        if not (flags & CKF_SERIAL_SESSION):
            raise PKCS11Error(CKR_FUNCTION_FAILED, "Only serial sessions supported")
        p = self.storage.get_partition(slot_id)
        if p is None:
            raise PKCS11Error(CKR_TOKEN_NOT_PRESENT, f"Slot {slot_id} not found")
        session_id = self.sessions.open_session(slot_id, flags)
        self.audit.log(session_id, "anonymous", "C_OpenSession",
                       success=True, detail=f"slot={slot_id}")
        return session_id

    def C_CloseSession(self, session_id: int) -> int:
        """Close a session."""
        s = self.sessions.get_session(session_id)
        self.auth.clear_session(session_id)
        self.sessions.close_session(session_id)
        self.audit.log(session_id, "anonymous", "C_CloseSession", success=True)
        return CKR_OK

    def C_CloseAllSessions(self, slot_id: int = None) -> int:
        """Close all sessions."""
        self.sessions.close_all_sessions(slot_id)
        return CKR_OK

    def C_GetSessionInfo(self, session_id: int) -> dict:
        """Return session information."""
        return self.sessions.get_session_info(session_id)

    def C_Login(self, session_id: int, user_type: int, pin: str) -> int:
        """Login to a session."""
        s = self.sessions.get_session(session_id)
        # Map CKU_ to role
        if user_type == CKU_SO:
            role = ROLE_SO
        elif user_type == CKU_USER:
            role = ROLE_CO
        else:
            role = ROLE_CU
        try:
            self.auth.login(session_id, s.slot_id, role, pin)
            s.user_type = user_type
            self.audit.log(session_id, role, "C_Login", success=True,
                           detail=f"slot={s.slot_id}")
            return CKR_OK
        except PKCS11Error as e:
            self.audit.log(session_id, role, "C_Login", success=False,
                           detail=str(e))
            raise

    def C_Logout(self, session_id: int) -> int:
        """Logout from a session."""
        role = self.auth.get_role(session_id)
        s = self.sessions.get_session(session_id)
        s.user_type = None
        self.auth.logout(session_id)
        self.audit.log(session_id, role or "anonymous", "C_Logout", success=True)
        return CKR_OK

    # ==================================================================
    # Slot and Token Management
    # ==================================================================

    def C_GetSlotList(self, token_present: bool = True) -> list:
        """Return list of slot IDs."""
        return self.tokens.list_slots()

    def C_GetSlotInfo(self, slot_id: int) -> dict:
        """Return slot info."""
        return self.tokens.get_slot_info(slot_id)

    def C_GetTokenInfo(self, slot_id: int) -> dict:
        """Return token info."""
        return self.tokens.get_token_info(slot_id)

    def C_InitToken(self, slot_id: int, so_pin: str, label: str = None) -> int:
        """Initialize a token."""
        self.tokens.init_token(slot_id, so_pin, label)
        self.audit.log(0, ROLE_SO, "C_InitToken", success=True,
                       detail=f"slot={slot_id}, label={label}")
        return CKR_OK

    def C_InitPIN(self, session_id: int, pin: str) -> int:
        """Initialize the user PIN."""
        s = self.sessions.get_session(session_id)
        self.tokens.init_pin(s.slot_id, pin, ROLE_CO)
        self.audit.log(session_id, ROLE_SO, "C_InitPIN", success=True,
                       detail=f"slot={s.slot_id}")
        return CKR_OK

    def C_SetPIN(self, session_id: int, old_pin: str, new_pin: str) -> int:
        """Set/change the PIN."""
        s = self.sessions.get_session(session_id)
        role = self.auth.get_role(session_id) or ROLE_CO
        self.auth.change_pin(s.slot_id, role, old_pin, new_pin)
        self.audit.log(session_id, role, "C_SetPIN", success=True)
        return CKR_OK

    # ==================================================================
    # Object Management
    # ==================================================================

    def C_CreateObject(self, session_id: int, template: dict) -> int:
        """Create an object from a template. Returns handle."""
        s = self.sessions.get_session(session_id)
        if not self.keystore.check_quota(s.slot_id):
            raise PKCS11Error(CKR_DEVICE_MEMORY, "Partition object quota exceeded")
        handle = self.keystore.allocate_handle()
        obj = CKObject(handle, template)
        label = obj.label()
        self.keystore.store(s.slot_id, obj)
        self.audit.log(session_id, self.auth.get_role(session_id) or "anonymous",
                       "C_CreateObject", object_label=label, object_handle=handle,
                       success=True)
        return handle

    def C_DestroyObject(self, session_id: int, handle: int) -> int:
        """Destroy an object."""
        obj, _ = self.keystore.retrieve(handle)
        self.keystore.delete(handle)
        self.audit.log(session_id, self.auth.get_role(session_id) or "anonymous",
                       "C_DestroyObject", object_label=obj.label(),
                       object_handle=handle, success=True)
        return CKR_OK

    def C_CopyObject(self, session_id: int, handle: int, template: dict) -> int:
        """Copy an object with optional attribute modifications."""
        s = self.sessions.get_session(session_id)
        obj, km = self.keystore.retrieve(handle)
        new_attrs = dict(obj.attributes)
        new_attrs.update(template)
        if CKA_LABEL in template:
            new_attrs[CKA_LABEL] = template[CKA_LABEL]
        new_handle = self.keystore.allocate_handle()
        new_obj = CKObject(new_handle, new_attrs)
        self.keystore.store(s.slot_id, new_obj, km)
        self.audit.log(session_id, self.auth.get_role(session_id) or "anonymous",
                       "C_CopyObject", object_label=new_obj.label(),
                       object_handle=new_handle, success=True)
        return new_handle

    def C_FindObjectsInit(self, session_id: int, template: dict) -> int:
        """Initialize a search for objects matching *template*."""
        s = self.sessions.get_session(session_id)
        if s._find_active:
            raise PKCS11Error(CKR_OPERATION_ACTIVE, "Find operation already active")
        all_objs = self.keystore.list_objects(s.slot_id)
        results = []
        for obj, km in all_objs:
            match = True
            for k, v in template.items():
                obj_val = obj.get(k)
                if obj_val is None:
                    match = False
                    break
                if isinstance(v, bytes) and isinstance(obj_val, bytes):
                    if v != obj_val:
                        match = False
                        break
                elif isinstance(v, str):
                    ov = obj_val
                    if isinstance(ov, bytes):
                        ov = ov.decode("utf-8", errors="replace")
                    if v != ov:
                        match = False
                        break
                elif v != obj_val:
                    match = False
                    break
            if match:
                results.append(obj.handle)
        s._find_active = True
        s._find_results = results
        return CKR_OK

    def C_FindObjects(self, session_id: int, max_count: int = 100) -> list:
        """Return matching object handles from the active search."""
        s = self.sessions.get_session(session_id)
        if not s._find_active:
            raise PKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
        results = s._find_results[:max_count]
        s._find_results = s._find_results[max_count:]
        return results

    def C_FindObjectsFinal(self, session_id: int) -> int:
        """Finalize a search."""
        s = self.sessions.get_session(session_id)
        if not s._find_active:
            raise PKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
        s._find_active = False
        s._find_results = []
        return CKR_OK

    def C_GetAttributeValue(self, session_id: int, handle: int,
                            attr_types: list) -> dict:
        """Return attribute values for an object."""
        obj, _ = self.keystore.retrieve(handle)
        result = {}
        for at in attr_types:
            val = obj.get(at)
            if val is None:
                result[at] = None
            elif obj.is_sensitive() and at == CKA_VALUE and not obj.is_extractable():
                result[at] = None  # Sensitive — not returned
            elif at in (CKA_PRIVATE_EXPONENT, CKA_MODULUS) and at == CKA_PRIVATE_EXPONENT:
                if obj.is_sensitive() and not obj.is_extractable():
                    result[at] = None
                else:
                    result[at] = val
            else:
                result[at] = val
        return result

    def C_SetAttributeValue(self, session_id: int, handle: int,
                             template: dict) -> int:
        """Set attribute values on an object."""
        s = self.sessions.get_session(session_id)
        obj, km = self.keystore.retrieve(handle)
        for k, v in template.items():
            if k in (CKA_SENSITIVE, CKA_EXTRACTABLE, CKA_NEVER_EXTRACTABLE,
                     CKA_ALWAYS_SENSITIVE):
                # These can only be set to more restrictive, not less
                if obj.get(k) and not v:
                    raise PKCS11Error(CKR_ACTION_PROHIBITED,
                                      f"Cannot relax {cka_name(k)} once set to TRUE")
            if not obj.get(CKA_MODIFIABLE, True):
                raise PKCS11Error(CKR_ACTION_PROHIBITED,
                                  "Object is not modifiable")
            obj.set(k, v)
        self.keystore.update(handle, obj, km)
        return CKR_OK

    # ==================================================================
    # Key Generation
    # ==================================================================

    def C_GenerateKey(self, session_id: int, mechanism: int,
                      template: dict, params: dict = None) -> int:
        """Generate a symmetric key. Returns handle."""
        s = self.sessions.get_session(session_id)
        if not self.keystore.check_quota(s.slot_id):
            raise PKCS11Error(CKR_DEVICE_MEMORY, "Partition quota exceeded")
        mech_info = get_mechanism_info(mechanism)
        if not mech_info.supports(MF_GENERATE):
            raise PKCS11Error(CKR_MECHANISM_INVALID,
                              f"Mechanism {ckm_name(mechanism)} does not support key generation")

        role = self.auth.get_role(session_id) or "anonymous"

        if mechanism == CKM_AES_KEY_GEN:
            key_size = template.get(CKA_VALUE_LEN, 32)
            if key_size not in (16, 24, 32):
                raise PKCS11Error(CKR_KEY_SIZE_RANGE)
            key_value = sym.generate_aes_key(key_size * 8)
            obj = CKObject(0, template)
            obj.set(CKA_CHECK_VALUE, sym._xor_bytes(key_value[:3], b"\x00\x00\x00"))
            handle = self.keystore.store(s.slot_id, obj, key_value)
            self.audit.log(session_id, role, "C_GenerateKey",
                           object_label=obj.label(), object_handle=handle,
                           success=True, detail=f"AES-{key_size*8}")
            return handle

        elif mechanism == CKM_DES3_KEY_GEN:
            key_size = template.get(CKA_VALUE_LEN, 24)
            key_value = sym.generate_des3_key(key_size * 8)
            obj = CKObject(0, template)
            handle = self.keystore.store(s.slot_id, obj, key_value)
            self.audit.log(session_id, role, "C_GenerateKey",
                           object_label=obj.label(), object_handle=handle,
                           success=True, detail="3DES")
            return handle

        else:
            raise PKCS11Error(CKR_MECHANISM_INVALID,
                              f"Unsupported key generation mechanism: {ckm_name(mechanism)}")

    def C_GenerateKeyPair(self, session_id: int, mechanism: int,
                          priv_template: dict, pub_template: dict,
                          params: dict = None) -> tuple:
        """Generate an asymmetric key pair. Returns (priv_handle, pub_handle)."""
        s = self.sessions.get_session(session_id)
        if not self.keystore.check_quota(s.slot_id, additional_objects=2):
            raise PKCS11Error(CKR_DEVICE_MEMORY, "Partition quota exceeded")
        role = self.auth.get_role(session_id) or "anonymous"

        if mechanism == CKM_RSA_PKCS_KEY_PAIR_GEN:
            key_size = pub_template.get(CKA_MODULUS_BITS, 2048)
            priv_key, pub_key = asym.generate_rsa_keypair(key_size)
            # Build public key object
            pub_obj = CKObject(0, pub_template)
            pub_obj.set(CKA_MODULUS, pub_key.public_numbers().n.to_bytes(
                (pub_key.public_numbers().n.bit_length() + 7) // 8, "big"))
            pub_obj.set(CKA_PUBLIC_EXPONENT, pub_key.public_numbers().e.to_bytes(
                (pub_key.public_numbers().e.bit_length() + 7) // 8, "big"))
            pub_obj.set(CKA_MODULUS_BITS, key_size)
            # Build private key object
            priv_obj = CKObject(0, priv_template)
            priv_material = asym.serialize_private_key(priv_key)
            pub_material = asym.serialize_public_key(pub_key)
            priv_handle = self.keystore.store(s.slot_id, priv_obj, priv_material)
            pub_handle = self.keystore.store(s.slot_id, pub_obj, pub_material)
            self.audit.log(session_id, role, "C_GenerateKeyPair",
                           object_label=pub_obj.label(), object_handle=pub_handle,
                           success=True, detail=f"RSA-{key_size}")
            return priv_handle, pub_handle

        elif mechanism == CKM_EC_KEY_PAIR_GEN:
            curve_name = params.get("curve", "P-256") if params else "P-256"
            priv_key, pub_key = asym.generate_ec_keypair(curve_name)
            pub_obj = CKObject(0, pub_template)
            pub_obj.set(CKA_EC_PARAMS, priv_template.get(CKA_EC_PARAMS, b""))
            # EC point is the serialized public key
            from cryptography.hazmat.primitives import serialization
            ec_point = pub_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint,
            )
            pub_obj.set(CKA_EC_POINT, ec_point)
            priv_obj = CKObject(0, priv_template)
            priv_material = asym.serialize_private_key(priv_key)
            pub_material = asym.serialize_public_key(pub_key)
            priv_handle = self.keystore.store(s.slot_id, priv_obj, priv_material)
            pub_handle = self.keystore.store(s.slot_id, pub_obj, pub_material)
            self.audit.log(session_id, role, "C_GenerateKeyPair",
                           object_label=pub_obj.label(), object_handle=pub_handle,
                           success=True, detail=f"EC-{curve_name}")
            return priv_handle, pub_handle

        else:
            raise PKCS11Error(CKR_MECHANISM_INVALID,
                              f"Unsupported key pair generation mechanism: {ckm_name(mechanism)}")

    # ==================================================================
    # Encryption / Decryption
    # ==================================================================

    def C_EncryptInit(self, session_id: int, mechanism: int, handle: int) -> int:
        """Initialize an encryption operation."""
        s = self.sessions.get_session(session_id)
        if s._encrypt_active:
            raise PKCS11Error(CKR_OPERATION_ACTIVE)
        obj, km = self.keystore.retrieve(handle)
        s._encrypt_active = True
        s._encrypt_mech = mechanism
        s._encrypt_key = km
        s._encrypt_buffer = b""
        return CKR_OK

    def C_Encrypt(self, session_id: int, data: bytes,
                  iv: bytes = None, aad: bytes = None) -> bytes:
        """Encrypt data in a single call."""
        s = self.sessions.get_session(session_id)
        if not s._encrypt_active:
            raise PKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
        result = sym.encrypt(s._encrypt_mech, s._encrypt_key, data, iv, aad)
        s._encrypt_active = False
        s._encrypt_key = None
        s._encrypt_mech = None
        self.audit.log(session_id, self.auth.get_role(session_id) or "anonymous",
                       "C_Encrypt", success=True,
                       detail=f"mech={ckm_name(s._encrypt_mech) if s._encrypt_mech else 'N/A'}, bytes={len(data)}")
        return result

    def C_EncryptUpdate(self, session_id: int, data: bytes) -> bytes:
        """Update an encryption operation with more data."""
        s = self.sessions.get_session(session_id)
        if not s._encrypt_active:
            raise PKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
        s._encrypt_buffer += data
        return b""

    def C_EncryptFinal(self, session_id: int,
                       iv: bytes = None, aad: bytes = None) -> bytes:
        """Finalize an encryption operation."""
        s = self.sessions.get_session(session_id)
        if not s._encrypt_active:
            raise PKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
        data = s._encrypt_buffer
        mech = s._encrypt_mech
        key = s._encrypt_key
        result = sym.encrypt(mech, key, data, iv, aad)
        s._encrypt_active = False
        s._encrypt_key = None
        s._encrypt_mech = None
        s._encrypt_buffer = b""
        self.audit.log(session_id, self.auth.get_role(session_id) or "anonymous",
                       "C_EncryptFinal", success=True,
                       detail=f"mech={ckm_name(mech)}, bytes={len(data)}")
        return result

    def C_DecryptInit(self, session_id: int, mechanism: int, handle: int) -> int:
        """Initialize a decryption operation."""
        s = self.sessions.get_session(session_id)
        if s._decrypt_active:
            raise PKCS11Error(CKR_OPERATION_ACTIVE)
        obj, km = self.keystore.retrieve(handle)
        s._decrypt_active = True
        s._decrypt_mech = mechanism
        s._decrypt_key = km
        s._decrypt_buffer = b""
        return CKR_OK

    def C_Decrypt(self, session_id: int, data: bytes,
                  iv: bytes = None, aad: bytes = None) -> bytes:
        """Decrypt data in a single call."""
        s = self.sessions.get_session(session_id)
        if not s._decrypt_active:
            raise PKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
        mech = s._decrypt_mech
        key = s._decrypt_key
        result = sym.decrypt(mech, key, data, iv, aad)
        s._decrypt_active = False
        s._decrypt_key = None
        s._decrypt_mech = None
        self.audit.log(session_id, self.auth.get_role(session_id) or "anonymous",
                       "C_Decrypt", success=True,
                       detail=f"mech={ckm_name(mech)}, bytes={len(data)}")
        return result

    def C_DecryptUpdate(self, session_id: int, data: bytes) -> bytes:
        """Update a decryption operation."""
        s = self.sessions.get_session(session_id)
        if not s._decrypt_active:
            raise PKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
        s._decrypt_buffer += data
        return b""

    def C_DecryptFinal(self, session_id: int,
                       iv: bytes = None, aad: bytes = None) -> bytes:
        """Finalize a decryption operation."""
        s = self.sessions.get_session(session_id)
        if not s._decrypt_active:
            raise PKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
        data = s._decrypt_buffer
        mech = s._decrypt_mech
        key = s._decrypt_key
        result = sym.decrypt(mech, key, data, iv, aad)
        s._decrypt_active = False
        s._decrypt_key = None
        s._decrypt_mech = None
        s._decrypt_buffer = b""
        self.audit.log(session_id, self.auth.get_role(session_id) or "anonymous",
                       "C_DecryptFinal", success=True,
                       detail=f"mech={ckm_name(mech)}, bytes={len(data)}")
        return result

    # ==================================================================
    # Signing / Verification
    # ==================================================================

    def C_SignInit(self, session_id: int, mechanism: int, handle: int) -> int:
        """Initialize a signing operation."""
        s = self.sessions.get_session(session_id)
        if s._sign_active:
            raise PKCS11Error(CKR_OPERATION_ACTIVE)
        obj, km = self.keystore.retrieve(handle)
        s._sign_active = True
        s._sign_mech = mechanism
        s._sign_key = km
        s._sign_buffer = b""
        return CKR_OK

    def C_Sign(self, session_id: int, data: bytes) -> bytes:
        """Sign data in a single call."""
        s = self.sessions.get_session(session_id)
        if not s._sign_active:
            raise PKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
        mech = s._sign_mech
        key_material = s._sign_key
        # Determine key type and call appropriate signer
        if mech in (CKM_SHA256_RSA_PKCS, CKM_SHA384_RSA_PKCS, CKM_SHA512_RSA_PKCS,
                     CKM_RSA_PKCS, CKM_SHA256_RSA_PKCS_PSS, CKM_SHA384_RSA_PKCS_PSS,
                     CKM_SHA512_RSA_PKCS_PSS, CKM_RSA_PKCS_PSS):
            priv_key = asym.deserialize_private_key(key_material)
            sig = asym.sign(mech, priv_key, data)
        elif mech == CKM_ECDSA:
            priv_key = asym.deserialize_private_key(key_material)
            sig = asym.sign(mech, priv_key, data)
        elif mech in (CKM_SHA256_HMAC, CKM_SHA512_HMAC, CKM_AES_CMAC):
            sig = dig.hmac(mech, key_material, data)
        else:
            raise PKCS11Error(CKR_MECHANISM_INVALID,
                             f"Unsupported sign mechanism: {ckm_name(mech)}")
        s._sign_active = False
        s._sign_key = None
        s._sign_mech = None
        self.audit.log(session_id, self.auth.get_role(session_id) or "anonymous",
                       "C_Sign", success=True,
                       detail=f"mech={ckm_name(mech)}, bytes={len(data)}")
        return sig

    def C_SignUpdate(self, session_id: int, data: bytes) -> int:
        """Update a signing operation with more data."""
        s = self.sessions.get_session(session_id)
        if not s._sign_active:
            raise PKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
        s._sign_buffer += data
        return CKR_OK

    def C_SignFinal(self, session_id: int) -> bytes:
        """Finalize a signing operation."""
        s = self.sessions.get_session(session_id)
        if not s._sign_active:
            raise PKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
        data = s._sign_buffer
        mech = s._sign_mech
        key_material = s._sign_key
        if mech in (CKM_SHA256_RSA_PKCS, CKM_SHA384_RSA_PKCS, CKM_SHA512_RSA_PKCS,
                     CKM_RSA_PKCS, CKM_SHA256_RSA_PKCS_PSS, CKM_SHA384_RSA_PKCS_PSS,
                     CKM_SHA512_RSA_PKCS_PSS, CKM_RSA_PKCS_PSS):
            priv_key = asym.deserialize_private_key(key_material)
            sig = asym.sign(mech, priv_key, data)
        elif mech == CKM_ECDSA:
            priv_key = asym.deserialize_private_key(key_material)
            sig = asym.sign(mech, priv_key, data)
        elif mech in (CKM_SHA256_HMAC, CKM_SHA512_HMAC, CKM_AES_CMAC):
            sig = dig.hmac(mech, key_material, data)
        else:
            raise PKCS11Error(CKR_MECHANISM_INVALID)
        s._sign_active = False
        s._sign_key = None
        s._sign_mech = None
        s._sign_buffer = b""
        self.audit.log(session_id, self.auth.get_role(session_id) or "anonymous",
                       "C_SignFinal", success=True,
                       detail=f"mech={ckm_name(mech)}, bytes={len(data)}")
        return sig

    def C_VerifyInit(self, session_id: int, mechanism: int, handle: int) -> int:
        """Initialize a verification operation."""
        s = self.sessions.get_session(session_id)
        if s._verify_active:
            raise PKCS11Error(CKR_OPERATION_ACTIVE)
        obj, km = self.keystore.retrieve(handle)
        s._verify_active = True
        s._verify_mech = mechanism
        s._verify_key = km
        s._verify_buffer = b""
        return CKR_OK

    def C_Verify(self, session_id: int, data: bytes, signature: bytes) -> bool:
        """Verify a signature in a single call."""
        s = self.sessions.get_session(session_id)
        if not s._verify_active:
            raise PKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
        mech = s._verify_mech
        key_material = s._verify_key
        if mech in (CKM_SHA256_RSA_PKCS, CKM_SHA384_RSA_PKCS, CKM_SHA512_RSA_PKCS,
                     CKM_RSA_PKCS, CKM_SHA256_RSA_PKCS_PSS, CKM_SHA384_RSA_PKCS_PSS,
                     CKM_SHA512_RSA_PKCS_PSS, CKM_RSA_PKCS_PSS):
            pub_key = asym.deserialize_public_key(key_material)
            result = asym.verify(mech, pub_key, data, signature)
        elif mech == CKM_ECDSA:
            pub_key = asym.deserialize_public_key(key_material)
            result = asym.verify(mech, pub_key, data, signature)
        elif mech in (CKM_SHA256_HMAC, CKM_SHA512_HMAC, CKM_AES_CMAC):
            result = dig.verify_hmac(mech, key_material, data, signature)
        else:
            raise PKCS11Error(CKR_MECHANISM_INVALID)
        s._verify_active = False
        s._verify_key = None
        s._verify_mech = None
        self.audit.log(session_id, self.auth.get_role(session_id) or "anonymous",
                       "C_Verify", success=True,
                       detail=f"mech={ckm_name(mech)}")
        return result

    def C_VerifyUpdate(self, session_id: int, data: bytes) -> int:
        """Update a verification operation."""
        s = self.sessions.get_session(session_id)
        if not s._verify_active:
            raise PKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
        s._verify_buffer += data
        return CKR_OK

    def C_VerifyFinal(self, session_id: int, signature: bytes) -> bool:
        """Finalize a verification operation."""
        s = self.sessions.get_session(session_id)
        if not s._verify_active:
            raise PKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
        data = s._verify_buffer
        mech = s._verify_mech
        key_material = s._verify_key
        if mech in (CKM_SHA256_RSA_PKCS, CKM_SHA384_RSA_PKCS, CKM_SHA512_RSA_PKCS,
                     CKM_RSA_PKCS, CKM_SHA256_RSA_PKCS_PSS, CKM_SHA384_RSA_PKCS_PSS,
                     CKM_SHA512_RSA_PKCS_PSS, CKM_RSA_PKCS_PSS):
            pub_key = asym.deserialize_public_key(key_material)
            result = asym.verify(mech, pub_key, data, signature)
        elif mech == CKM_ECDSA:
            pub_key = asym.deserialize_public_key(key_material)
            result = asym.verify(mech, pub_key, data, signature)
        elif mech in (CKM_SHA256_HMAC, CKM_SHA512_HMAC, CKM_AES_CMAC):
            result = dig.verify_hmac(mech, key_material, data, signature)
        else:
            raise PKCS11Error(CKR_MECHANISM_INVALID)
        s._verify_active = False
        s._verify_key = None
        s._verify_mech = None
        s._verify_buffer = b""
        self.audit.log(session_id, self.auth.get_role(session_id) or "anonymous",
                       "C_VerifyFinal", success=True,
                       detail=f"mech={ckm_name(mech)}")
        return result

    # ==================================================================
    # Digest (Hashing)
    # ==================================================================

    def C_DigestInit(self, session_id: int, mechanism: int) -> int:
        """Initialize a digest operation."""
        s = self.sessions.get_session(session_id)
        if s._digest_active:
            raise PKCS11Error(CKR_OPERATION_ACTIVE)
        s._digest_active = True
        s._digest_mech = mechanism
        s._digest_buffer = b""
        return CKR_OK

    def C_Digest(self, session_id: int, data: bytes) -> bytes:
        """Compute a digest in a single call."""
        s = self.sessions.get_session(session_id)
        if not s._digest_active:
            raise PKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
        result = dig.digest(s._digest_mech, data)
        s._digest_active = False
        s._digest_mech = None
        self.audit.log(session_id, self.auth.get_role(session_id) or "anonymous",
                       "C_Digest", success=True,
                       detail=f"mech={ckm_name(s._digest_mech) if s._digest_mech else 'N/A'}")
        return result

    def C_DigestUpdate(self, session_id: int, data: bytes) -> int:
        """Update a digest operation."""
        s = self.sessions.get_session(session_id)
        if not s._digest_active:
            raise PKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
        s._digest_buffer += data
        return CKR_OK

    def C_DigestFinal(self, session_id: int) -> bytes:
        """Finalize a digest operation."""
        s = self.sessions.get_session(session_id)
        if not s._digest_active:
            raise PKCS11Error(CKR_OPERATION_NOT_INITIALIZED)
        data = s._digest_buffer
        mech = s._digest_mech
        result = dig.digest(mech, data)
        s._digest_active = False
        s._digest_mech = None
        s._digest_buffer = b""
        self.audit.log(session_id, self.auth.get_role(session_id) or "anonymous",
                       "C_DigestFinal", success=True,
                       detail=f"mech={ckm_name(mech)}")
        return result

    # ==================================================================
    # Key Wrapping / Unwrapping / Derivation
    # ==================================================================

    def C_WrapKey(self, session_id: int, wrap_mechanism: int,
                  wrapping_handle: int, key_handle: int) -> bytes:
        """Wrap (encrypt) a key using a wrapping key."""
        s = self.sessions.get_session(session_id)
        wrap_obj, wrap_key = self.keystore.retrieve(wrapping_handle)
        target_obj, target_key = self.keystore.retrieve(key_handle)
        if not target_obj.is_extractable():
            raise PKCS11Error(CKR_ATTRIBUTE_SENSITIVE,
                              "Target key is not extractable — cannot wrap")
        if target_key is None:
            raise PKCS11Error(CKR_ATTRIBUTE_SENSITIVE, "No key material to wrap")
        if wrap_mechanism == CKM_AES_GCM:
            iv = os.urandom(12)
            wrapped = sym.encrypt(CKM_AES_GCM, wrap_key, target_key, iv=iv)
        elif wrap_mechanism == CKM_AES_CBC:
            iv = os.urandom(16)
            # Pad to block size
            padded = target_key + b"\x00" * (16 - len(target_key) % 16) if len(target_key) % 16 else target_key
            wrapped = iv + sym.encrypt(CKM_AES_CBC, wrap_key, padded, iv=iv)
        elif wrap_mechanism == CKM_RSA_PKCS:
            pub_key = asym.deserialize_public_key(wrap_key)
            wrapped = asym.rsa_encrypt(CKM_RSA_PKCS, pub_key, target_key)
        elif wrap_mechanism == CKM_RSA_PKCS_OAEP:
            pub_key = asym.deserialize_public_key(wrap_key)
            wrapped = asym.rsa_encrypt(CKM_RSA_PKCS_OAEP, pub_key, target_key)
        else:
            raise PKCS11Error(CKR_MECHANISM_INVALID,
                              f"Unsupported wrap mechanism: {ckm_name(wrap_mechanism)}")
        self.audit.log(session_id, self.auth.get_role(session_id) or "anonymous",
                       "C_WrapKey", object_label=target_obj.label(),
                       object_handle=key_handle, success=True,
                       detail=f"mech={ckm_name(wrap_mechanism)}")
        return wrapped

    def C_UnwrapKey(self, session_id: int, unwrap_mechanism: int,
                    unwrapping_handle: int, wrapped_key: bytes,
                    template: dict) -> int:
        """Unwrap (decrypt) a key and store it."""
        s = self.sessions.get_session(session_id)
        if not self.keystore.check_quota(s.slot_id):
            raise PKCS11Error(CKR_DEVICE_MEMORY, "Partition quota exceeded")
        unwrap_obj, unwrap_key = self.keystore.retrieve(unwrapping_handle)
        if unwrap_mechanism == CKM_AES_GCM:
            key_material = sym.decrypt(CKM_AES_GCM, unwrap_key, wrapped_key)
        elif unwrap_mechanism == CKM_AES_CBC:
            iv = wrapped_key[:16]
            ct = wrapped_key[16:]
            key_material = sym.decrypt(CKM_AES_CBC, unwrap_key, ct, iv=iv)
            key_material = key_material.rstrip(b"\x00")
        elif unwrap_mechanism == CKM_RSA_PKCS:
            priv_key = asym.deserialize_private_key(unwrap_key)
            key_material = asym.rsa_decrypt(CKM_RSA_PKCS, priv_key, wrapped_key)
        elif unwrap_mechanism == CKM_RSA_PKCS_OAEP:
            priv_key = asym.deserialize_private_key(unwrap_key)
            key_material = asym.rsa_decrypt(CKM_RSA_PKCS_OAEP, priv_key, wrapped_key)
        else:
            raise PKCS11Error(CKR_MECHANISM_INVALID,
                              f"Unsupported unwrap mechanism: {ckm_name(unwrap_mechanism)}")
        obj = CKObject(0, template)
        obj.set(CKA_LOCAL, False)
        obj.set(CKA_EXTRACTABLE, False)
        obj.set(CKA_NEVER_EXTRACTABLE, False)
        handle = self.keystore.store(s.slot_id, obj, key_material)
        self.audit.log(session_id, self.auth.get_role(session_id) or "anonymous",
                       "C_UnwrapKey", object_label=obj.label(),
                       object_handle=handle, success=True,
                       detail=f"mech={ckm_name(unwrap_mechanism)}")
        return handle

    def C_DeriveKey(self, session_id: int, mechanism: int,
                    base_handle: int, template: dict,
                    params: dict = None) -> int:
        """Derive a key from a base key."""
        s = self.sessions.get_session(session_id)
        if not self.keystore.check_quota(s.slot_id):
            raise PKCS11Error(CKR_DEVICE_MEMORY, "Partition quota exceeded")
        base_obj, base_key = self.keystore.retrieve(base_handle)
        params = params or {}
        if mechanism == CKM_ECDH1_DERIVE:
            peer_pub_der = params.get("peer_public_key")
            if peer_pub_der is None:
                raise PKCS11Error(CKR_ARGUMENTS_BAD, "ECDH requires peer_public_key param")
            priv_key = asym.deserialize_private_key(base_key)
            peer_pub = asym.deserialize_public_key(peer_pub_der)
            shared = asym.ecdh_derive(priv_key, peer_pub)
            # Use shared secret as the derived key material
            key_material = shared
        elif mechanism == CKM_PBKDF2:
            password = base_key
            salt = params.get("salt", os.urandom(16))
            iterations = params.get("iterations", 10000)
            length = params.get("length", 32)
            key_material = kdf_mod.pbkdf2(password, salt, iterations, length)
        elif mechanism == CKM_HKDF_DERIVE:
            ikm = base_key
            length = params.get("length", 32)
            salt = params.get("salt")
            info = params.get("info")
            key_material = kdf_mod.hkdf(ikm, length, salt, info)
        else:
            raise PKCS11Error(CKR_MECHANISM_INVALID,
                              f"Unsupported derive mechanism: {ckm_name(mechanism)}")
        obj = CKObject(0, template)
        obj.set(CKA_LOCAL, False)
        handle = self.keystore.store(s.slot_id, obj, key_material)
        self.audit.log(session_id, self.auth.get_role(session_id) or "anonymous",
                       "C_DeriveKey", object_label=obj.label(),
                       object_handle=handle, success=True,
                       detail=f"mech={ckm_name(mechanism)}")
        return handle
