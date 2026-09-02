"""PKCS#11 object classes — keys, certificates, data objects.

Each object is represented as a dictionary of CKA_ attributes with a
unique handle.  Secret-key material and private-key material are stored
encrypted at rest via the storage layer.
"""

import time
import struct
import hashlib

from pkcs11.constants import (
    CKA_CLASS, CKA_TOKEN, CKA_PRIVATE, CKA_LABEL, CKA_VALUE,
    CKA_KEY_TYPE, CKA_SENSITIVE, CKA_ENCRYPT, CKA_DECRYPT,
    CKA_WRAP, CKA_UNWRAP, CKA_SIGN, CKA_VERIFY, CKA_DERIVE,
    CKA_VALUE_LEN, CKA_EXTRACTABLE, CKA_LOCAL, CKA_NEVER_EXTRACTABLE,
    CKA_ALWAYS_SENSITIVE, CKA_MODIFIABLE, CKA_COPYABLE, CKA_DESTROYABLE,
    CKA_MODULUS, CKA_MODULUS_BITS, CKA_PUBLIC_EXPONENT,
    CKA_PRIVATE_EXPONENT, CKA_EC_PARAMS, CKA_EC_POINT,
    CKA_CHECK_VALUE, CKA_START_DATE, CKA_END_DATE,
    CKA_PUBLIC_KEY_INFO, CKA_ALWAYS_AUTHENTICATE,
    CKO_SECRET_KEY, CKO_PUBLIC_KEY, CKO_PRIVATE_KEY, CKO_DATA,
    CKK_AES, CKK_RSA, CKK_EC, CKK_DES, CKK_DES3, CKK_DSA,
    CKK_GENERIC_SECRET,
    CKS_PRE_ACTIVE, CKS_ACTIVE, CKS_DEACTIVATED, CKS_DESTROYED,
    cka_name, cko_name, ckk_name,
)


class CKObject:
    """A PKCS#11 object identified by a numeric handle.

    Attributes are stored in a dict keyed by CKA_ constant.
    Some attributes are byte-strings (CKA_VALUE, CKA_MODULUS, etc.);
    others are booleans, integers, or strings.
    """

    def __init__(self, handle: int, attributes: dict):
        self.handle = handle
        self.attributes = dict(attributes)
        self.state = CKS_ACTIVE
        self.usage_count = 0
        self.created_at = time.time()
        self.expires_at = None

    def get(self, attr: int, default=None):
        return self.attributes.get(attr, default)

    def set(self, attr: int, value):
        self.attributes[attr] = value

    def has(self, attr: int) -> bool:
        return attr in self.attributes

    def is_token_object(self) -> bool:
        return bool(self.attributes.get(CKA_TOKEN, False))

    def is_private(self) -> bool:
        return bool(self.attributes.get(CKA_PRIVATE, False))

    def is_sensitive(self) -> bool:
        return bool(self.attributes.get(CKA_SENSITIVE, False))

    def is_extractable(self) -> bool:
        return bool(self.attributes.get(CKA_EXTRACTABLE, False))

    def object_class(self) -> int:
        return self.attributes.get(CKA_CLASS, CKO_DATA)

    def key_type(self) -> int:
        return self.attributes.get(CKA_KEY_TYPE, 0)

    def label(self) -> str:
        v = self.attributes.get(CKA_LABEL, b"")
        if isinstance(v, bytes):
            return v.decode("utf-8", errors="replace")
        return str(v)

    def value_len(self) -> int:
        return self.attributes.get(CKA_VALUE_LEN, 0)

    def increment_usage(self):
        self.usage_count += 1

    def is_active(self) -> bool:
        return self.state == CKS_ACTIVE

    def deactivate(self):
        self.state = CKS_DEACTIVATED

    def to_dict(self) -> dict:
        """Serialize to a JSON-compatible dict for storage."""
        attrs = {}
        for k, v in self.attributes.items():
            attrs[str(k)] = self._serialize_value(v)
        return {
            "handle": self.handle,
            "attributes": attrs,
            "state": self.state,
            "usage_count": self.usage_count,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
        }

    @staticmethod
    def _serialize_value(v):
        if isinstance(v, bytes):
            return {"_type": "bytes", "value": v.hex()}
        elif isinstance(v, bool):
            return {"_type": "bool", "value": v}
        elif isinstance(v, int):
            return {"_type": "int", "value": v}
        elif isinstance(v, str):
            return {"_type": "str", "value": v}
        elif isinstance(v, list):
            return {"_type": "list", "value": [CKObject._serialize_value(x) for x in v]}
        else:
            return {"_type": "str", "value": str(v)}

    @staticmethod
    def _deserialize_value(v):
        if isinstance(v, dict) and "_type" in v:
            t = v["_type"]
            if t == "bytes":
                return bytes.fromhex(v["value"])
            elif t == "bool":
                return v["value"]
            elif t == "int":
                return v["value"]
            elif t == "str":
                return v["value"]
            elif t == "list":
                return [CKObject._deserialize_value(x) for x in v["value"]]
        return v

    @classmethod
    def from_dict(cls, d: dict) -> "CKObject":
        attrs = {}
        for k, v in d["attributes"].items():
            attrs[int(k)] = cls._deserialize_value(v)
        obj = cls(d["handle"], attrs)
        obj.state = d.get("state", CKS_ACTIVE)
        obj.usage_count = d.get("usage_count", 0)
        obj.created_at = d.get("created_at", time.time())
        obj.expires_at = d.get("expires_at")
        return obj

    def display(self) -> str:
        """Return a human-readable summary of this object."""
        lines = []
        lines.append(f"  Handle: 0x{self.handle:08X}")
        lines.append(f"  Label: {self.label()}")
        lines.append(f"  Class: {cko_name(self.object_class())}")
        if self.has(CKA_KEY_TYPE):
            lines.append(f"  Key Type: {ckk_name(self.key_type())}")
        if self.has(CKA_VALUE_LEN):
            lines.append(f"  Value Length: {self.value_len()} bytes ({self.value_len() * 8} bits)")
        if self.has(CKA_MODULUS_BITS):
            lines.append(f"  Modulus Bits: {self.get(CKA_MODULUS_BITS)}")
        lines.append(f"  Token: {self.is_token_object()}")
        lines.append(f"  Private: {self.is_private()}")
        lines.append(f"  Sensitive: {self.is_sensitive()}")
        lines.append(f"  Extractable: {self.is_extractable()}")
        lines.append(f"  Encrypt: {bool(self.get(CKA_ENCRYPT, False))}")
        lines.append(f"  Decrypt: {bool(self.get(CKA_DECRYPT, False))}")
        lines.append(f"  Sign: {bool(self.get(CKA_SIGN, False))}")
        lines.append(f"  Verify: {bool(self.get(CKA_VERIFY, False))}")
        lines.append(f"  Wrap: {bool(self.get(CKA_WRAP, False))}")
        lines.append(f"  Unwrap: {bool(self.get(CKA_UNWRAP, False))}")
        lines.append(f"  Derive: {bool(self.get(CKA_DERIVE, False))}")
        lines.append(f"  State: {self.state}")
        lines.append(f"  Usage Count: {self.usage_count}")
        lines.append(f"  Created: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.created_at))}")
        return "\n".join(lines)


def _compute_check_value(key_value: bytes) -> bytes:
    """Compute the CKA_CHECK_VALUE: first 3 bytes of ECB-encrypting a zero block."""
    # Simplified: use SHA-256 of the key, take first 3 bytes
    return hashlib.sha256(key_value).digest()[:3]


def make_aes_key_template(label: str, key_size_bits: int,
                          token: bool = True,
                          sensitive: bool = True,
                          extractable: bool = False,
                          encrypt: bool = True,
                          decrypt: bool = True,
                          wrap: bool = False,
                          unwrap: bool = False,
                          sign: bool = False,
                          verify: bool = False) -> dict:
    """Build a CKA_ template for an AES key."""
    return {
        CKA_CLASS: CKO_SECRET_KEY,
        CKA_TOKEN: token,
        CKA_PRIVATE: True,
        CKA_LABEL: label.encode("utf-8"),
        CKA_KEY_TYPE: CKK_AES,
        CKA_VALUE_LEN: key_size_bits // 8,
        CKA_SENSITIVE: sensitive,
        CKA_ENCRYPT: encrypt,
        CKA_DECRYPT: decrypt,
        CKA_WRAP: wrap,
        CKA_UNWRAP: unwrap,
        CKA_SIGN: sign,
        CKA_VERIFY: verify,
        CKA_EXTRACTABLE: extractable,
        CKA_LOCAL: True,
        CKA_NEVER_EXTRACTABLE: not extractable,
        CKA_ALWAYS_SENSITIVE: sensitive,
        CKA_MODIFIABLE: True,
        CKA_COPYABLE: False,
        CKA_DESTROYABLE: True,
    }


def make_rsa_keypair_templates(label: str, key_size: int,
                                token: bool = True,
                                sensitive: bool = True,
                                extractable: bool = False,
                                sign: bool = True,
                                verify: bool = True,
                                encrypt: bool = False,
                                decrypt: bool = True,
                                wrap: bool = False,
                                unwrap: bool = False) -> tuple:
    """Build (private_template, public_template) for an RSA key pair."""
    pub_tmpl = {
        CKA_CLASS: CKO_PUBLIC_KEY,
        CKA_TOKEN: token,
        CKA_PRIVATE: False,
        CKA_LABEL: label.encode("utf-8"),
        CKA_KEY_TYPE: CKK_RSA,
        CKA_MODULUS_BITS: key_size,
        CKA_ENCRYPT: encrypt,
        CKA_VERIFY: verify,
        CKA_WRAP: wrap,
        CKA_MODIFIABLE: True,
        CKA_COPYABLE: True,
        CKA_DESTROYABLE: True,
        CKA_LOCAL: True,
    }
    priv_tmpl = {
        CKA_CLASS: CKO_PRIVATE_KEY,
        CKA_TOKEN: token,
        CKA_PRIVATE: True,
        CKA_LABEL: label.encode("utf-8"),
        CKA_KEY_TYPE: CKK_RSA,
        CKA_SENSITIVE: sensitive,
        CKA_DECRYPT: decrypt,
        CKA_SIGN: sign,
        CKA_UNWRAP: unwrap,
        CKA_EXTRACTABLE: extractable,
        CKA_LOCAL: True,
        CKA_NEVER_EXTRACTABLE: not extractable,
        CKA_ALWAYS_SENSITIVE: sensitive,
        CKA_MODIFIABLE: True,
        CKA_COPYABLE: False,
        CKA_DESTROYABLE: True,
    }
    return priv_tmpl, pub_tmpl


def make_ec_keypair_templates(label: str, curve_name: str,
                              token: bool = True,
                              sensitive: bool = True,
                              extractable: bool = False,
                              sign: bool = True,
                              verify: bool = True,
                              derive: bool = False) -> tuple:
    """Build (private_template, public_template) for an EC key pair."""
    curve_map = {
        "P-256": b"\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07",
        "P-384": b"\x06\x05\x2b\x81\x04\x00\x22",
        "P-521": b"\x06\x05\x2b\x81\x04\x00\x23",
        "secp256k1": b"\x06\x05\x2b\x81\x04\x00\x0a",
    }
    ec_params = curve_map.get(curve_name, b"")
    pub_tmpl = {
        CKA_CLASS: CKO_PUBLIC_KEY,
        CKA_TOKEN: token,
        CKA_PRIVATE: False,
        CKA_LABEL: label.encode("utf-8"),
        CKA_KEY_TYPE: CKK_EC,
        CKA_EC_PARAMS: ec_params,
        CKA_VERIFY: verify,
        CKA_MODIFIABLE: True,
        CKA_COPYABLE: True,
        CKA_DESTROYABLE: True,
        CKA_LOCAL: True,
    }
    priv_tmpl = {
        CKA_CLASS: CKO_PRIVATE_KEY,
        CKA_TOKEN: token,
        CKA_PRIVATE: True,
        CKA_LABEL: label.encode("utf-8"),
        CKA_KEY_TYPE: CKK_EC,
        CKA_EC_PARAMS: ec_params,
        CKA_SENSITIVE: sensitive,
        CKA_SIGN: sign,
        CKA_DERIVE: derive,
        CKA_EXTRACTABLE: extractable,
        CKA_LOCAL: True,
        CKA_NEVER_EXTRACTABLE: not extractable,
        CKA_ALWAYS_SENSITIVE: sensitive,
        CKA_MODIFIABLE: True,
        CKA_COPYABLE: False,
        CKA_DESTROYABLE: True,
    }
    return priv_tmpl, pub_tmpl


def make_des3_key_template(label: str, key_size_bits: int = 192,
                           token: bool = True,
                           sensitive: bool = True,
                           extractable: bool = False,
                           encrypt: bool = True,
                           decrypt: bool = True) -> dict:
    """Build a CKA_ template for a 3DES key."""
    return {
        CKA_CLASS: CKO_SECRET_KEY,
        CKA_TOKEN: token,
        CKA_PRIVATE: True,
        CKA_LABEL: label.encode("utf-8"),
        CKA_KEY_TYPE: CKK_DES3,
        CKA_VALUE_LEN: key_size_bits // 8,
        CKA_SENSITIVE: sensitive,
        CKA_ENCRYPT: encrypt,
        CKA_DECRYPT: decrypt,
        CKA_EXTRACTABLE: extractable,
        CKA_LOCAL: True,
        CKA_NEVER_EXTRACTABLE: not extractable,
        CKA_ALWAYS_SENSITIVE: sensitive,
        CKA_MODIFIABLE: True,
        CKA_COPYABLE: False,
        CKA_DESTROYABLE: True,
    }


def make_hmac_key_template(label: str, key_size: int = 32,
                           token: bool = True,
                           sensitive: bool = True,
                           extractable: bool = False,
                           sign: bool = True,
                           verify: bool = True,
                           hmac_key_type: int = CKK_GENERIC_SECRET) -> dict:
    """Build a CKA_ template for an HMAC key."""
    return {
        CKA_CLASS: CKO_SECRET_KEY,
        CKA_TOKEN: token,
        CKA_PRIVATE: True,
        CKA_LABEL: label.encode("utf-8"),
        CKA_KEY_TYPE: hmac_key_type,
        CKA_VALUE_LEN: key_size,
        CKA_SENSITIVE: sensitive,
        CKA_SIGN: sign,
        CKA_VERIFY: verify,
        CKA_EXTRACTABLE: extractable,
        CKA_LOCAL: True,
        CKA_NEVER_EXTRACTABLE: not extractable,
        CKA_ALWAYS_SENSITIVE: sensitive,
        CKA_MODIFIABLE: True,
        CKA_COPYABLE: False,
        CKA_DESTROYABLE: True,
    }
