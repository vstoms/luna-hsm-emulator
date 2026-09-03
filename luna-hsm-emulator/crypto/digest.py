"""Hashing and MAC operations — SHA-1/256/384/512, HMAC, CMAC."""

import hashlib
import hmac as _hmac

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC as CryptoHMAC
from cryptography.hazmat.backends import default_backend

from pkcs11.constants import (
    PKCS11Error, CKR_MECHANISM_INVALID,
    CKM_SHA_1, CKM_SHA256, CKM_SHA384, CKM_SHA512,
    CKM_SHA_1_HMAC, CKM_SHA256_HMAC, CKM_SHA384_HMAC, CKM_SHA512_HMAC,
    CKM_AES_CMAC,
)
from crypto.symmetric import compute_cmac

_HASH_MECHS = {
    CKM_SHA_1: hashlib.sha1,
    CKM_SHA256: hashlib.sha256,
    CKM_SHA384: hashlib.sha384,
    CKM_SHA512: hashlib.sha512,
}

_HMAC_MECHS = {
    CKM_SHA_1_HMAC: hashes.SHA1,
    CKM_SHA256_HMAC: hashes.SHA256,
    CKM_SHA384_HMAC: hashes.SHA384,
    CKM_SHA512_HMAC: hashes.SHA512,
}


def digest(mechanism: int, data: bytes) -> bytes:
    """Compute a hash digest of *data*."""
    if mechanism in _HASH_MECHS:
        return _HASH_MECHS[mechanism](data).digest()
    else:
        raise PKCS11Error(CKR_MECHANISM_INVALID,
                          f"Unsupported digest mechanism: 0x{mechanism:08X}")


def hmac(mechanism: int, key: bytes, data: bytes) -> bytes:
    """Compute an HMAC of *data* with *key*."""
    if mechanism in _HMAC_MECHS:
        hash_alg = _HMAC_MECHS[mechanism]
        h = CryptoHMAC(key, hash_alg(), backend=default_backend())
        h.update(data)
        return h.finalize()
    elif mechanism == CKM_AES_CMAC:
        return compute_cmac(key, data)
    else:
        raise PKCS11Error(CKR_MECHANISM_INVALID,
                          f"Unsupported MAC mechanism: 0x{mechanism:08X}")


def verify_hmac(mechanism: int, key: bytes, data: bytes, mac: bytes) -> bool:
    """Verify an HMAC. Returns True or raises."""
    expected = hmac(mechanism, key, data)
    if _hmac.compare_digest(expected, mac):
        return True
    raise PKCS11Error(CKR_SIGNATURE_INVALID, "MAC verification failed")


def get_digest_size(mechanism: int) -> int:
    """Return the digest size in bytes for the given hash mechanism."""
    sizes = {
        CKM_SHA_1: 20,
        CKM_SHA256: 32,
        CKM_SHA384: 48,
        CKM_SHA512: 64,
    }
    return sizes.get(mechanism, 0)


def get_hash_name(mechanism: int) -> str:
    """Return a human-readable hash name."""
    names = {
        CKM_SHA_1: "SHA-1",
        CKM_SHA256: "SHA-256",
        CKM_SHA384: "SHA-384",
        CKM_SHA512: "SHA-512",
    }
    return names.get(mechanism, f"UNKNOWN(0x{mechanism:08X})")
