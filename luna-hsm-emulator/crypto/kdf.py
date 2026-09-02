"""Key derivation functions — PBKDF2, HKDF, SP800-108 Counter Mode."""

import hashlib
import hmac as _hmac
import struct

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from pkcs11.constants import (
    PKCS11Error, CKR_MECHANISM_INVALID,
)


def pbkdf2(password: bytes, salt: bytes, iterations: int, length: int,
           hash_alg=hashes.SHA256) -> bytes:
    """Derive a key using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hash_alg(),
        length=length,
        salt=salt,
        iterations=iterations,
        backend=default_backend(),
    )
    return kdf.derive(password)


def hkdf(ikm: bytes, length: int, salt: bytes = None, info: bytes = None,
         hash_alg=hashes.SHA256) -> bytes:
    """Derive a key using HKDF (Extract-then-Expand)."""
    kdf = HKDF(
        algorithm=hash_alg(),
        length=length,
        salt=salt,
        info=info,
        backend=default_backend(),
    )
    return kdf.derive(ikm)


def sp800_108_counter(ikm: bytes, label: bytes, context: bytes,
                      length: int, hash_alg=hashlib.sha256) -> bytes:
    """NIST SP800-108 KDF in Counter Mode.

    Uses the construction:
        K(i) = PRF(ikm, i || label || 0x00 || context || L)
    where L is the requested bit length as a 32-bit big-endian integer.
    """
    L = length * 8  # bit length
    result = b""
    counter = 1
    while len(result) < length:
        # Construct the input: counter || label || 0x00 || context || L
        inp = (
            struct.pack(">I", counter)
            + label
            + b"\x00"
            + context
            + struct.pack(">I", L)
        )
        block = _hmac.new(ikm, inp, hash_alg).digest()
        result += block
        counter += 1
    return result[:length]


def derive(mechanism: str, **kwargs) -> bytes:
    """Dispatch to the appropriate KDF based on mechanism name string."""
    if mechanism == "PBKDF2":
        return pbkdf2(
            kwargs["password"], kwargs["salt"],
            kwargs["iterations"], kwargs["length"],
        )
    elif mechanism == "HKDF":
        return hkdf(
            kwargs["ikm"], kwargs["length"],
            kwargs.get("salt"), kwargs.get("info"),
        )
    elif mechanism == "SP800-108":
        return sp800_108_counter(
            kwargs["ikm"], kwargs.get("label", b""),
            kwargs.get("context", b""), kwargs["length"],
        )
    else:
        raise PKCS11Error(CKR_MECHANISM_INVALID,
                          f"Unsupported KDF: {mechanism}")
