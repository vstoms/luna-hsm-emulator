"""Symmetric cryptographic operations — AES, 3DES, DES.

All operations use the pyca/cryptography library backed by OpenSSL.
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import struct

from pkcs11.constants import (
    CKM_AES_ECB, CKM_AES_CBC, CKM_AES_CTR, CKM_AES_GCM,
    CKM_DES_ECB, CKM_DES_CBC,
    CKM_DES3_ECB, CKM_DES3_CBC, CKM_DES3_CBC_PAD,
    PKCS11Error, CKR_MECHANISM_INVALID, CKR_DATA_LEN_RANGE,
)


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def encrypt(mechanism: int, key: bytes, data: bytes, iv: bytes = None,
            aad: bytes = None, tag_len: int = 16) -> bytes:
    """Encrypt *data* with *key* using the given PKCS#11 mechanism."""
    if mechanism == CKM_AES_ECB:
        if len(key) not in (16, 24, 32):
            raise PKCS11Error(CKR_KEY_SIZE_RANGE)
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        enc = cipher.encryptor()
        if len(data) % 16 != 0:
            raise PKCS11Error(CKR_DATA_LEN_RANGE,
                              "ECB requires data length multiple of block size")
        return enc.update(data) + enc.finalize()

    elif mechanism == CKM_AES_CBC:
        if iv is None or len(iv) != 16:
            raise PKCS11Error(CKR_MECHANISM_PARAM_INVALID, "CBC requires 16-byte IV")
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        enc = cipher.encryptor()
        if len(data) % 16 != 0:
            raise PKCS11Error(CKR_DATA_LEN_RANGE,
                              "CBC requires data length multiple of block size")
        return enc.update(data) + enc.finalize()

    elif mechanism == CKM_AES_CTR:
        if iv is None or len(iv) != 16:
            raise PKCS11Error(CKR_MECHANISM_PARAM_INVALID, "CTR requires 16-byte nonce/counter")
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
        enc = cipher.encryptor()
        return enc.update(data) + enc.finalize()

    elif mechanism == CKM_AES_GCM:
        if iv is None:
            iv = os.urandom(12)
        elif len(iv) != 12:
            raise PKCS11Error(CKR_MECHANISM_PARAM_INVALID, "GCM requires 12-byte IV")
        aesgcm = AESGCM(key)
        ct = aesgcm.encrypt(iv, data, aad)
        return iv + ct

    elif mechanism == CKM_DES3_ECB:
        cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend=default_backend())
        enc = cipher.encryptor()
        if len(data) % 8 != 0:
            raise PKCS11Error(CKR_DATA_LEN_RANGE)
        return enc.update(data) + enc.finalize()

    elif mechanism == CKM_DES3_CBC:
        if iv is None or len(iv) != 8:
            raise PKCS11Error(CKR_MECHANISM_PARAM_INVALID, "3DES CBC requires 8-byte IV")
        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
        enc = cipher.encryptor()
        if len(data) % 8 != 0:
            raise PKCS11Error(CKR_DATA_LEN_RANGE)
        return enc.update(data) + enc.finalize()

    elif mechanism == CKM_DES3_CBC_PAD:
        if iv is None or len(iv) != 8:
            raise PKCS11Error(CKR_MECHANISM_PARAM_INVALID, "3DES CBC-PAD requires 8-byte IV")
        padder = padding.PKCS7(64).padder()
        padded = padder.update(data) + padder.finalize()
        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
        enc = cipher.encryptor()
        return enc.update(padded) + enc.finalize()

    elif mechanism == CKM_DES_ECB:
        cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend=default_backend())
        enc = cipher.encryptor()
        if len(data) % 8 != 0:
            raise PKCS11Error(CKR_DATA_LEN_RANGE)
        return enc.update(data) + enc.finalize()

    elif mechanism == CKM_DES_CBC:
        if iv is None or len(iv) != 8:
            raise PKCS11Error(CKR_MECHANISM_PARAM_INVALID, "DES CBC requires 8-byte IV")
        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
        enc = cipher.encryptor()
        if len(data) % 8 != 0:
            raise PKCS11Error(CKR_DATA_LEN_RANGE)
        return enc.update(data) + enc.finalize()

    else:
        raise PKCS11Error(CKR_MECHANISM_INVALID, f"Unsupported encrypt mechanism: 0x{mechanism:08X}")


def decrypt(mechanism: int, key: bytes, data: bytes, iv: bytes = None,
            aad: bytes = None, tag_len: int = 16) -> bytes:
    """Decrypt *data* with *key* using the given PKCS#11 mechanism."""
    if mechanism == CKM_AES_ECB:
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        dec = cipher.decryptor()
        return dec.update(data) + dec.finalize()

    elif mechanism == CKM_AES_CBC:
        if iv is None or len(iv) != 16:
            raise PKCS11Error(CKR_MECHANISM_PARAM_INVALID)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        dec = cipher.decryptor()
        return dec.update(data) + dec.finalize()

    elif mechanism == CKM_AES_CTR:
        if iv is None or len(iv) != 16:
            raise PKCS11Error(CKR_MECHANISM_PARAM_INVALID)
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
        dec = cipher.decryptor()
        return dec.update(data) + dec.finalize()

    elif mechanism == CKM_AES_GCM:
        if iv is None:
            iv = data[:12]
            ct = data[12:]
        else:
            if len(iv) != 12:
                raise PKCS11Error(CKR_MECHANISM_PARAM_INVALID)
            ct = data
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(iv, ct, aad)

    elif mechanism == CKM_DES3_ECB:
        cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend=default_backend())
        dec = cipher.decryptor()
        return dec.update(data) + dec.finalize()

    elif mechanism == CKM_DES3_CBC:
        if iv is None or len(iv) != 8:
            raise PKCS11Error(CKR_MECHANISM_PARAM_INVALID)
        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
        dec = cipher.decryptor()
        return dec.update(data) + dec.finalize()

    elif mechanism == CKM_DES3_CBC_PAD:
        if iv is None or len(iv) != 8:
            raise PKCS11Error(CKR_MECHANISM_PARAM_INVALID)
        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
        dec = cipher.decryptor()
        padded = dec.update(data) + dec.finalize()
        unpadder = padding.PKCS7(64).unpadder()
        return unpadder.update(padded) + unpadder.finalize()

    elif mechanism == CKM_DES_ECB:
        cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend=default_backend())
        dec = cipher.decryptor()
        return dec.update(data) + dec.finalize()

    elif mechanism == CKM_DES_CBC:
        if iv is None or len(iv) != 8:
            raise PKCS11Error(CKR_MECHANISM_PARAM_INVALID)
        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
        dec = cipher.decryptor()
        return dec.update(data) + dec.finalize()

    else:
        raise PKCS11Error(CKR_MECHANISM_INVALID, f"Unsupported decrypt mechanism: 0x{mechanism:08X}")


def generate_aes_key(key_size_bits: int = 256) -> bytes:
    """Generate a random AES key of the given size (128/192/256 bits)."""
    if key_size_bits not in (128, 192, 256):
        raise PKCS11Error(CKR_KEY_SIZE_RANGE, "AES key size must be 128, 192, or 256 bits")
    return os.urandom(key_size_bits // 8)


def generate_des3_key(key_size_bits: int = 192) -> bytes:
    """Generate a random 3DES key (112 or 168 bits)."""
    if key_size_bits == 112:
        return os.urandom(16)
    elif key_size_bits == 168:
        return os.urandom(24)
    else:
        raise PKCS11Error(CKR_KEY_SIZE_RANGE, "3DES key size must be 112 or 168 bits")


def generate_des_key() -> bytes:
    """Generate a random DES key (8 bytes)."""
    return os.urandom(8)


def compute_cmac(key: bytes, data: bytes, block_size: int = 16) -> bytes:
    """Compute AES-CMAC over *data*."""
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())

    def _blk_encrypt(blk: bytes) -> bytes:
        enc = cipher.encryptor()
        return enc.update(blk) + enc.finalize()

    zero = b"\x00" * block_size
    L = _blk_encrypt(zero)
    msb_L = int.from_bytes(L, "big") >> (block_size * 8 - 1)
    K1 = ((int.from_bytes(L, "big") << 1) & ((1 << (block_size * 8)) - 1)).to_bytes(block_size, "big")
    K2 = ((int.from_bytes(K1, "big") << 1) & ((1 << (block_size * 8)) - 1)).to_bytes(block_size, "big")
    if msb_L == 0:
        pass
    else:
        pass
    if msb_L:
        K1_int = int.from_bytes(K1, "big") ^ 0x87
        K1 = K1_int.to_bytes(block_size, "big")
        K2_int = (int.from_bytes(K2, "big") ^ 0x87).to_bytes(block_size, "big") if False else None
    if msb_L:
        K1 = ((int.from_bytes(L, "big") << 1) ^ 0x87).to_bytes(block_size, "big")
        K2 = ((int.from_bytes(K1, "big") << 1) ^ 0x87).to_bytes(block_size, "big")
    else:
        K1 = (int.from_bytes(L, "big") << 1).to_bytes(block_size, "big")
        K2 = (int.from_bytes(K1, "big") << 1).to_bytes(block_size, "big")

    n = max(1, (len(data) + block_size - 1) // block_size)
    if n == 0:
        n = 1
    last_complete = (len(data) > 0 and len(data) % block_size == 0)
    if last_complete:
        last_block = data[(n - 1) * block_size: n * block_size]
        last_block = _xor_bytes(last_block, K1)
    else:
        if len(data) == 0:
            last_block = b"\x80" + b"\x00" * (block_size - 1)
        else:
            remaining = data[(n - 1) * block_size:]
            last_block = remaining + b"\x80" + b"\x00" * (block_size - len(remaining) - 1)
        last_block = _xor_bytes(last_block, K2)

    X = zero
    for i in range(n - 1):
        block = data[i * block_size: (i + 1) * block_size]
        X = _blk_encrypt(_xor_bytes(X, block))
    T = _xor_bytes(X, last_block)
    Y = _blk_encrypt(T)
    return Y[:block_size]
