"""PKCS#11 mechanism definitions and metadata.

Each mechanism carries flags indicating which operations it supports
(generate, encrypt, decrypt, sign, verify, digest, wrap, unwrap, derive)
and the key types it works with.
"""

from pkcs11.constants import (
    # Mechanism constants
    CKM_RSA_PKCS_KEY_PAIR_GEN, CKM_RSA_PKCS, CKM_RSA_PKCS_OAEP, CKM_RSA_PKCS_PSS,
    CKM_SHA_1, CKM_SHA256, CKM_SHA384, CKM_SHA512,
    CKM_SHA_1_RSA_PKCS, CKM_SHA256_RSA_PKCS, CKM_SHA384_RSA_PKCS, CKM_SHA512_RSA_PKCS,
    CKM_SHA_1_RSA_PKCS_PSS, CKM_SHA256_RSA_PKCS_PSS, CKM_SHA384_RSA_PKCS_PSS,
    CKM_SHA512_RSA_PKCS_PSS,
    CKM_AES_KEY_GEN, CKM_AES_ECB, CKM_AES_CBC, CKM_AES_CTR, CKM_AES_GCM,
    CKM_AES_CBC_PAD, CKM_AES_CMAC,
    CKM_DES_KEY_GEN, CKM_DES_ECB, CKM_DES_CBC,
    CKM_DES2_KEY_GEN, CKM_DES3_KEY_GEN, CKM_DES3_ECB, CKM_DES3_CBC, CKM_DES3_CBC_PAD,
    CKM_DSA_KEY_PAIR_GEN, CKM_DSA,
    CKM_EC_KEY_PAIR_GEN, CKM_ECDSA, CKM_ECDH1_DERIVE,
    CKM_SHA_1_HMAC, CKM_SHA256_HMAC, CKM_SHA384_HMAC, CKM_SHA512_HMAC,
    CKM_PBKDF2, CKM_HKDF_DERIVE,
    CKM_GENERIC_SECRET_KEY_GEN,
    # Key types
    CKK_RSA, CKK_DSA, CKK_EC, CKK_AES, CKK_DES, CKK_DES2, CKK_DES3,
    CKK_GENERIC_SECRET,
    CKK_SHA_1_HMAC, CKK_SHA256_HMAC, CKK_SHA384_HMAC, CKK_SHA512_HMAC,
    # Object classes
    CKO_PUBLIC_KEY, CKO_PRIVATE_KEY, CKO_SECRET_KEY,
)

# Mechanism flags
MF_GENERATE = 1 << 0
MF_GENERATE_KEY_PAIR = 1 << 1
MF_ENCRYPT = 1 << 2
MF_DECRYPT = 1 << 3
MF_SIGN = 1 << 4
MF_VERIFY = 1 << 5
MF_DIGEST = 1 << 6
MF_WRAP = 1 << 7
MF_UNWRAP = 1 << 8
MF_DERIVE = 1 << 9


class MechanismInfo:
    """Metadata about a single PKCS#11 mechanism."""

    def __init__(self, mechanism_id: int, flags: int, key_type: int = None,
                 min_key_size: int = 0, max_key_size: int = 0,
                 description: str = ""):
        self.mechanism_id = mechanism_id
        self.flags = flags
        self.key_type = key_type
        self.min_key_size = min_key_size
        self.max_key_size = max_key_size
        self.description = description

    def supports(self, flag: int) -> bool:
        return bool(self.flags & flag)


# Build the mechanism registry
MECHANISMS = {
    # Key generation mechanisms
    CKM_RSA_PKCS_KEY_PAIR_GEN: MechanismInfo(
        CKM_RSA_PKCS_KEY_PAIR_GEN, MF_GENERATE_KEY_PAIR,
        CKK_RSA, 1024, 4096, "RSA key pair generation"),
    CKM_DSA_KEY_PAIR_GEN: MechanismInfo(
        CKM_DSA_KEY_PAIR_GEN, MF_GENERATE_KEY_PAIR,
        CKK_DSA, 1024, 3072, "DSA key pair generation"),
    CKM_EC_KEY_PAIR_GEN: MechanismInfo(
        CKM_EC_KEY_PAIR_GEN, MF_GENERATE_KEY_PAIR,
        CKK_EC, 256, 521, "EC key pair generation"),
    CKM_AES_KEY_GEN: MechanismInfo(
        CKM_AES_KEY_GEN, MF_GENERATE,
        CKK_AES, 128, 256, "AES key generation"),
    CKM_DES_KEY_GEN: MechanismInfo(
        CKM_DES_KEY_GEN, MF_GENERATE,
        CKK_DES, 64, 64, "DES key generation"),
    CKM_DES2_KEY_GEN: MechanismInfo(
        CKM_DES2_KEY_GEN, MF_GENERATE,
        CKK_DES2, 112, 112, "2-key 3DES key generation"),
    CKM_DES3_KEY_GEN: MechanismInfo(
        CKM_DES3_KEY_GEN, MF_GENERATE,
        CKK_DES3, 168, 168, "3-key 3DES key generation"),
    CKM_GENERIC_SECRET_KEY_GEN: MechanismInfo(
        CKM_GENERIC_SECRET_KEY_GEN, MF_GENERATE,
        CKK_GENERIC_SECRET, 8, 512, "Generic secret key generation"),

    # RSA mechanisms
    CKM_RSA_PKCS: MechanismInfo(
        CKM_RSA_PKCS, MF_ENCRYPT | MF_DECRYPT | MF_SIGN | MF_VERIFY | MF_WRAP | MF_UNWRAP,
        CKK_RSA, 1024, 4096, "RSA PKCS#1 v1.5"),
    CKM_RSA_PKCS_OAEP: MechanismInfo(
        CKM_RSA_PKCS_OAEP, MF_ENCRYPT | MF_DECRYPT | MF_WRAP | MF_UNWRAP,
        CKK_RSA, 1024, 4096, "RSA OAEP"),
    CKM_RSA_PKCS_PSS: MechanismInfo(
        CKM_RSA_PKCS_PSS, MF_SIGN | MF_VERIFY,
        CKK_RSA, 1024, 4096, "RSA PSS"),

    # RSA + hash mechanisms
    CKM_SHA_1_RSA_PKCS: MechanismInfo(
        CKM_SHA_1_RSA_PKCS, MF_SIGN | MF_VERIFY, CKK_RSA, 1024, 4096,
        "SHA-1 with RSA PKCS#1 v1.5"),
    CKM_SHA256_RSA_PKCS: MechanismInfo(
        CKM_SHA256_RSA_PKCS, MF_SIGN | MF_VERIFY, CKK_RSA, 1024, 4096,
        "SHA-256 with RSA PKCS#1 v1.5"),
    CKM_SHA384_RSA_PKCS: MechanismInfo(
        CKM_SHA384_RSA_PKCS, MF_SIGN | MF_VERIFY, CKK_RSA, 1024, 4096,
        "SHA-384 with RSA PKCS#1 v1.5"),
    CKM_SHA512_RSA_PKCS: MechanismInfo(
        CKM_SHA512_RSA_PKCS, MF_SIGN | MF_VERIFY, CKK_RSA, 1024, 4096,
        "SHA-512 with RSA PKCS#1 v1.5"),
    CKM_SHA_1_RSA_PKCS_PSS: MechanismInfo(
        CKM_SHA_1_RSA_PKCS_PSS, MF_SIGN | MF_VERIFY, CKK_RSA, 1024, 4096,
        "SHA-1 with RSA PSS"),
    CKM_SHA256_RSA_PKCS_PSS: MechanismInfo(
        CKM_SHA256_RSA_PKCS_PSS, MF_SIGN | MF_VERIFY, CKK_RSA, 1024, 4096,
        "SHA-256 with RSA PSS"),
    CKM_SHA384_RSA_PKCS_PSS: MechanismInfo(
        CKM_SHA384_RSA_PKCS_PSS, MF_SIGN | MF_VERIFY, CKK_RSA, 1024, 4096,
        "SHA-384 with RSA PSS"),
    CKM_SHA512_RSA_PKCS_PSS: MechanismInfo(
        CKM_SHA512_RSA_PKCS_PSS, MF_SIGN | MF_VERIFY, CKK_RSA, 1024, 4096,
        "SHA-512 with RSA PSS"),

    # AES mechanisms
    CKM_AES_ECB: MechanismInfo(
        CKM_AES_ECB, MF_ENCRYPT | MF_DECRYPT, CKK_AES, 128, 256, "AES ECB"),
    CKM_AES_CBC: MechanismInfo(
        CKM_AES_CBC, MF_ENCRYPT | MF_DECRYPT, CKK_AES, 128, 256, "AES CBC"),
    CKM_AES_CBC_PAD: MechanismInfo(
        CKM_AES_CBC_PAD, MF_ENCRYPT | MF_DECRYPT, CKK_AES, 128, 256, "AES CBC with PKCS7 padding"),
    CKM_AES_CTR: MechanismInfo(
        CKM_AES_CTR, MF_ENCRYPT | MF_DECRYPT, CKK_AES, 128, 256, "AES CTR"),
    CKM_AES_GCM: MechanismInfo(
        CKM_AES_GCM, MF_ENCRYPT | MF_DECRYPT | MF_WRAP | MF_UNWRAP, CKK_AES, 128, 256, "AES GCM"),
    CKM_AES_CMAC: MechanismInfo(
        CKM_AES_CMAC, MF_SIGN | MF_VERIFY, CKK_AES, 128, 256, "AES CMAC"),

    # DES mechanisms
    CKM_DES_ECB: MechanismInfo(
        CKM_DES_ECB, MF_ENCRYPT | MF_DECRYPT, CKK_DES, 64, 64, "DES ECB"),
    CKM_DES_CBC: MechanismInfo(
        CKM_DES_CBC, MF_ENCRYPT | MF_DECRYPT, CKK_DES, 64, 64, "DES CBC"),

    # 3DES mechanisms
    CKM_DES3_ECB: MechanismInfo(
        CKM_DES3_ECB, MF_ENCRYPT | MF_DECRYPT, CKK_DES3, 112, 168, "3DES ECB"),
    CKM_DES3_CBC: MechanismInfo(
        CKM_DES3_CBC, MF_ENCRYPT | MF_DECRYPT, CKK_DES3, 112, 168, "3DES CBC"),
    CKM_DES3_CBC_PAD: MechanismInfo(
        CKM_DES3_CBC_PAD, MF_ENCRYPT | MF_DECRYPT, CKK_DES3, 112, 168, "3DES CBC with padding"),

    # EC mechanisms
    CKM_ECDSA: MechanismInfo(
        CKM_ECDSA, MF_SIGN | MF_VERIFY, CKK_EC, 256, 521, "ECDSA"),
    CKM_ECDH1_DERIVE: MechanismInfo(
        CKM_ECDH1_DERIVE, MF_DERIVE, CKK_EC, 256, 521, "ECDH key derivation"),

    # DSA mechanism
    CKM_DSA: MechanismInfo(
        CKM_DSA, MF_SIGN | MF_VERIFY, CKK_DSA, 1024, 3072, "DSA"),

    # Hash mechanisms
    CKM_SHA_1: MechanismInfo(
        CKM_SHA_1, MF_DIGEST, None, 0, 0, "SHA-1"),
    CKM_SHA256: MechanismInfo(
        CKM_SHA256, MF_DIGEST, None, 0, 0, "SHA-256"),
    CKM_SHA384: MechanismInfo(
        CKM_SHA384, MF_DIGEST, None, 0, 0, "SHA-384"),
    CKM_SHA512: MechanismInfo(
        CKM_SHA512, MF_DIGEST, None, 0, 0, "SHA-512"),

    # HMAC mechanisms
    CKM_SHA_1_HMAC: MechanismInfo(
        CKM_SHA_1_HMAC, MF_SIGN | MF_VERIFY, CKK_SHA_1_HMAC, 20, 512, "HMAC-SHA1"),
    CKM_SHA256_HMAC: MechanismInfo(
        CKM_SHA256_HMAC, MF_SIGN | MF_VERIFY, CKK_SHA256_HMAC, 32, 512, "HMAC-SHA256"),
    CKM_SHA384_HMAC: MechanismInfo(
        CKM_SHA384_HMAC, MF_SIGN | MF_VERIFY, CKK_SHA384_HMAC, 48, 512, "HMAC-SHA384"),
    CKM_SHA512_HMAC: MechanismInfo(
        CKM_SHA512_HMAC, MF_SIGN | MF_VERIFY, CKK_SHA512_HMAC, 64, 512, "HMAC-SHA512"),

    # KDF mechanisms
    CKM_PBKDF2: MechanismInfo(
        CKM_PBKDF2, MF_DERIVE, CKK_GENERIC_SECRET, 8, 512, "PBKDF2"),
    CKM_HKDF_DERIVE: MechanismInfo(
        CKM_HKDF_DERIVE, MF_DERIVE, CKK_GENERIC_SECRET, 8, 512, "HKDF"),
}


def get_mechanism_info(mechanism: int) -> MechanismInfo:
    """Return the MechanismInfo for *mechanism* or raise."""
    info = MECHANISMS.get(mechanism)
    if info is None:
        from pkcs11.constants import PKCS11Error, CKR_MECHANISM_INVALID
        raise PKCS11Error(CKR_MECHANISM_INVALID,
                          f"Unknown mechanism: 0x{mechanism:08X}")
    return info


def is_mechanism_supported(mechanism: int) -> bool:
    """Check whether a mechanism is in the registry."""
    return mechanism in MECHANISMS


def list_mechanisms() -> list:
    """Return all registered mechanism IDs."""
    return sorted(MECHANISMS.keys())


# String name -> mechanism ID map (for CLI parsing)
MECHANISM_NAME_TO_ID = {
    "RSA_PKCS": CKM_RSA_PKCS,
    "RSA_PKCS_OAEP": CKM_RSA_PKCS_OAEP,
    "RSA_PKCS_PSS": CKM_RSA_PKCS_PSS,
    "SHA1_RSA_PKCS": CKM_SHA_1_RSA_PKCS,
    "SHA256_RSA_PKCS": CKM_SHA256_RSA_PKCS,
    "SHA384_RSA_PKCS": CKM_SHA384_RSA_PKCS,
    "SHA512_RSA_PKCS": CKM_SHA512_RSA_PKCS,
    "SHA1_RSA_PKCS_PSS": CKM_SHA_1_RSA_PKCS_PSS,
    "SHA256_RSA_PKCS_PSS": CKM_SHA256_RSA_PKCS_PSS,
    "SHA384_RSA_PKCS_PSS": CKM_SHA384_RSA_PKCS_PSS,
    "SHA512_RSA_PKCS_PSS": CKM_SHA512_RSA_PKCS_PSS,
    "AES_ECB": CKM_AES_ECB,
    "AES_CBC": CKM_AES_CBC,
    "AES_CBC_PAD": CKM_AES_CBC_PAD,
    "AES_CTR": CKM_AES_CTR,
    "AES_GCM": CKM_AES_GCM,
    "AES_CMAC": CKM_AES_CMAC,
    "DES_ECB": CKM_DES_ECB,
    "DES_CBC": CKM_DES_CBC,
    "DES3_ECB": CKM_DES3_ECB,
    "DES3_CBC": CKM_DES3_CBC,
    "DES3_CBC_PAD": CKM_DES3_CBC_PAD,
    "ECDSA": CKM_ECDSA,
    "ECDH1_DERIVE": CKM_ECDH1_DERIVE,
    "DSA": CKM_DSA,
    "SHA_1": CKM_SHA_1,
    "SHA256": CKM_SHA256,
    "SHA384": CKM_SHA384,
    "SHA512": CKM_SHA512,
    "SHA1_HMAC": CKM_SHA_1_HMAC,
    "SHA256_HMAC": CKM_SHA256_HMAC,
    "SHA384_HMAC": CKM_SHA384_HMAC,
    "SHA512_HMAC": CKM_SHA512_HMAC,
    "PBKDF2": CKM_PBKDF2,
    "HKDF": CKM_HKDF_DERIVE,
    "AES_KEY_GEN": CKM_AES_KEY_GEN,
    "RSA_PKCS_KEY_PAIR_GEN": CKM_RSA_PKCS_KEY_PAIR_GEN,
    "EC_KEY_PAIR_GEN": CKM_EC_KEY_PAIR_GEN,
    "DSA_KEY_PAIR_GEN": CKM_DSA_KEY_PAIR_GEN,
    "DES3_KEY_GEN": CKM_DES3_KEY_GEN,
    "GENERIC_SECRET_KEY_GEN": CKM_GENERIC_SECRET_KEY_GEN,
}
