"""Asymmetric cryptographic operations — RSA, ECC, DSA.

Uses pyca/cryptography backed by OpenSSL for key generation, signing,
verification, encryption, and key agreement.
"""

from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, padding
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import os

from pkcs11.constants import (
    PKCS11Error, CKR_KEY_SIZE_RANGE, CKR_MECHANISM_INVALID,
    CKR_SIGNATURE_INVALID, CKR_DATA_INVALID,
    CKM_RSA_PKCS, CKM_RSA_PKCS_OAEP, CKM_RSA_PKCS_PSS,
    CKM_SHA256_RSA_PKCS, CKM_SHA384_RSA_PKCS, CKM_SHA512_RSA_PKCS,
    CKM_SHA_1_RSA_PKCS,
    CKM_SHA256_RSA_PKCS_PSS, CKM_SHA384_RSA_PKCS_PSS, CKM_SHA512_RSA_PKCS_PSS,
    CKM_SHA_1_RSA_PKCS_PSS,
    CKM_ECDSA,
    CKM_DSA,
    CKM_ECDH1_DERIVE,
)

# Map of mechanism -> hash algorithm for RSA signed-digest mechanisms
_RSA_HASH_MECHS = {
    CKM_SHA_1_RSA_PKCS: hashes.SHA1,
    CKM_SHA256_RSA_PKCS: hashes.SHA256,
    CKM_SHA384_RSA_PKCS: hashes.SHA384,
    CKM_SHA512_RSA_PKCS: hashes.SHA512,
    CKM_SHA_1_RSA_PKCS_PSS: hashes.SHA1,
    CKM_SHA256_RSA_PKCS_PSS: hashes.SHA256,
    CKM_SHA384_RSA_PKCS_PSS: hashes.SHA384,
    CKM_SHA512_RSA_PKCS_PSS: hashes.SHA512,
}

# Map of ECC curve names to ec curve objects
EC_CURVES = {
    "P-256": ec.SECP256R1(),
    "P-384": ec.SECP384R1(),
    "P-521": ec.SECP521R1(),
    "secp256k1": ec.SECP256K1(),
}

# Reverse map for serialization
EC_CURVE_NAMES = {
    ec.SECP256R1(): "P-256",
    ec.SECP384R1(): "P-384",
    ec.SECP521R1(): "P-521",
    ec.SECP256K1(): "secp256k1",
}


def generate_rsa_keypair(key_size: int = 2048):
    """Generate an RSA key pair. Returns (private_key, public_key)."""
    if key_size not in (1024, 2048, 3072, 4096):
        raise PKCS11Error(CKR_KEY_SIZE_RANGE,
                          "RSA key size must be 1024, 2048, 3072, or 4096 bits")
    priv = rsa.generate_private_key(
        public_exponent=65537, key_size=key_size, backend=default_backend()
    )
    return priv, priv.public_key()


def generate_ec_keypair(curve_name: str = "P-256"):
    """Generate an EC key pair. Returns (private_key, public_key)."""
    curve = EC_CURVES.get(curve_name)
    if curve is None:
        raise PKCS11Error(CKR_MECHANISM_INVALID,
                          f"Unsupported curve: {curve_name}")
    priv = ec.generate_private_key(curve, backend=default_backend())
    return priv, priv.public_key()


def generate_dsa_keypair(key_size: int = 2048):
    """Generate a DSA key pair. Returns (private_key, public_key)."""
    if key_size not in (1024, 2048, 3072):
        raise PKCS11Error(CKR_KEY_SIZE_RANGE,
                          "DSA key size must be 1024, 2048, or 3072 bits")
    priv = dsa.generate_private_key(key_size=key_size, backend=default_backend())
    return priv, priv.public_key()


def sign(mechanism: int, private_key, data: bytes) -> bytes:
    """Sign *data* with *private_key* using the given mechanism."""
    if mechanism == CKM_RSA_PKCS:
        return private_key.sign(data, padding.PKCS1v15(), hashes.SHA1())

    elif mechanism in (CKM_SHA256_RSA_PKCS, CKM_SHA384_RSA_PKCS,
                       CKM_SHA512_RSA_PKCS, CKM_SHA_1_RSA_PKCS):
        hash_alg = _RSA_HASH_MECHS[mechanism]
        return private_key.sign(data, padding.PKCS1v15(), hash_alg())

    elif mechanism in (CKM_SHA256_RSA_PKCS_PSS, CKM_SHA384_RSA_PKCS_PSS,
                       CKM_SHA512_RSA_PKCS_PSS, CKM_SHA_1_RSA_PKCS_PSS):
        hash_alg = _RSA_HASH_MECHS[mechanism]
        return private_key.sign(
            data,
            padding.PSS(mgf=padding.MGF1(hash_alg()),
                        salt_length=padding.PSS.MAX_LENGTH),
            hash_alg()
        )

    elif mechanism == CKM_RSA_PKCS_PSS:
        return private_key.sign(
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )

    elif mechanism == CKM_ECDSA:
        return private_key.sign(data, ec.ECDSA(hashes.SHA256()))

    elif mechanism == CKM_DSA:
        return private_key.sign(data, hashes.SHA256())

    else:
        raise PKCS11Error(CKR_MECHANISM_INVALID,
                          f"Unsupported sign mechanism: 0x{mechanism:08X}")


def verify(mechanism: int, public_key, data: bytes, signature: bytes) -> bool:
    """Verify *signature* over *data* with *public_key*. Returns True or raises."""
    try:
        if mechanism == CKM_RSA_PKCS:
            public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA1())
        elif mechanism in (CKM_SHA256_RSA_PKCS, CKM_SHA384_RSA_PKCS,
                           CKM_SHA512_RSA_PKCS, CKM_SHA_1_RSA_PKCS):
            hash_alg = _RSA_HASH_MECHS[mechanism]
            public_key.verify(signature, data, padding.PKCS1v15(), hash_alg())
        elif mechanism in (CKM_SHA256_RSA_PKCS_PSS, CKM_SHA384_RSA_PKCS_PSS,
                           CKM_SHA512_RSA_PKCS_PSS, CKM_SHA_1_RSA_PKCS_PSS):
            hash_alg = _RSA_HASH_MECHS[mechanism]
            public_key.verify(
                signature, data,
                padding.PSS(mgf=padding.MGF1(hash_alg()),
                            salt_length=padding.PSS.MAX_LENGTH),
                hash_alg()
            )
        elif mechanism == CKM_RSA_PKCS_PSS:
            public_key.verify(
                signature, data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
        elif mechanism == CKM_ECDSA:
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        elif mechanism == CKM_DSA:
            public_key.verify(signature, data, hashes.SHA256())
        else:
            raise PKCS11Error(CKR_MECHANISM_INVALID,
                              f"Unsupported verify mechanism: 0x{mechanism:08X}")
        return True
    except InvalidSignature:
        raise PKCS11Error(CKR_SIGNATURE_INVALID, "Signature verification failed")


def rsa_encrypt(mechanism: int, public_key, data: bytes) -> bytes:
    """RSA-encrypt *data* with *public_key*."""
    if mechanism == CKM_RSA_PKCS:
        return public_key.encrypt(data, padding.PKCS1v15())
    elif mechanism == CKM_RSA_PKCS_OAEP:
        return public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    else:
        raise PKCS11Error(CKR_MECHANISM_INVALID,
                         f"Unsupported RSA encrypt mechanism: 0x{mechanism:08X}")


def rsa_decrypt(mechanism: int, private_key, data: bytes) -> bytes:
    """RSA-decrypt *data* with *private_key*."""
    if mechanism == CKM_RSA_PKCS:
        return private_key.decrypt(data, padding.PKCS1v15())
    elif mechanism == CKM_RSA_PKCS_OAEP:
        return private_key.decrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    else:
        raise PKCS11Error(CKR_MECHANISM_INVALID,
                         f"Unsupported RSA decrypt mechanism: 0x{mechanism:08X}")


def ecdh_derive(private_key, peer_public_key) -> bytes:
    """Perform ECDH key agreement. Returns the shared secret bytes."""
    shared = private_key.exchange(ec.ECDH(), peer_public_key)
    return shared


def serialize_private_key(priv) -> bytes:
    """Serialize a private key to DER bytes (PKCS#8)."""
    return priv.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def serialize_public_key(pub) -> bytes:
    """Serialize a public key to DER bytes (SubjectPublicKeyInfo)."""
    return pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def deserialize_private_key(der: bytes):
    """Deserialize a private key from DER bytes."""
    return serialization.load_der_private_key(der, password=None, backend=default_backend())


def deserialize_public_key(der: bytes):
    """Deserialize a public key from DER bytes."""
    return serialization.load_der_public_key(der, backend=default_backend())


def get_rsa_modulus_bits(public_key) -> int:
    """Return the RSA modulus bit length."""
    return public_key.key_size


def get_ec_curve_name(public_key) -> str:
    """Return the curve name for an EC public key."""
    curve = public_key.curve
    return EC_CURVE_NAMES.get(curve, str(curve.name))
