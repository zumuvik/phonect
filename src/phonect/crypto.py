"""
phonect.crypto — RSA-4096 key management, challenge/response signature ops.

All asymmetric crypto via the ``cryptography`` library.
Private keys are intended for Android Keystore (hardware-backed) and PC filesystem.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NONCE_BYTES = 32              # 256-bit cryptographic nonce
RSA_KEY_SIZE = 4096
SIGNATURE_HASH = hashes.SHA512()
SIGNATURE_PADDING = padding.PSS(
    mgf=padding.MGF1(SIGNATURE_HASH),
    salt_length=padding.PSS.MAX_LENGTH,
)

PUBLIC_KEY_FINGERPRINT_HASH = hashes.SHA256()


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class KeyPair:
    """RSA-4096 key pair representation."""
    private_key_pem: bytes
    public_key_pem: bytes
    public_key_fingerprint: str       # hex-encoded SHA-256 of DER

    @property
    def private_key(self) -> rsa.RSAPrivateKey:
        return serialization.load_pem_private_key(
            self.private_key_pem,
            password=None,
            backend=default_backend(),
        )

    @property
    def public_key(self) -> rsa.RSAPublicKey:
        return serialization.load_pem_public_key(
            self.public_key_pem,
            backend=default_backend(),
        )


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

def generate_key_pair() -> KeyPair:
    """Generate a fresh RSA-4096 key pair, return PEM-encoded keys with fingerprint."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE,
        backend=default_backend(),
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Fingerprint = SHA-256 of DER-encoded public key
    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    fingerprint = hashes.Hash(PUBLIC_KEY_FINGERPRINT_HASH, backend=default_backend())
    fingerprint.update(public_der)
    fp_hex = fingerprint.finalize().hex()

    return KeyPair(
        private_key_pem=private_pem,
        public_key_pem=public_pem,
        public_key_fingerprint=fp_hex,
    )


def load_public_key(pem_data: bytes) -> rsa.RSAPublicKey:
    """Load a PEM-encoded RSA public key."""
    return serialization.load_pem_public_key(pem_data, backend=default_backend())


def load_private_key(pem_data: bytes) -> rsa.RSAPrivateKey:
    """Load a PEM-encoded RSA private key (no password)."""
    return serialization.load_pem_private_key(
        pem_data, password=None, backend=default_backend(),
    )


# ---------------------------------------------------------------------------
# Nonce
# ---------------------------------------------------------------------------

def generate_nonce() -> bytes:
    """Generate a cryptographically secure random nonce."""
    return os.urandom(NONCE_BYTES)


# ---------------------------------------------------------------------------
# Sign & Verify
# ---------------------------------------------------------------------------

def sign_nonce(private_key: rsa.RSAPrivateKey, nonce: bytes) -> bytes:
    """
    Sign *nonce* with *private_key*.

    Returns PKCS#1 PSS SHA-512 signature bytes.
    """
    return private_key.sign(nonce, SIGNATURE_PADDING, SIGNATURE_HASH)


def verify_nonce(
    public_key: rsa.RSAPublicKey,
    nonce: bytes,
    signature: bytes,
) -> bool:
    """
    Verify *signature* of *nonce* against *public_key*.

    Returns ``True`` if valid, ``False`` otherwise (never raises).
    """
    try:
        public_key.verify(signature, nonce, SIGNATURE_PADDING, SIGNATURE_HASH)
        return True
    except InvalidSignature:
        return False


def fingerprint_from_public_key(public_key: rsa.RSAPublicKey) -> str:
    """Return hex-encoded SHA-256 fingerprint for a public key."""
    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashes.Hash(PUBLIC_KEY_FINGERPRINT_HASH, backend=default_backend())
    digest.update(public_der)
    return digest.finalize().hex()


# ---------------------------------------------------------------------------
# Key serialisation helpers
# ---------------------------------------------------------------------------

def public_key_to_pem(public_key: rsa.RSAPublicKey) -> bytes:
    """Serialise an RSA public key to PEM."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def private_key_to_pem(private_key: rsa.RSAPrivateKey) -> bytes:
    """Serialise an RSA private key to PEM (no encryption)."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
