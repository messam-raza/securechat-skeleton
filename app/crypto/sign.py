#!/usr/bin/env python3
"""
RSA PKCS#1 v1.5 SHA-256 helpers for signing and verifying messages.
"""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

def load_rsa_private(path: str):
    with open(path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    return key

def load_rsa_public(path: str):
    with open(path, "rb") as f:
        cert = serialization.load_pem_x509_certificate(f.read())
    return cert.public_key()

def sign_data(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    """
    Sign data using RSA PKCS#1 v1.5 + SHA-256
    """
    return private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

def verify_signature(public_key: rsa.RSAPublicKey, data: bytes, signature: bytes) -> bool:
    """
    Verify RSA PKCS#1 v1.5 + SHA-256 signature
    """
    try:
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False
