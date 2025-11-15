#!/usr/bin/env python3
"""
gen_ca.py
Generate a root Certificate Authority (CA) key and self-signed certificate.

Outputs (default):
  certs/ca.key.pem   # PEM encoded private key (PKCS#8)
  certs/ca.cert.pem  # PEM encoded self-signed X.509 certificate

Important security note:
  - Do NOT commit the private key file (ca.key.pem) to your repo.
  - Protect the file permissions (e.g., chmod 600).
"""

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
import os

OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "certs")
CA_KEY_PATH = os.path.join(OUT_DIR, "ca.key.pem")
CA_CERT_PATH = os.path.join(OUT_DIR, "ca.cert.pem")


def ensure_out_dir():
    os.makedirs(OUT_DIR, exist_ok=True)


def generate_ca(key_size=4096, valid_days=3650):
    """
    Generate an RSA private key and a self-signed certificate for the root CA.
    key_size: RSA bits (4096 recommended)
    valid_days: days certificate is valid (e.g., 10 years = 3650 days)
    """
    # 1) Generate private key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    # 2) Build subject / issuer (self-signed)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Province"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat-CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "SecureChat Root CA"),
        ]
    )

    # 3) Certificate builder
    now = datetime.datetime.utcnow()
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=valid_days))
        # BasicConstraints: CA:TRUE, path_length None (root)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        # KeyUsage for CA: keyCertSign, crlSign
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        # SubjectKeyIdentifier
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), critical=False)
    )

    # 4) Self-sign
    certificate = cert_builder.sign(private_key=private_key, algorithm=hashes.SHA256())

    # 5) Write out files (PKCS#8 for key)
    with open(CA_KEY_PATH, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    os.chmod(CA_KEY_PATH, 0o600)

    with open(CA_CERT_PATH, "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))

    print(f"[+] CA key written: {CA_KEY_PATH}")
    print(f"[+] CA certificate written: {CA_CERT_PATH}")


if __name__ == "__main__":
    ensure_out_dir()
    generate_ca()
