#!/usr/bin/env python3
"""
gen_cert.py
Create a new RSA keypair and an X.509 certificate signed by the root CA created
by scripts/gen_ca.py.

Usage:
  python3 scripts/gen_cert.py --cn server
  python3 scripts/gen_cert.py --cn client --san 127.0.0.1

Outputs (default):
  certs/<cn>.key.pem
  certs/<cn>.cert.pem

Important:
  - Do NOT commit the private key to your repository.
  - This script expects certs/ca.key.pem and certs/ca.cert.pem to exist.
"""

import argparse
import datetime
import os
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key


THIS_DIR = os.path.join(os.path.dirname(__file__), "..")
OUT_DIR = os.path.join(THIS_DIR, "certs")
CA_KEY_PATH = os.path.join(OUT_DIR, "ca.key.pem")
CA_CERT_PATH = os.path.join(OUT_DIR, "ca.cert.pem")


def load_ca():
    if not os.path.exists(CA_KEY_PATH) or not os.path.exists(CA_CERT_PATH):
        raise FileNotFoundError("CA key or cert not found. Run scripts/gen_ca.py first.")
    with open(CA_KEY_PATH, "rb") as f:
        ca_key = load_pem_private_key(f.read(), password=None)
    with open(CA_CERT_PATH, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    return ca_key, ca_cert


def generate_cert(cn: str, san: list = None, key_size=2048, valid_days=3650):
    """
    Generate key + certificate for the supplied Common Name (cn).
    san: optional list of subjectAltName entries (IP addresses or DNS names)
    """
    san = san or []
    ca_key, ca_cert = load_ca()

    # 1) create private key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    # 2) subject name
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )

    # 3) Build certificate
    now = datetime.datetime.utcnow()
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=valid_days))
        # Not a CA
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        # Key usage: digital signature, key encipherment
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        # Extended key usage: serverAuth and clientAuth (so same script can issue both)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    )

    # 4) Add subjectAltName if given
    alt_names = []
    for entry in san:
        # try IP address vs DNS name
        try:
            # If it parses as an IP address, add as IP
            import ipaddress
            ip = ipaddress.ip_address(entry)
            alt_names.append(x509.IPAddress(ip))
        except Exception:
            alt_names.append(x509.DNSName(entry))

    if alt_names:
        builder = builder.add_extension(x509.SubjectAlternativeName(alt_names), critical=False)

    # 5) Sign the cert with CA private key
    certificate = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())

    # 6) Output to files
    key_path = os.path.join(OUT_DIR, f"{cn}.key.pem")
    cert_path = os.path.join(OUT_DIR, f"{cn}.cert.pem")

    with open(key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    os.chmod(key_path, 0o600)

    with open(cert_path, "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))

    print(f"[+] key written: {key_path}")
    print(f"[+] cert written: {cert_path}")
    return key_path, cert_path


def parse_args():
    p = argparse.ArgumentParser(description="Generate RSA key and X.509 cert signed by local CA.")
    p.add_argument("--cn", required=True, help="Common Name for certificate (e.g., server or client).")
    p.add_argument("--san", nargs="*", help="Optional SAN entries (DNS names or IPs).")
    p.add_argument("--days", type=int, default=3650, help="Validity in days (default 3650).")
    p.add_argument("--bits", type=int, default=2048, help="RSA key size in bits for entity (default 2048).")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    os.makedirs(OUT_DIR, exist_ok=True)
    generate_cert(cn=args.cn, san=args.san or [], key_size=args.bits, valid_days=args.days)
