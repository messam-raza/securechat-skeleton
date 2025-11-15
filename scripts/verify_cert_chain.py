#!/usr/bin/env python3
"""
verify_cert_chain.py

Programmatic checks:
 - CA signature verification of target cert
 - Validity window (notBefore / notAfter)
 - Common Name (CN) check
 - SAN presence (optional)
"""

import sys
import datetime
from cryptography import x509
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

CA_CERT = "certs/ca.cert.pem"
TARGET_CERT = "certs/server.cert.pem"
EXPECTED_CN = "server"
CHECK_SAN_FOR = ["localhost", "127.0.0.1"]  # optional checks

def load_cert(path):
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())

def verify_signature(ca_cert, cert):
    # Verify that cert was signed by ca_cert (by verifying the signature over tbs_certificate_bytes)
    pubkey = ca_cert.public_key()
    signature = cert.signature
    tbs = cert.tbs_certificate_bytes
    algo = cert.signature_hash_algorithm
    try:
        pubkey.verify(
            signature,
            tbs,
            # padding depends on key type; for RSA use PKCS1v15
            padding.PKCS1v15(),
            algo,
        )
        return True, None
    except Exception as e:
        return False, str(e)

def check_validity(cert):
    now = datetime.datetime.utcnow()
    if now < cert.not_valid_before:
        return False, f"Certificate not valid yet: starts at {cert.not_valid_before}"
    if now > cert.not_valid_after:
        return False, f"Certificate expired: valid until {cert.not_valid_after}"
    return True, None

def get_cn(cert):
    try:
        for rd in cert.subject:
            if rd.oid.dotted_string == x509.NameOID.COMMON_NAME.dotted_string:
                return rd.value
    except Exception:
        pass
    # alternate approach:
    try:
        cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
        return cn
    except Exception:
        return None

def check_san(cert, required_items=None):
    required_items = required_items or []
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        dns = san.get_values_for_type(x509.DNSName)
        ips = san.get_values_for_type(x509.IPAddress)
        ips = [str(i) for i in ips]
        found = dns + ips
        missing = [r for r in required_items if r not in found]
        return len(missing) == 0, found, missing
    except x509.ExtensionNotFound:
        return False, [], required_items

def main():
    ca_cert = load_cert(CA_CERT)
    cert = load_cert(TARGET_CERT)

    ok, err = verify_signature(ca_cert, cert)
    print(f"Signature verification against CA: {'OK' if ok else 'FAIL'}")
    if not ok:
        print(" ->", err)
        sys.exit(2)

    ok, err = check_validity(cert)
    print(f"Validity window check: {'OK' if ok else 'FAIL'}")
    if not ok:
        print(" ->", err)
        sys.exit(3)

    cn = get_cn(cert)
    print("Common Name (CN):", cn)
    if cn != EXPECTED_CN:
        print(f"WARNING: CN mismatch (expected '{EXPECTED_CN}')")

    san_ok, found, missing = check_san(cert, CHECK_SAN_FOR)
    print("SAN entries found:", found)
    if not san_ok:
        print("WARNING: SAN missing required entries:", missing)

    print("All tested checks finished. If there are WARNINGS or FAIL, fix accordingly.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
