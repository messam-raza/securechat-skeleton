"""
app/crypto/pki.py
Load and verify X.509 certificates.
"""

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import datetime

def load_pem_cert(path: str) -> x509.Certificate:
    with open(path, "rb") as f:
        data = f.read()
    return x509.load_pem_x509_certificate(data)

def verify_cert_against_ca(
    peer_cert_pem: bytes,
    ca_cert_path: str,
    expected_cn: str = None,
    check_san_host: str = None
):
    try:
        ca_cert = load_pem_cert(ca_cert_path)
    except Exception as e:
        return False, f"CA_LOAD_FAIL: {e}"

    try:
        peer_cert = x509.load_pem_x509_certificate(peer_cert_pem)
    except Exception as e:
        return False, f"PEER_CERT_PARSE_FAIL: {e}"

    # 1. Verify CA signature
    try:
        ca_public_key = ca_cert.public_key()
        ca_public_key.verify(
            peer_cert.signature,
            peer_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            peer_cert.signature_hash_algorithm,
        )
    except Exception as e:
        return False, f"BAD_CERT: signature failed ({e})"

    # 2. Check validity
    now = datetime.datetime.utcnow()
    try:
        if now.replace(tzinfo=None) < peer_cert.not_valid_before:
            return False, f"BAD_CERT: not valid yet ({peer_cert.not_valid_before})"
        if now.replace(tzinfo=None) > peer_cert.not_valid_after:
            return False, f"BAD_CERT: expired ({peer_cert.not_valid_after})"
    except Exception as e:
        return False, f"TIME_CHECK_FAIL: {e}"

    # 3. Check CN
    if expected_cn:
        try:
            cn = peer_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
            if cn != expected_cn:
                return False, f"CN_MISMATCH: expected {expected_cn}, got {cn}"
        except Exception:
            return False, "CN_MISSING"

    # 4. Check SAN
    if check_san_host:
        try:
            san = peer_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            dns = san.get_values_for_type(x509.DNSName)
            ips = [str(ip) for ip in san.get_values_for_type(x509.IPAddress)]
            if check_san_host not in dns and check_san_host not in ips:
                return False, f"SAN_MISSING: {check_san_host}"
        except x509.ExtensionNotFound:
            return False, "SAN_EXTENSION_MISSING"

    return True, None

def get_cert_fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()