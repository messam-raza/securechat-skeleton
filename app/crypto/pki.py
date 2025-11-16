"""
app/pki.py
Utilities to load and verify X.509 certificates issued by our local CA.

Functions:
 - load_pem_cert(path) -> cryptography.x509.Certificate
 - verify_cert_against_ca(cert_pem_bytes, ca_cert_path, expected_cn=None) -> (True, None) or (False, "error message")
 - get_cert_fingerprint(cert) -> hex fingerprint (SHA256)
"""

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding
import datetime

def load_pem_cert(path: str) -> x509.Certificate:
    with open(path, "rb") as f:
        data = f.read()
    return x509.load_pem_x509_certificate(data)

def verify_cert_against_ca(peer_cert_pem: bytes, ca_cert_path: str, expected_cn: str = None, check_san_host: str = None):
    """
    Verify that peer_cert_pem (bytes) is signed by CA in ca_cert_path, that it is within validity,
    and that its CN or SAN matches expected_cn/check_san_host if provided.

    Returns: (True, None) on success, (False, "error message") on failure.
    """
    try:
        ca_cert = load_pem_cert(ca_cert_path)
    except Exception as e:
        return False, f"CA_LOAD_FAIL: {e}"

    try:
        peer_cert = x509.load_pem_x509_certificate(peer_cert_pem)
    except Exception as e:
        return False, f"PEER_CERT_PARSE_FAIL: {e}"

    # 1) Verify signature - confirms CA signed the certificate
    try:
        ca_public_key = ca_cert.public_key()
        ca_public_key.verify(
            peer_cert.signature,
            peer_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            peer_cert.signature_hash_algorithm,
        )
    except Exception as e:
        return False, f"BAD CERT: signature verification failed ({e})"

    # 2) Check validity dates
    now = datetime.datetime.utcnow()
    if now < peer_cert.not_valid_before:
        return False, f"BAD CERT: not valid yet (valid_from={peer_cert.not_valid_before})"
    if now > peer_cert.not_valid_after:
        return False, f"BAD CERT: expired (valid_to={peer_cert.not_valid_after})"

    # 3) Check CN if given
    if expected_cn:
        try:
            cn_attr = peer_cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0]
            cn = cn_attr.value
            if cn != expected_cn:
                return False, f"BAD CERT: CN mismatch (expected {expected_cn}, got {cn})"
        except Exception:
            return False, "BAD CERT: CN missing or unreadable"

    # 4) Check SAN against host if provided
    if check_san_host:
        try:
            san_ext = peer_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            dns_names = san_ext.get_values_for_type(x509.DNSName)
            ip_names = [str(x) for x in san_ext.get_values_for_type(x509.IPAddress)]
            if check_san_host not in dns_names and check_san_host not in ip_names:
                return False, f"BAD CERT: SAN does not contain {check_san_host}"
        except x509.ExtensionNotFound:
            return False, "BAD CERT: SAN extension missing"

    return True, None

def get_cert_fingerprint(cert: x509.Certificate) -> str:
    digest = cert.fingerprint(hashes.SHA256())
    return digest.hex()
