"""X.509 validation: signed-by-CA, validity window, CN/SAN.""" 
"""
PKI Module - Certificate Loading, Validation, and Verification
Handles X.509 certificate operations and chain validation.
"""

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID
import datetime


class PKIManager:
    """Manages PKI operations including certificate validation."""
    
    def __init__(self, ca_cert_path, entity_cert_path, entity_key_path):
        """
        Initialize PKI manager.
        
        Args:
            ca_cert_path: Path to CA certificate
            entity_cert_path: Path to entity's certificate
            entity_key_path: Path to entity's private key
        """
        self.ca_cert = self._load_certificate(ca_cert_path)
        self.entity_cert = self._load_certificate(entity_cert_path)
        self.entity_private_key = self._load_private_key(entity_key_path)
        self.entity_public_key = self.entity_cert.public_key()
    
    @staticmethod
    def _load_certificate(cert_path):
        """Load X.509 certificate from PEM file."""
        with open(cert_path, 'rb') as f:
            return x509.load_pem_x509_certificate(f.read(), default_backend())
    
    @staticmethod
    def _load_private_key(key_path):
        """Load RSA private key from PEM file."""
        with open(key_path, 'rb') as f:
            return serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
    
    def get_certificate_pem(self):
        """Export entity's certificate as PEM string."""
        return self.entity_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    
    def verify_certificate(self, peer_cert_pem, expected_cn=None):
        """
        Verify peer's certificate against CA and perform comprehensive validation.
        
        Args:
            peer_cert_pem: Peer's certificate in PEM format (string)
            expected_cn: Expected Common Name (optional)
        
        Returns:
            tuple: (is_valid, certificate_object, error_message)
        """
        try:
            # Parse certificate
            peer_cert = x509.load_pem_x509_certificate(
                peer_cert_pem.encode('utf-8'),
                default_backend()
            )
            
            # 1. Verify signature chain (issued by trusted CA)
            try:
                self.ca_cert.public_key().verify(
                    peer_cert.signature,
                    peer_cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    peer_cert.signature_hash_algorithm
                )
            except Exception as e:
                return False, None, f"BAD_CERT: Signature verification failed - {str(e)}"
            
            # 2. Check if certificate is self-signed (should not be for client/server)
            if peer_cert.issuer == peer_cert.subject:
                return False, None, "BAD_CERT: Self-signed certificate not trusted"
            
            # 3. Verify issuer matches CA
            if peer_cert.issuer != self.ca_cert.subject:
                return False, None, f"BAD_CERT: Certificate not issued by trusted CA"
            
            # 4. Check validity period
            now = datetime.datetime.utcnow()
            if now < peer_cert.not_valid_before:
                return False, None, f"BAD_CERT: Certificate not yet valid (valid from {peer_cert.not_valid_before})"
            
            if now > peer_cert.not_valid_after:
                return False, None, f"BAD_CERT: Certificate expired (expired on {peer_cert.not_valid_after})"
            
            # 5. Verify Common Name if specified
            if expected_cn:
                cert_cn = peer_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                if not cert_cn or cert_cn[0].value != expected_cn:
                    actual_cn = cert_cn[0].value if cert_cn else "None"
                    return False, None, f"BAD_CERT: Common Name mismatch (expected: {expected_cn}, got: {actual_cn})"
            
            # 6. Check BasicConstraints (should not be a CA)
            try:
                basic_constraints = peer_cert.extensions.get_extension_for_oid(
                    ExtensionOID.BASIC_CONSTRAINTS
                ).value
                if basic_constraints.ca:
                    return False, None, "BAD_CERT: Certificate has CA flag set (should be end-entity)"
            except x509.ExtensionNotFound:
                # BasicConstraints not present is acceptable for end-entity certs
                pass
            
            # All checks passed
            return True, peer_cert, "Certificate valid"
            
        except Exception as e:
            return False, None, f"BAD_CERT: Certificate parsing/validation error - {str(e)}"
    
    def get_certificate_fingerprint(self, cert=None):
        """
        Calculate SHA-256 fingerprint of a certificate.
        
        Args:
            cert: Certificate object (uses entity cert if None)
        
        Returns:
            str: Hexadecimal fingerprint
        """
        if cert is None:
            cert = self.entity_cert
        
        fingerprint = cert.fingerprint(hashes.SHA256())
        return fingerprint.hex()
    
    def sign_data(self, data):
        """
        Sign data using entity's private key (RSA-PSS with SHA-256).
        
        Args:
            data: bytes to sign
        
        Returns:
            bytes: Signature
        """
        signature = self.entity_private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
    
    def verify_signature(self, data, signature, peer_cert):
        """
        Verify signature using peer's certificate.
        
        Args:
            data: Original data (bytes)
            signature: Signature to verify (bytes)
            peer_cert: Peer's certificate object
        
        Returns:
            bool: True if signature is valid
        """
        try:
            peer_cert.public_key().verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            print(f"[!] Signature verification failed: {e}")
            return False
    
    def get_certificate_info(self, cert=None):
        """
        Get human-readable certificate information.
        
        Args:
            cert: Certificate object (uses entity cert if None)
        
        Returns:
            dict: Certificate details
        """
        if cert is None:
            cert = self.entity_cert
        
        return {
            'subject': cert.subject.rfc4514_string(),
            'issuer': cert.issuer.rfc4514_string(),
            'serial_number': cert.serial_number,
            'not_valid_before': cert.not_valid_before.isoformat(),
            'not_valid_after': cert.not_valid_after.isoformat(),
            'fingerprint': self.get_certificate_fingerprint(cert)
        }