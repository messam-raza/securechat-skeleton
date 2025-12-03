"""Create Root CA (RSA + self-signed X.509) using cryptography.""" 
"""
Root CA Generation Script
Creates a self-signed root Certificate Authority for the secure chat system.
"""

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import datetime
import os

def generate_root_ca():
    """Generate a self-signed root CA certificate and private key."""
    
    # Create certs directory if it doesn't exist
    os.makedirs('certs', exist_ok=True)
    
    print("[*] Generating RSA private key for Root CA...")
    # Generate RSA private key (2048 bits minimum for security)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    print("[*] Creating self-signed certificate...")
    # Create certificate subject
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Punjab"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Rawalpindi"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"FAST NUCES SecureChat"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"Certificate Authority"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"SecureChat Root CA"),
    ])
    
    # Build the certificate
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))  # 10 years
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )
    
    print("[*] Saving CA private key to certs/ca_private_key.pem...")
    # Write private key to file (encrypted with password for security)
    with open('certs/ca_private_key.pem', 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()  # For simplicity; use BestAvailableEncryption in production
        ))
    
    print("[*] Saving CA certificate to certs/ca_cert.pem...")
    # Write certificate to file
    with open('certs/ca_cert.pem', 'wb') as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))
    
    print("\n[✓] Root CA generated successfully!")
    print("    - Private Key: certs/ca_private_key.pem")
    print("    - Certificate: certs/ca_cert.pem")
    print(f"    - Serial Number: {certificate.serial_number}")
    print(f"    - Valid From: {certificate.not_valid_before}")
    print(f"    - Valid Until: {certificate.not_valid_after}")
    print(f"    - Subject: {certificate.subject.rfc4514_string()}")
    
    return private_key, certificate

if __name__ == '__main__':
    try:
        generate_root_ca()
    except Exception as e:
        print(f"[✗] Error generating Root CA: {e}")
        raise