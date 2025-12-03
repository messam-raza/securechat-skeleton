"""Issue server/client cert signed by Root CA (SAN=DNSName(CN)).""" 
"""
Certificate Generation Script
Issues X.509 certificates for server and client, signed by the Root CA.
"""

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import datetime
import os
import sys

def load_ca():
    """Load the Root CA certificate and private key."""
    print("[*] Loading Root CA...")
    
    # Load CA private key
    with open('certs/ca_private_key.pem', 'rb') as f:
        ca_private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    
    # Load CA certificate
    with open('certs/ca_cert.pem', 'rb') as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    
    print("[✓] Root CA loaded successfully")
    return ca_private_key, ca_cert

def generate_certificate(entity_type, common_name, dns_names=None):
    """
    Generate a certificate for server or client.
    
    Args:
        entity_type: 'server' or 'client'
        common_name: CN for the certificate
        dns_names: List of DNS names for SubjectAlternativeName (optional)
    """
    
    # Load CA
    ca_private_key, ca_cert = load_ca()
    
    print(f"\n[*] Generating RSA private key for {entity_type}...")
    # Generate private key for the entity
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    print(f"[*] Creating certificate for {entity_type}...")
    # Create certificate subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Punjab"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Rawalpindi"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"FAST NUCES SecureChat"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, entity_type.title()),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    # Build certificate
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))  # 1 year
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_private_key.public_key()),
            critical=False,
        )
    )
    
    # Add appropriate key usage based on entity type
    if entity_type == 'server':
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
            ]),
            critical=True,
        )
        
        # Add SubjectAlternativeName for server
        if dns_names:
            san_list = [x509.DNSName(name) for name in dns_names]
            builder = builder.add_extension(
                x509.SubjectAlternativeName(san_list),
                critical=False,
            )
    else:  # client
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=True,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=True,
        )
    
    # Sign the certificate
    certificate = builder.sign(ca_private_key, hashes.SHA256(), default_backend())
    
    # Save private key
    key_filename = f'certs/{entity_type}_private_key.pem'
    print(f"[*] Saving {entity_type} private key to {key_filename}...")
    with open(key_filename, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Save certificate
    cert_filename = f'certs/{entity_type}_cert.pem'
    print(f"[*] Saving {entity_type} certificate to {cert_filename}...")
    with open(cert_filename, 'wb') as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))
    
    print(f"\n[✓] {entity_type.title()} certificate generated successfully!")
    print(f"    - Private Key: {key_filename}")
    print(f"    - Certificate: {cert_filename}")
    print(f"    - Serial Number: {certificate.serial_number}")
    print(f"    - Valid From: {certificate.not_valid_before}")
    print(f"    - Valid Until: {certificate.not_valid_after}")
    print(f"    - Subject: {certificate.subject.rfc4514_string()}")
    
    return private_key, certificate

def main():
    """Generate certificates for both server and client."""
    
    # Check if CA exists
    if not os.path.exists('certs/ca_cert.pem') or not os.path.exists('certs/ca_private_key.pem'):
        print("[✗] Error: Root CA not found. Run gen_ca.py first.")
        sys.exit(1)
    
    print("=" * 60)
    print("SecureChat Certificate Generation")
    print("=" * 60)
    
    # Generate server certificate
    generate_certificate(
        entity_type='server',
        common_name='securechat.server.local',
        dns_names=['localhost', 'securechat.server.local', '127.0.0.1']
    )
    
    print("\n" + "=" * 60 + "\n")
    
    # Generate client certificate
    generate_certificate(
        entity_type='client',
        common_name='securechat.client.local'
    )
    
    print("\n" + "=" * 60)
    print("[✓] All certificates generated successfully!")
    print("=" * 60)

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(f"[✗] Error generating certificates: {e}")
        raise