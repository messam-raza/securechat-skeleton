"""Classic DH helpers + Trunc16(SHA256(Ks)) derivation.""" 
"""
Diffie-Hellman Key Exchange Module
Implements classical DH key agreement for session key establishment.
"""

import os
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


class DHKeyExchange:
    """Handles Diffie-Hellman key exchange operations."""
    
    # RFC 3526 2048-bit MODP Group (Group 14)
    # These are well-known, secure parameters
    DEFAULT_P = int(
        'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1'
        '29024E088A67CC74020BBEA63B139B22514A08798E3404DD'
        'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245'
        'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'
        'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D'
        'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F'
        '83655D23DCA3AD961C62F356208552BB9ED529077096966D'
        '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B'
        'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9'
        'DE2BCBF6955817183995497CEA956AE515D2261898FA0510'
        '15728E5A8AACAA68FFFFFFFFFFFFFFFF', 16
    )
    
    DEFAULT_G = 2
    
    def __init__(self, p=None, g=None):
        """
        Initialize DH with parameters.
        
        Args:
            p: Prime modulus (uses RFC 3526 default if None)
            g: Generator (uses 2 if None)
        """
        self.p = p if p is not None else self.DEFAULT_P
        self.g = g if g is not None else self.DEFAULT_G
        self.private_key = None
        self.public_key = None
        self.shared_secret = None
    
    def generate_private_key(self):
        """Generate a random private key (exponent)."""
        # Generate random private key between 2 and p-2
        # Use at least 256 bits of randomness for security
        bit_length = self.p.bit_length()
        while True:
            self.private_key = secrets.randbelow(self.p - 2) + 1
            # Ensure sufficient entropy (at least 256 bits)
            if self.private_key.bit_length() >= min(256, bit_length - 1):
                break
        
        return self.private_key
    
    def compute_public_key(self):
        """
        Compute public key: A = g^a mod p or B = g^b mod p.
        
        Returns:
            int: Public key
        """
        if self.private_key is None:
            self.generate_private_key()
        
        # Use Python's built-in pow with three arguments for efficient modular exponentiation
        self.public_key = pow(self.g, self.private_key, self.p)
        return self.public_key
    
    def compute_shared_secret(self, peer_public_key):
        """
        Compute shared secret: K_s = B^a mod p = A^b mod p.
        
        Args:
            peer_public_key: Peer's public DH value
        
        Returns:
            int: Shared secret
        """
        if self.private_key is None:
            raise ValueError("Private key not generated")
        
        # Validate peer's public key
        if not self._validate_public_key(peer_public_key):
            raise ValueError("Invalid peer public key")
        
        # Compute shared secret
        self.shared_secret = pow(peer_public_key, self.private_key, self.p)
        return self.shared_secret
    
    def _validate_public_key(self, public_key):
        """
        Validate peer's public key to prevent small subgroup attacks.
        
        Args:
            public_key: Peer's public key
        
        Returns:
            bool: True if valid
        """
        # Check that 2 <= public_key <= p-2
        if not (2 <= public_key <= self.p - 2):
            return False
        
        # Additional check: ensure public_key is not 1 or p-1
        if public_key == 1 or public_key == self.p - 1:
            return False
        
        return True
    
    def derive_session_key(self, shared_secret=None):
        """
        Derive AES-128 session key from shared secret.
        K = Trunc_16(SHA256(big-endian(K_s)))
        
        Args:
            shared_secret: Shared secret (uses stored value if None)
        
        Returns:
            bytes: 16-byte AES key
        """
        if shared_secret is None:
            if self.shared_secret is None:
                raise ValueError("Shared secret not computed")
            shared_secret = self.shared_secret
        
        # Convert shared secret to big-endian bytes
        byte_length = (shared_secret.bit_length() + 7) // 8
        shared_secret_bytes = shared_secret.to_bytes(byte_length, byteorder='big')
        
        # Compute SHA-256 hash
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(shared_secret_bytes)
        hash_output = digest.finalize()
        
        # Truncate to 16 bytes for AES-128
        session_key = hash_output[:16]
        
        return session_key
    
    def get_public_parameters(self):
        """
        Get public parameters for exchange.
        
        Returns:
            dict: {'g': generator, 'p': prime, 'public_key': A or B}
        """
        if self.public_key is None:
            self.compute_public_key()
        
        return {
            'g': self.g,
            'p': self.p,
            'public_key': self.public_key
        }
    
    @staticmethod
    def create_initiator():
        """
        Create DH instance for initiator (client).
        Generates parameters and computes public key.
        
        Returns:
            DHKeyExchange: Configured instance with public key
        """
        dh = DHKeyExchange()
        dh.compute_public_key()
        return dh
    
    @staticmethod
    def create_responder(p, g):
        """
        Create DH instance for responder (server).
        Uses parameters received from initiator.
        
        Args:
            p: Prime modulus from initiator
            g: Generator from initiator
        
        Returns:
            DHKeyExchange: Configured instance with public key
        """
        dh = DHKeyExchange(p=p, g=g)
        dh.compute_public_key()
        return dh