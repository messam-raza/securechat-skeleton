"""RSA PKCS#1 v1.5 SHA-256 sign/verify.""" 
"""
Digital Signature Module
Handles RSA signing and verification with SHA-256.
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from app.common.utils import b64e, b64d, sha256_hex


class SignatureManager:
    """Manages digital signatures for messages and transcripts."""
    
    @staticmethod
    def compute_message_digest(seqno, timestamp, ciphertext):
        """
        Compute SHA-256 digest for a message.
        digest = SHA256(seqno || timestamp || ciphertext)
        
        Args:
            seqno: Sequence number (int)
            timestamp: Unix timestamp in milliseconds (int)
            ciphertext: Encrypted message (bytes)
        
        Returns:
            bytes: SHA-256 digest (32 bytes)
        """
        # Convert integers to bytes (8 bytes each, big-endian)
        seqno_bytes = seqno.to_bytes(8, byteorder='big')
        ts_bytes = timestamp.to_bytes(8, byteorder='big')
        
        # Concatenate: seqno || timestamp || ciphertext
        data = seqno_bytes + ts_bytes + ciphertext
        
        # Compute SHA-256
        digest_obj = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest_obj.update(data)
        digest = digest_obj.finalize()
        
        return digest
    
    @staticmethod
    def compute_sha256(data):
        """
        Compute SHA-256 hash of arbitrary data.
        
        Args:
            data: bytes to hash
        
        Returns:
            bytes: SHA-256 digest (32 bytes)
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        digest_obj = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest_obj.update(data)
        return digest_obj.finalize()
    
    @staticmethod
    def compute_transcript_hash(transcript_lines):
        """
        Compute SHA-256 hash of session transcript.
        
        Args:
            transcript_lines: List of transcript line strings
        
        Returns:
            str: Hexadecimal hash
        """
        # Concatenate all transcript lines
        transcript_data = ''.join(transcript_lines).encode('utf-8')
        
        # Compute SHA-256 using helper function
        return sha256_hex(transcript_data)
    
    @staticmethod
    def sign_digest(digest, private_key):
        """
        Sign a digest using RSA private key.
        
        Args:
            digest: SHA-256 digest (bytes)
            private_key: RSA private key object
        
        Returns:
            bytes: Signature
        """
        from cryptography.hazmat.primitives.asymmetric import padding
        
        signature = private_key.sign(
            digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return signature
    
    @staticmethod
    def verify_digest_signature(digest, signature, public_key):
        """
        Verify a signature on a digest using RSA public key.
        
        Args:
            digest: Original SHA-256 digest (bytes)
            signature: Signature to verify (bytes)
            public_key: RSA public key object
        
        Returns:
            bool: True if signature is valid
        """
        from cryptography.hazmat.primitives.asymmetric import padding
        
        try:
            public_key.verify(
                signature,
                digest,
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
    
    @staticmethod
    def encode_signature(signature):
        """
        Encode signature as base64 string.
        
        Args:
            signature: Signature bytes
        
        Returns:
            str: Base64-encoded signature
        """
        return b64e(signature)
    
    @staticmethod
    def decode_signature(b64_signature):
        """
        Decode base64 signature.
        
        Args:
            b64_signature: Base64 string
        
        Returns:
            bytes: Signature
        """
        return b64d(b64_signature)
    
    @staticmethod
    def create_message_signature(seqno, timestamp, ciphertext, private_key):
        """
        Create signature for a chat message.
        
        Args:
            seqno: Sequence number
            timestamp: Unix timestamp (ms)
            ciphertext: Encrypted message bytes
            private_key: RSA private key
        
        Returns:
            str: Base64-encoded signature
        """
        # Compute digest
        digest = SignatureManager.compute_message_digest(seqno, timestamp, ciphertext)
        
        # Sign digest
        signature = SignatureManager.sign_digest(digest, private_key)
        
        # Encode to base64
        return SignatureManager.encode_signature(signature)
    
    @staticmethod
    def verify_message_signature(seqno, timestamp, ciphertext, b64_signature, public_key):
        """
        Verify signature of a chat message.
        
        Args:
            seqno: Sequence number
            timestamp: Unix timestamp (ms)
            ciphertext: Encrypted message bytes
            b64_signature: Base64-encoded signature
            public_key: RSA public key
        
        Returns:
            bool: True if signature is valid
        """
        try:
            # Recompute digest
            digest = SignatureManager.compute_message_digest(seqno, timestamp, ciphertext)
            
            # Decode signature
            signature = SignatureManager.decode_signature(b64_signature)
            
            # Verify
            return SignatureManager.verify_digest_signature(digest, signature, public_key)
        except Exception as e:
            print(f"[!] Message signature verification error: {e}")
            return False