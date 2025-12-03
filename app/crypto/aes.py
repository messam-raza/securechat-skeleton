"""AES-128(ECB)+PKCS#7 helpers (use library).""" 
"""
AES-128 Encryption Module
Handles symmetric encryption/decryption with PKCS#7 padding.
"""

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding


class AESCipher:
    """AES-128 encryption in CBC mode with PKCS#7 padding."""
    
    BLOCK_SIZE = 128  # bits
    KEY_SIZE = 16  # bytes (128 bits)
    
    def __init__(self, key):
        """
        Initialize AES cipher with a key.
        
        Args:
            key: 16-byte AES key
        """
        if len(key) != self.KEY_SIZE:
            raise ValueError(f"AES-128 requires a {self.KEY_SIZE}-byte key")
        
        self.key = key
    
    def encrypt(self, plaintext):
        """
        Encrypt plaintext using AES-128-CBC with PKCS#7 padding.
        
        Args:
            plaintext: bytes or str to encrypt
        
        Returns:
            tuple: (iv, ciphertext) both as bytes
        """
        # Convert string to bytes if necessary
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        # Apply PKCS#7 padding
        padder = sym_padding.PKCS7(self.BLOCK_SIZE).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        
        # Generate random IV (Initialization Vector)
        iv = os.urandom(16)  # AES block size is 16 bytes
        
        # Create cipher and encrypt
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        return iv, ciphertext
    
    def decrypt(self, iv, ciphertext):
        """
        Decrypt ciphertext using AES-128-CBC and remove PKCS#7 padding.
        
        Args:
            iv: Initialization vector (16 bytes)
            ciphertext: Encrypted data (bytes)
        
        Returns:
            bytes: Decrypted plaintext
        """
        # Create cipher and decrypt
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove PKCS#7 padding
        unpadder = sym_padding.PKCS7(self.BLOCK_SIZE).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        
        return plaintext
    
    def encrypt_to_base64(self, plaintext):
        """
        Encrypt and encode as base64 (IV prepended to ciphertext).
        
        Args:
            plaintext: Data to encrypt
        
        Returns:
            str: Base64-encoded (iv || ciphertext)
        """
        import base64
        
        iv, ciphertext = self.encrypt(plaintext)
        # Prepend IV to ciphertext for transmission
        combined = iv + ciphertext
        return base64.b64encode(combined).decode('utf-8')
    
    def decrypt_from_base64(self, b64_data):
        """
        Decode base64 and decrypt (IV prepended to ciphertext).
        
        Args:
            b64_data: Base64 string containing (iv || ciphertext)
        
        Returns:
            bytes: Decrypted plaintext
        """
        import base64
        
        combined = base64.b64decode(b64_data)
        # Extract IV (first 16 bytes) and ciphertext (rest)
        iv = combined[:16]
        ciphertext = combined[16:]
        return self.decrypt(iv, ciphertext)


def test_aes():
    """Test AES encryption/decryption."""
    # Generate a random key
    key = os.urandom(16)
    cipher = AESCipher(key)
    
    # Test data
    original = "This is a secret message for testing AES-128 encryption!"
    print(f"Original: {original}")
    
    # Encrypt
    iv, ct = cipher.encrypt(original)
    print(f"Encrypted (hex): {ct.hex()}")
    print(f"IV (hex): {iv.hex()}")
    
    # Decrypt
    decrypted = cipher.decrypt(iv, ct)
    print(f"Decrypted: {decrypted.decode('utf-8')}")
    
    # Verify
    assert decrypted.decode('utf-8') == original
    print("✓ AES test passed!")


if __name__ == '__main__':
    test_aes()