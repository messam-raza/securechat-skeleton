"""
Utility Module - Helper Functions
Helper signatures: now_ms, b64e, b64d, sha256_hex and additional utilities.
"""

import os
import time
import base64
import secrets
import hashlib
import re

    
def now_ms():
    """
    Get current Unix timestamp in milliseconds.
    
    Returns:
        int: Current time in milliseconds since epoch
    """
    return int(time.time() * 1000)


def b64e(b: bytes):
    """
    Base64 encode bytes.
    
    Args:
        b: Bytes to encode
    
    Returns:
        str: Base64-encoded string
    """
    return base64.b64encode(b).decode('utf-8')


def b64d(s: str):
    """
    Base64 decode string.
    
    Args:
        s: Base64-encoded string
    
    Returns:
        bytes: Decoded bytes
    """
    return base64.b64decode(s)


def sha256_hex(data: bytes):
    """
    Compute SHA-256 hash and return as hex string.
    
    Args:
        data: Bytes to hash
    
    Returns:
        str: Hexadecimal hash string (64 characters)
    """
    return hashlib.sha256(data).hexdigest()


def generate_nonce(length=16):
    """
    Generate a random nonce.
    
    Args:
        length: Nonce length in bytes (default: 16)
    
    Returns:
        bytes: Random nonce
    """
    return secrets.token_bytes(length)


def generate_salt(length=16):
    """
    Generate a random salt for password hashing.
    
    Args:
        length: Salt length in bytes (default: 16)
    
    Returns:
        bytes: Random salt
    """
    return secrets.token_bytes(length)


def bytes_to_base64(data):
    """Convert bytes to base64 string (alias for b64e)."""
    return b64e(data)


def base64_to_bytes(b64_string):
    """Convert base64 string to bytes (alias for b64d)."""
    return b64d(b64_string)


def format_certificate_info(cert_info):
    """
    Format certificate information for display.
    
    Args:
        cert_info: Dictionary with certificate details
    
    Returns:
        str: Formatted string
    """
    return f"""
Certificate Information:
  Subject: {cert_info['subject']}
  Issuer: {cert_info['issuer']}
  Serial Number: {cert_info['serial_number']}
  Valid From: {cert_info['not_valid_before']}
  Valid Until: {cert_info['not_valid_after']}
  Fingerprint (SHA-256): {cert_info['fingerprint']}
    """.strip()


def send_message(socket, message):
    """
    Send a message over a socket with length prefix.
    
    Args:
        socket: Socket object
        message: Message string to send
    """
    # Encode message
    message_bytes = message.encode('utf-8')
    
    # Send length prefix (4 bytes, big-endian)
    length = len(message_bytes)
    socket.sendall(length.to_bytes(4, byteorder='big'))
    
    # Send message
    socket.sendall(message_bytes)


def receive_message(socket):
    """
    Receive a message from a socket with length prefix.
    
    Args:
        socket: Socket object
    
    Returns:
        str: Received message or None if connection closed
    """
    # Receive length prefix (4 bytes)
    length_bytes = _receive_exact(socket, 4)
    if not length_bytes:
        return None
    
    # Parse length
    length = int.from_bytes(length_bytes, byteorder='big')
    
    # Receive message
    message_bytes = _receive_exact(socket, length)
    if not message_bytes:
        return None
    
    # Decode message
    return message_bytes.decode('utf-8')


def _receive_exact(socket, length):
    """
    Receive exact number of bytes from socket.
    
    Args:
        socket: Socket object
        length: Number of bytes to receive
    
    Returns:
        bytes: Received data or None if connection closed
    """
    data = b''
    while len(data) < length:
        chunk = socket.recv(length - len(data))
        if not chunk:
            return None
        data += chunk
    return data


class TranscriptLogger:
    """Manages session transcript for non-repudiation."""
    
    def __init__(self, filepath, peer_role):
        """
        Initialize transcript logger.
        
        Args:
            filepath: Path to transcript file
            peer_role: "client" or "server"
        """
        self.filepath = filepath
        self.peer_role = peer_role
        self.lines = []
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        # Open file in append mode
        self.file = open(filepath, 'a', encoding='utf-8')
    
    def log_message(self, seqno, timestamp, ciphertext_b64, signature_b64, peer_cert_fingerprint):
        """
        Log a message to the transcript.
        Format: seqno|timestamp|ciphertext_b64|signature_b64|peer_cert_fingerprint
        
        Args:
            seqno: Sequence number
            timestamp: Unix timestamp (ms)
            ciphertext_b64: Base64-encoded ciphertext
            signature_b64: Base64-encoded signature
            peer_cert_fingerprint: SHA-256 fingerprint of peer's certificate
        """
        line = f"{seqno}|{timestamp}|{ciphertext_b64}|{signature_b64}|{peer_cert_fingerprint}\n"
        self.lines.append(line)
        self.file.write(line)
        self.file.flush()  # Ensure data is written immediately
    
    def get_transcript_lines(self):
        """Get all transcript lines."""
        return self.lines
    
    def close(self):
        """Close transcript file."""
        if self.file:
            self.file.close()
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()


def validate_email(email):
    """
    Basic email validation.
    
    Args:
        email: Email string
    
    Returns:
        bool: True if valid format
    """
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def validate_username(username):
    """
    Validate username (alphanumeric, underscore, 3-20 chars).
    
    Args:
        username: Username string
    
    Returns:
        bool: True if valid
    """
    pattern = r'^[a-zA-Z0-9_]{3,20}$'
    return re.match(pattern, username) is not None


def validate_password(password):
    """
    Validate password strength (min 8 chars).
    
    Args:
        password: Password string
    
    Returns:
        tuple: (is_valid, message)
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    # Additional checks can be added here
    # (uppercase, lowercase, digits, special chars)
    
    return True, "Password valid"


def clear_screen():
    """Clear console screen."""
    os.system('cls' if os.name == 'nt' else 'clear')


def print_banner(title):
    """
    Print a formatted banner.
    
    Args:
        title: Banner title
    """
    width = 60
    print("\n" + "=" * width)
    print(title.center(width))
    print("=" * width + "\n")


def constant_time_compare(a, b):
    """
    Constant-time string comparison to prevent timing attacks.
    
    Args:
        a: First string
        b: Second string
    
    Returns:
        bool: True if strings are equal
    """
    if len(a) != len(b):
        return False
    
    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)
    
    return result == 0



if __name__ == '__main__':
    # Test helper functions
    print("Testing utility functions...")
    
    # Test now_ms
    timestamp = now_ms()
    print(f"✓ now_ms(): {timestamp}")
    assert isinstance(timestamp, int)
    assert timestamp > 0
    
    # Test b64e and b64d
    test_data = b"Hello, SecureChat!"
    encoded = b64e(test_data)
    decoded = b64d(encoded)
    print(f"✓ b64e/b64d: {test_data} -> {encoded} -> {decoded}")
    assert decoded == test_data
    
    # Test sha256_hex
    hash_result = sha256_hex(test_data)
    print(f"✓ sha256_hex: {hash_result}")
    assert len(hash_result) == 64
    assert all(c in '0123456789abcdef' for c in hash_result)
    
    # Test generate_nonce
    nonce = generate_nonce(16)
    print(f"✓ generate_nonce: {len(nonce)} bytes")
    assert len(nonce) == 16
    
    # Test generate_salt
    salt = generate_salt(16)
    print(f"✓ generate_salt: {len(salt)} bytes")
    assert len(salt) == 16
    
    # Test validation functions
    assert validate_email("test@example.com") == True
    assert validate_email("invalid-email") == False
    print("✓ validate_email")
    
    assert validate_username("alice123") == True
    assert validate_username("ab") == False  # too short
    print("✓ validate_username")
    
    is_valid, msg = validate_password("SecurePass123")
    assert is_valid == True
    print("✓ validate_password")
    
    # Test constant_time_compare
    assert constant_time_compare("secret", "secret") == True
    assert constant_time_compare("secret", "public") == False
    print("✓ constant_time_compare")
    
    print("\n✅ All utility functions working correctly!")