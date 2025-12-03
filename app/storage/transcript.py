"""Append-only transcript + TranscriptHash helpers.""" 
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
import json

def now_ms():
    """Get current Unix timestamp in milliseconds."""
    return int(time.time() * 1000)

def b64e(b: bytes):
    """Base64 encode bytes."""
    return base64.b64encode(b).decode('utf-8')

def b64d(s: str):
    """Base64 decode string."""
    return base64.b64decode(s)

def sha256_hex(data: bytes):
    """Compute SHA-256 hash and return as hex string."""
    return hashlib.sha256(data).hexdigest()


def generate_nonce(length=16):
    """Generate a random nonce."""
    return secrets.token_bytes(length)

def generate_salt(length=16):
    """Generate a random salt for password hashing."""
    return secrets.token_bytes(length)

def bytes_to_base64(data):
    """Convert bytes to base64 string (alias for b64e)."""
    return b64e(data)

def base64_to_bytes(b64_string):
    """Convert base64 string to bytes (alias for b64d)."""
    return b64d(b64_string)

def format_certificate_info(cert_info):
    """Format certificate information for display."""
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
    """Send a message over a socket with length prefix."""
    message_bytes = message.encode('utf-8')
    length = len(message_bytes)
    socket.sendall(length.to_bytes(4, byteorder='big'))
    socket.sendall(message_bytes)

def receive_message(socket):
    """Receive a message from a socket with length prefix."""
    length_bytes = _receive_exact(socket, 4)
    if not length_bytes:
        return None
    length = int.from_bytes(length_bytes, byteorder='big')
    message_bytes = _receive_exact(socket, length)
    if not message_bytes:
        return None
    return message_bytes.decode('utf-8')

def _receive_exact(socket, length):
    """Receive exact number of bytes from socket."""
    data = b''
    while len(data) < length:
        chunk = socket.recv(length - len(data))
        if not chunk:
            return None
        data += chunk
    return data

def validate_email(email):
    """Basic email validation."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_username(username):
    """Validate username (alphanumeric, underscore, 3-20 chars)."""
    pattern = r'^[a-zA-Z0-9_]{3,20}$'
    return re.match(pattern, username) is not None

def validate_password(password):
    """Validate password strength (min 8 chars)."""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    return True, "Password valid"

def clear_screen():
    """Clear console screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner(title):
    """Print a formatted banner."""
    width = 60
    print("\n" + "=" * width)
    print(title.center(width))
    print("=" * width + "\n")

def constant_time_compare(a, b):
    """Constant-time string comparison to prevent timing attacks."""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)
    return result == 0


def create_transcript_path(session_type, username):
    """Create a transcript file path for a given session."""
    transcripts_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'transcripts')
    os.makedirs(transcripts_dir, exist_ok=True)
    session_id = f"{session_type}_{username}"
    return os.path.join(transcripts_dir, f"{session_id}_transcript.json")


class TranscriptLogger:
    """Logs chat messages in append-only transcript format."""
    
    def __init__(self, transcript_path, session_type="client"):
        """Initialize transcript logger.
        
        Args:
            transcript_path: Path to the transcript file
            session_type: Type of session ("client" or "server")
        """
        self.transcript_path = transcript_path
        self.session_type = session_type
        self.transcript = []
        self._load_existing()
    
    def _load_existing(self):
        """Load existing transcript if it exists."""
        if os.path.exists(self.transcript_path):
            try:
                with open(self.transcript_path, 'r') as f:
                    self.transcript = json.load(f)
            except Exception as e:
                print(f"[!] Could not load existing transcript: {e}")
                self.transcript = []
    
    def add_message(self, sender, receiver, message, timestamp=None):
        """Add a message to the transcript."""
        if timestamp is None:
            timestamp = now_ms()
        
        entry = {
            'timestamp': timestamp,
            'sender': sender,
            'receiver': receiver,
            'message': message
        }
        self.transcript.append(entry)
        self._save()
    
    def log_message(self, seqno, timestamp, ciphertext_b64, signature_b64, peer_fingerprint):
        """Log an encrypted message to the transcript with all metadata.
        
        Args:
            seqno: Sequence number
            timestamp: Message timestamp
            ciphertext_b64: Base64-encoded ciphertext
            signature_b64: Base64-encoded signature
            peer_fingerprint: Peer's certificate fingerprint
        """
        entry = {
            'seqno': seqno,
            'timestamp': timestamp,
            'ciphertext': ciphertext_b64,
            'signature': signature_b64,
            'peer_fingerprint': peer_fingerprint
        }
        self.transcript.append(entry)
        self._save()
    
    def close(self):
        """Close the transcript (ensure final save)."""
        self._save()
    
    def _save(self):
        """Save transcript to file."""
        try:
            os.makedirs(os.path.dirname(self.transcript_path), exist_ok=True)
            with open(self.transcript_path, 'w') as f:
                json.dump(self.transcript, f, indent=2)
        except Exception as e:
            print(f"[!] Could not save transcript: {e}")
    
    def get_transcript(self):
        """Get the complete transcript."""
        return self.transcript
    
    def get_hash(self):
        """Get SHA256 hash of transcript for integrity verification."""
        transcript_json = json.dumps(self.transcript, sort_keys=True)
        return sha256_hex(transcript_json.encode('utf-8'))
    
    def compute_transcript_hash(self):
        """Compute transcript hash (alias for get_hash)."""
        return self.get_hash()
    
    def get_message_count(self):
        """Get the number of messages in the transcript."""
        return len(self.transcript)
    
    @property
    def filepath(self):
        """Get the transcript file path."""
        return self.transcript_path

