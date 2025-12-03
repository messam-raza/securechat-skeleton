"""Pydantic models: hello, server_hello, register, login, dh_client, dh_server, msg, receipt.""" 
"""
Protocol Module - Message Formatting and Parsing
Defines the secure chat protocol message structures.
"""

import json
from app.common.utils import b64e, b64d, now_ms


class ProtocolMessage:
    """Handles protocol message creation and parsing."""
    
    # Message types
    TYPE_HELLO = "hello"
    TYPE_SERVER_HELLO = "server_hello"
    TYPE_REGISTER = "register"
    TYPE_LOGIN = "login"
    TYPE_AUTH_RESPONSE = "auth_response"
    TYPE_DH_CLIENT = "dh_client"
    TYPE_DH_SERVER = "dh_server"
    TYPE_MSG = "msg"
    TYPE_RECEIPT = "receipt"
    TYPE_ERROR = "error"
    TYPE_DISCONNECT = "disconnect"
    
    @staticmethod
    def create_hello(client_cert_pem, nonce):
        """
        Create HELLO message.
        
        Args:
            client_cert_pem: Client certificate (PEM string)
            nonce: Random nonce (bytes)
        
        Returns:
            str: JSON message
        """
        return json.dumps({
            "type": ProtocolMessage.TYPE_HELLO,
            "client_cert": client_cert_pem,
            "nonce": b64e(nonce)
        })
    
    @staticmethod
    def create_server_hello(server_cert_pem, nonce):
        """
        Create SERVER_HELLO message.
        
        Args:
            server_cert_pem: Server certificate (PEM string)
            nonce: Random nonce (bytes)
        
        Returns:
            str: JSON message
        """
        return json.dumps({
            "type": ProtocolMessage.TYPE_SERVER_HELLO,
            "server_cert": server_cert_pem,
            "nonce": b64e(nonce)
        })
    
    @staticmethod
    def create_register(email, username, password_hash, salt):
        """
        Create REGISTER message (to be encrypted).
        
        Args:
            email: User email
            username: Username
            password_hash: Base64-encoded salted hash
            salt: Base64-encoded salt
        
        Returns:
            str: JSON message
        """
        return json.dumps({
            "type": ProtocolMessage.TYPE_REGISTER,
            "email": email,
            "username": username,
            "pwd": password_hash,
            "salt": salt
        })
    
    @staticmethod
    def create_login(email, password_hash, nonce):
        """
        Create LOGIN message (to be encrypted).
        
        Args:
            email: User email
            password_hash: Base64-encoded salted hash
            nonce: Random nonce (bytes)
        
        Returns:
            str: JSON message
        """
        return json.dumps({
            "type": ProtocolMessage.TYPE_LOGIN,
            "email": email,
            "pwd": password_hash,
            "nonce": b64e(nonce)
        })
    
    @staticmethod
    def create_auth_response(success, message, username=None):
        """
        Create AUTH_RESPONSE message.
        
        Args:
            success: Boolean indicating success
            message: Response message
            username: Username (if successful)
        
        Returns:
            str: JSON message
        """
        response = {
            "type": ProtocolMessage.TYPE_AUTH_RESPONSE,
            "success": success,
            "message": message
        }
        if username:
            response["username"] = username
        return json.dumps(response)
    
    @staticmethod
    def create_dh_client(g, p, A):
        """
        Create DH_CLIENT message.
        
        Args:
            g: Generator
            p: Prime modulus
            A: Client's public DH value
        
        Returns:
            str: JSON message
        """
        return json.dumps({
            "type": ProtocolMessage.TYPE_DH_CLIENT,
            "g": g,
            "p": p,
            "A": A
        })
    
    @staticmethod
    def create_dh_server(B):
        """
        Create DH_SERVER message.
        
        Args:
            B: Server's public DH value
        
        Returns:
            str: JSON message
        """
        return json.dumps({
            "type": ProtocolMessage.TYPE_DH_SERVER,
            "B": B
        })
    
    @staticmethod
    def create_chat_message(seqno, ciphertext_b64, signature_b64, timestamp=None):
        """
        Create MSG (chat message).
        
        Args:
            seqno: Sequence number
            ciphertext_b64: Base64-encoded ciphertext
            signature_b64: Base64-encoded signature
            timestamp: Unix timestamp in ms (if None, generates new one)
        
        Returns:
            str: JSON message
        """
        if timestamp is None:
            timestamp = now_ms()  # Use the helper function
        
        return json.dumps({
            "type": ProtocolMessage.TYPE_MSG,
            "seqno": seqno,
            "ts": timestamp,
            "ct": ciphertext_b64,
            "sig": signature_b64
        })
    
    @staticmethod
    def create_receipt(peer, first_seq, last_seq, transcript_hash, signature_b64):
        """
        Create RECEIPT (session receipt for non-repudiation).
        
        Args:
            peer: "client" or "server"
            first_seq: First sequence number
            last_seq: Last sequence number
            transcript_hash: Hexadecimal transcript hash
            signature_b64: Base64-encoded signature
        
        Returns:
            str: JSON message
        """
        return json.dumps({
            "type": ProtocolMessage.TYPE_RECEIPT,
            "peer": peer,
            "first_seq": first_seq,
            "last_seq": last_seq,
            "transcript_sha256": transcript_hash,
            "sig": signature_b64
        })
    
    @staticmethod
    def create_error(error_code, message):
        """
        Create ERROR message.
        
        Args:
            error_code: Error code (e.g., "BAD_CERT", "SIG_FAIL", "REPLAY")
            message: Error description
        
        Returns:
            str: JSON message
        """
        return json.dumps({
            "type": ProtocolMessage.TYPE_ERROR,
            "error_code": error_code,
            "message": message
        })
    
    @staticmethod
    def create_disconnect():
        """
        Create DISCONNECT message.
        
        Returns:
            str: JSON message
        """
        return json.dumps({
            "type": ProtocolMessage.TYPE_DISCONNECT
        })
    
    @staticmethod
    def parse(message_json):
        """
        Parse JSON message.
        
        Args:
            message_json: JSON string
        
        Returns:
            dict: Parsed message
        """
        try:
            return json.loads(message_json)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON message: {e}")
    
    @staticmethod
    def encode_bytes(data):
        """Encode bytes to base64 string."""
        return b64e(data)
    
    @staticmethod
    def decode_bytes(b64_string):
        """Decode base64 string to bytes."""
        return b64d(b64_string)