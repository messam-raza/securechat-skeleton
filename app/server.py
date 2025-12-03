"""Server skeleton — plain TCP; no TLS. See assignment spec."""

"""
Secure Chat Server
Implements the server-side of the secure chat protocol with full CIANR guarantees.
"""

import socket
import sys
import os
import json

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app.crypto.pki import PKIManager
from app.crypto.dh import DHKeyExchange
from app.crypto.aes import AESCipher
from app.crypto.sign import SignatureManager
from app.storage.db import DatabaseManager
from app.storage.transcript import TranscriptLogger, create_transcript_path
from app.common.protocol import ProtocolMessage
from app.common.utils import (
    generate_nonce, send_message, receive_message,
    print_banner, b64e, b64d
)


class SecureChatServer:
    """Secure chat server implementation."""
    
    def __init__(self, host='127.0.0.1', port=5000):
        """Initialize server."""
        self.host = host
        self.port = port
        self.socket = None
        self.client_socket = None
        
        # PKI
        self.pki = PKIManager(
            'certs/ca_cert.pem',
            'certs/server_cert.pem',
            'certs/server_private_key.pem'
        )
        
        # Database
        self.db = DatabaseManager(
            host=os.getenv('DB_HOST', 'localhost'),
            port=int(os.getenv('DB_PORT', 3306)),
            database=os.getenv('DB_NAME', 'securechat_db'),
            user=os.getenv('DB_USER', 'root'),
            password=os.getenv('DB_PASSWORD', '')
        )
        
        # Session state
        self.peer_cert = None
        self.session_key = None
        self.cipher = None
        self.username = None
        self.seqno_sent = 0
        self.seqno_received = 0
        self.transcript = None
    
    def start(self):
        """Start the server."""
        print_banner("SecureChat Server")
        
        # Connect to database
        if not self.db.connect():
            print("[✗] Failed to connect to database")
            return
        
        # Create socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        self.socket.listen(1)
        
        print(f"[*] Server listening on {self.host}:{self.port}")
        print("[*] Waiting for client connection...")
        
        try:
            self.client_socket, client_address = self.socket.accept()
            print(f"\n[✓] Client connected from {client_address}")
            
            # Handle client connection
            self.handle_client()
            
        except KeyboardInterrupt:
            print("\n[*] Server shutting down...")
        except Exception as e:
            print(f"\n[✗] Error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            self.cleanup()
    
    def handle_client(self):
        """Handle client connection through all protocol phases."""
        try:
            # Phase 1: Control Plane - Certificate Exchange & Authentication
            if not self.handle_control_plane():
                print("[✗] Control plane failed")
                return
            
            # Phase 2: Key Agreement - Establish session key
            if not self.handle_key_agreement():
                print("[✗] Key agreement failed")
                return
            
            print("\n[✓] Secure channel established!")
            print(f"[✓] Authenticated user: {self.username}")
            print("\n" + "="*60)
            print("Chat session active. Type your messages (Ctrl+C to exit)")
            print("="*60 + "\n")
            
            # Phase 3: Data Plane - Encrypted chat
            self.handle_chat_session()
            
            # Phase 4: Teardown - Non-repudiation
            self.handle_teardown()
            
        except Exception as e:
            print(f"[✗] Error handling client: {e}")
            import traceback
            traceback.print_exc()
    
    def handle_control_plane(self):
        """Handle certificate exchange and authentication."""
        print("\n" + "="*60)
        print("PHASE 1: Control Plane (Certificate Exchange & Authentication)")
        print("="*60)
        
        # Step 1: Receive client HELLO
        print("\n[*] Waiting for client HELLO...")
        msg = receive_message(self.client_socket)
        if not msg:
            return False
        
        hello_msg = ProtocolMessage.parse(msg)
        if hello_msg['type'] != ProtocolMessage.TYPE_HELLO:
            self.send_error("PROTOCOL_ERROR", "Expected HELLO message")
            return False
        
        print("[✓] Received client HELLO")
        
        # Step 2: Verify client certificate
        print("[*] Verifying client certificate...")
        is_valid, peer_cert, error_msg = self.pki.verify_certificate(
            hello_msg['client_cert'],
            expected_cn='securechat.client.local'
        )
        
        if not is_valid:
            print(f"[✗] {error_msg}")
            self.send_error("BAD_CERT", error_msg)
            return False
        
        self.peer_cert = peer_cert
        peer_info = self.pki.get_certificate_info(peer_cert)
        print(f"[✓] Client certificate valid")
        print(f"    CN: {peer_info['subject']}")
        print(f"    Fingerprint: {peer_info['fingerprint'][:32]}...")
        
        # Step 3: Send server HELLO
        print("[*] Sending server HELLO...")
        server_nonce = generate_nonce()
        server_hello = ProtocolMessage.create_server_hello(
            self.pki.get_certificate_pem(),
            server_nonce
        )
        send_message(self.client_socket, server_hello)
        print("[✓] Server HELLO sent")
        
        # Step 4: Temporary DH for authentication phase
        print("\n[*] Performing temporary DH exchange for authentication...")
        if not self.perform_temp_dh():
            return False
        
        # Step 5: Handle registration or login
        print("\n[*] Waiting for authentication request...")
        auth_msg_encrypted = receive_message(self.client_socket)
        if not auth_msg_encrypted:
            return False
        
        # Decrypt authentication message
        try:
            auth_msg_json = self.temp_cipher.decrypt_from_base64(auth_msg_encrypted)
            auth_msg = ProtocolMessage.parse(auth_msg_json.decode('utf-8'))
        except Exception as e:
            print(f"[✗] Failed to decrypt auth message: {e}")
            return False
        
        # Handle registration or login
        if auth_msg['type'] == ProtocolMessage.TYPE_REGISTER:
            success, message = self.handle_registration(auth_msg)
        elif auth_msg['type'] == ProtocolMessage.TYPE_LOGIN:
            success, message = self.handle_login(auth_msg)
        else:
            success = False
            message = "Unknown authentication type"
        
        # Send authentication response
        response = ProtocolMessage.create_auth_response(success, message, self.username)
        send_message(self.client_socket, response)
        
        if not success:
            print(f"[✗] Authentication failed: {message}")
            return False
        
        print(f"[✓] Authentication successful: {self.username}")
        return True
    
    def perform_temp_dh(self):
        """Perform temporary DH for authentication phase encryption."""
        # Receive DH_CLIENT
        msg = receive_message(self.client_socket)
        if not msg:
            return False
        
        dh_client_msg = ProtocolMessage.parse(msg)
        if dh_client_msg['type'] != ProtocolMessage.TYPE_DH_CLIENT:
            return False
        
        # Extract parameters
        g = dh_client_msg['g']
        p = dh_client_msg['p']
        A = dh_client_msg['A']
        
        print(f"    Received: g={g}, p_bits={p.bit_length()}, A_bits={A.bit_length()}")
        
        # Create responder DH
        dh = DHKeyExchange.create_responder(p, g)
        B = dh.public_key
        
        # Compute shared secret and derive key
        dh.compute_shared_secret(A)
        temp_key = dh.derive_session_key()
        self.temp_cipher = AESCipher(temp_key)
        
        # Send DH_SERVER
        dh_server_msg = ProtocolMessage.create_dh_server(B)
        send_message(self.client_socket, dh_server_msg)
        
        print(f"    Sent: B_bits={B.bit_length()}")
        print("[✓] Temporary session key established")
        
        return True
    
    def handle_registration(self, reg_msg):
        """Handle user registration."""
        print("\n[*] Processing registration request...")
        
        email = reg_msg['email']
        username = reg_msg['username']
        password = reg_msg['password']  # Plaintext over encrypted channel
        
        print(f"    Email: {email}")
        print(f"    Username: {username}")
        
        # Register user (database will hash the password)
        success, message = self.db.register_user(email, username, password)
        
        if success:
            self.username = username
        
        return success, message
    
    def handle_login(self, login_msg):
        """Handle user login."""
        print("\n[*] Processing login request...")
        
        email = login_msg['email']
        password = login_msg['password']  # Plaintext over encrypted channel
        
        print(f"    Email: {email}")
        
        # Authenticate user
        success, username_or_msg = self.db.authenticate_user(email, password)
        
        if success:
            self.username = username_or_msg
            return True, "Login successful"
        else:
            return False, username_or_msg
    
    def handle_key_agreement(self):
        """Handle DH key agreement for session."""
        print("\n" + "="*60)
        print("PHASE 2: Key Agreement (Session Key Establishment)")
        print("="*60)
        
        # Receive DH_CLIENT for session
        print("\n[*] Waiting for DH parameters...")
        msg = receive_message(self.client_socket)
        if not msg:
            return False
        
        dh_msg = ProtocolMessage.parse(msg)
        if dh_msg['type'] != ProtocolMessage.TYPE_DH_CLIENT:
            return False
        
        g = dh_msg['g']
        p = dh_msg['p']
        A = dh_msg['A']
        
        print(f"[✓] Received DH parameters")
        print(f"    g = {g}")
        print(f"    p = {p.bit_length()} bits")
        print(f"    A = {A.bit_length()} bits")
        
        # Create responder
        print("[*] Computing server DH values...")
        dh = DHKeyExchange.create_responder(p, g)
        B = dh.public_key
        
        # Compute shared secret
        dh.compute_shared_secret(A)
        self.session_key = dh.derive_session_key()
        self.cipher = AESCipher(self.session_key)
        
        # Send response
        print("[*] Sending DH response...")
        dh_response = ProtocolMessage.create_dh_server(B)
        send_message(self.client_socket, dh_response)
        
        print(f"[✓] Session key established")
        print(f"    Key (hex): {self.session_key.hex()[:32]}...")
        
        # Initialize transcript
        transcript_file = create_transcript_path("server", self.username)
        self.transcript = TranscriptLogger(transcript_file, "server")
        
        return True
    
    def handle_chat_session(self):
        """Handle encrypted chat session."""
        print("\n" + "="*60)
        print("PHASE 3: Data Plane (Encrypted Chat)")
        print("="*60 + "\n")
        
        import select
        
        while True:
            try:
                # Use select to check both socket and stdin
                readable, _, _ = select.select([self.client_socket, sys.stdin], [], [], 0.1)
                
                for source in readable:
                    if source == self.client_socket:
                        # Receive message from client
                        if not self.receive_chat_message():
                            return
                    
                    elif source == sys.stdin:
                        # Send message to client
                        message = sys.stdin.readline().strip()
                        if message:
                            if message.lower() == '/quit':
                                print("[*] Ending chat session...")
                                return
                            self.send_chat_message(message)
            except KeyboardInterrupt:
                print("\n[*] Chat interrupted. Ending session...")
                return
    
    def send_chat_message(self, plaintext):
        """Send encrypted and signed chat message."""
        # Increment sequence number
        self.seqno_sent += 1
        
        # Encrypt message
        iv, ciphertext = self.cipher.encrypt(plaintext)
        ct_with_iv = iv + ciphertext
        ct_b64 = b64e(ct_with_iv)
        
        # Create signature
        from app.common.utils import now_ms
        timestamp = now_ms()
        sig_b64 = SignatureManager.create_message_signature(
            self.seqno_sent,
            timestamp,
            ct_with_iv,
            self.pki.entity_private_key
        )
        
        # Create message
        msg = ProtocolMessage.create_chat_message(self.seqno_sent, ct_b64, sig_b64, timestamp)
        send_message(self.client_socket, msg)
        
        # Log to transcript
        peer_fingerprint = self.pki.get_certificate_fingerprint(self.peer_cert)
        self.transcript.log_message(
            self.seqno_sent,
            timestamp,
            ct_b64,
            sig_b64,
            peer_fingerprint
        )
        
        print(f"[Server] {plaintext}")
    
    def receive_chat_message(self):
        """Receive and verify encrypted chat message."""
        msg_json = receive_message(self.client_socket)
        if not msg_json:
            return False
        
        try:
            msg = ProtocolMessage.parse(msg_json)
            
            if msg['type'] == ProtocolMessage.TYPE_DISCONNECT:
                print("\n[*] Client disconnected")
                return False
            
            if msg['type'] != ProtocolMessage.TYPE_MSG:
                return True
            
            seqno = msg['seqno']
            timestamp = msg['ts']
            ct_b64 = msg['ct']
            sig_b64 = msg['sig']
            
            # Check sequence number (replay protection)
            if seqno <= self.seqno_received:
                print(f"[✗] REPLAY: Received seqno {seqno}, expected > {self.seqno_received}")
                self.send_error("REPLAY", "Message replay detected")
                return False
            
            # Verify signature
            ct_with_iv = b64d(ct_b64)
            if not SignatureManager.verify_message_signature(
                seqno,
                timestamp,
                ct_with_iv,
                sig_b64,
                self.peer_cert.public_key()
            ):
                print(f"[✗] SIG_FAIL: Signature verification failed")
                self.send_error("SIG_FAIL", "Signature verification failed")
                return False
            
            # Decrypt message
            iv = ct_with_iv[:16]
            ciphertext = ct_with_iv[16:]
            plaintext = self.cipher.decrypt(iv, ciphertext)
            
            # Update sequence number
            self.seqno_received = seqno
            
            # Log to transcript
            peer_fingerprint = self.pki.get_certificate_fingerprint(self.peer_cert)
            self.transcript.log_message(
                seqno,
                timestamp,
                ct_b64,
                sig_b64,
                peer_fingerprint
            )
            
            print(f"[Client] {plaintext.decode('utf-8')}")
            
            return True
            
        except Exception as e:
            print(f"[✗] Error processing message: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def handle_teardown(self):
        """Handle session teardown and generate receipt."""
        print("\n" + "="*60)
        print("PHASE 4: Teardown (Non-Repudiation)")
        print("="*60 + "\n")
        
        if self.transcript:
            # Compute transcript hash
            transcript_hash = self.transcript.compute_transcript_hash()
            
            print(f"[*] Session transcript: {self.transcript.get_message_count()} messages")
            print(f"[*] Transcript hash: {transcript_hash[:32]}...")
            
            # Sign transcript hash
            sig = SignatureManager.sign_digest(
                bytes.fromhex(transcript_hash),
                self.pki.entity_private_key
            )
            sig_b64 = SignatureManager.encode_signature(sig)
            
            # Create receipt
            receipt = ProtocolMessage.create_receipt(
                "server",
                1,
                max(self.seqno_sent, self.seqno_received),
                transcript_hash,
                sig_b64
            )
            
            # Save receipt
            receipt_file = self.transcript.filepath.replace('.txt', '_receipt.json')
            with open(receipt_file, 'w') as f:
                f.write(receipt)
            
            print(f"[✓] Session receipt saved: {receipt_file}")
            
            self.transcript.close()
    
    def send_error(self, error_code, message):
        """Send error message to client."""
        error_msg = ProtocolMessage.create_error(error_code, message)
        send_message(self.client_socket, error_msg)
    
    def cleanup(self):
        """Cleanup resources."""
        if self.transcript:
            self.transcript.close()
        
        if self.client_socket:
            try:
                self.client_socket.close()
            except:
                pass
        
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        
        if self.db:
            self.db.disconnect()
        
        print("\n[✓] Server stopped")


if __name__ == '__main__':
    server = SecureChatServer()
    server.start()