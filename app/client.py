"""Client skeleton — plain TCP; no TLS. See assignment spec."""

#!/usr/bin/env python3
"""
Secure Chat Client
Implements the client-side of the secure chat protocol with full CIANR guarantees.
"""

import socket
import sys
import os
import getpass
import json

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app.crypto.pki import PKIManager
from app.crypto.dh import DHKeyExchange
from app.crypto.aes import AESCipher
from app.crypto.sign import SignatureManager
from app.storage.transcript import TranscriptLogger, create_transcript_path
from app.common.protocol import ProtocolMessage
from app.common.utils import (
    generate_nonce, send_message, receive_message,
    print_banner, validate_email, validate_username, validate_password,
    b64e, b64d, now_ms
)


class SecureChatClient:
    """Secure chat client implementation."""
    
    def __init__(self, server_host='127.0.0.1', server_port=5000):
        """Initialize client."""
        self.server_host = server_host
        self.server_port = server_port
        self.socket = None
        
        # PKI
        self.pki = PKIManager(
            'certs/ca_cert.pem',
            'certs/client_cert.pem',
            'certs/client_private_key.pem'
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
        """Start the client."""
        print_banner("SecureChat Client")
        
        # Connect to server
        print(f"[*] Connecting to server...")
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        try:
            self.socket.connect((self.server_host, self.server_port))
            print(f"[✓] Connected to {self.server_host}:{self.server_port}\n")
            
            # Handle connection
            self.handle_connection()
            
        except ConnectionRefusedError:
            print(f"[✗] Connection refused. Is the server running?")
        except KeyboardInterrupt:
            print("\n[*] Client shutting down...")
        except Exception as e:
            print(f"\n[✗] Error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            self.cleanup()
    
    def handle_connection(self):
        """Handle connection through all protocol phases."""
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
            print(f"[✓] Authenticated as: {self.username}")
            print("\n" + "="*60)
            print("Chat session active. Type your messages (Ctrl+C to exit)")
            print("="*60 + "\n")
            
            # Phase 3: Data Plane - Encrypted chat
            self.handle_chat_session()
            
            # Phase 4: Teardown - Non-repudiation
            self.handle_teardown()
            
        except Exception as e:
            print(f"[✗] Error: {e}")
            import traceback
            traceback.print_exc()
    
    def handle_control_plane(self):
        """Handle certificate exchange and authentication."""
        print("=" * 60)
        print("PHASE 1: Control Plane (Certificate Exchange & Authentication)")
        print("=" * 60)
        
        # Step 1: Send client HELLO
        print("\n[*] Sending client HELLO...")
        client_nonce = generate_nonce()
        hello_msg = ProtocolMessage.create_hello(
            self.pki.get_certificate_pem(),
            client_nonce
        )
        send_message(self.socket, hello_msg)
        print("[✓] Client HELLO sent")
        
        # Step 2: Receive server HELLO
        print("[*] Waiting for server HELLO...")
        msg = receive_message(self.socket)
        if not msg:
            return False
        
        server_hello = ProtocolMessage.parse(msg)
        if server_hello['type'] != ProtocolMessage.TYPE_SERVER_HELLO:
            print("[✗] Expected SERVER_HELLO")
            return False
        
        print("[✓] Received server HELLO")
        
        # Step 3: Verify server certificate
        print("[*] Verifying server certificate...")
        is_valid, peer_cert, error_msg = self.pki.verify_certificate(
            server_hello['server_cert'],
            expected_cn='securechat.server.local'
        )
        
        if not is_valid:
            print(f"[✗] {error_msg}")
            return False
        
        self.peer_cert = peer_cert
        peer_info = self.pki.get_certificate_info(peer_cert)
        print(f"[✓] Server certificate valid")
        print(f"    CN: {peer_info['subject']}")
        print(f"    Fingerprint: {peer_info['fingerprint'][:32]}...")
        
        # Step 4: Temporary DH for authentication phase
        print("\n[*] Performing temporary DH exchange for authentication...")
        if not self.perform_temp_dh():
            return False
        
        # Step 5: Registration or Login
        print("\n" + "="*60)
        print("Choose an option:")
        print("1. Register")
        print("2. Login")
        choice = input("Enter choice (1/2): ").strip()
        
        if choice == '1':
            success, message = self.handle_registration()
        elif choice == '2':
            success, message = self.handle_login()
        else:
            print("[✗] Invalid choice")
            return False
        
        if not success:
            print(f"[✗] Authentication failed: {message}")
            return False
        
        print(f"[✓] {message}")
        return True
    
    def perform_temp_dh(self):
        """Perform temporary DH for authentication phase encryption."""
        # Create initiator DH
        dh = DHKeyExchange.create_initiator()
        params = dh.get_public_parameters()
        
        # Send DH_CLIENT
        dh_msg = ProtocolMessage.create_dh_client(params['g'], params['p'], params['public_key'])
        send_message(self.socket, dh_msg)
        
        print(f"    Sent: g={params['g']}, p_bits={params['p'].bit_length()}, A_bits={params['public_key'].bit_length()}")
        
        # Receive DH_SERVER
        msg = receive_message(self.socket)
        if not msg:
            return False
        
        dh_server_msg = ProtocolMessage.parse(msg)
        if dh_server_msg['type'] != ProtocolMessage.TYPE_DH_SERVER:
            return False
        
        B = dh_server_msg['B']
        print(f"    Received: B_bits={B.bit_length()}")
        
        # Compute shared secret and derive key
        dh.compute_shared_secret(B)
        temp_key = dh.derive_session_key()
        self.temp_cipher = AESCipher(temp_key)
        
        print("[✓] Temporary session key established")
        
        return True
    
    def handle_registration(self):
        """Handle user registration."""
        print("\n" + "="*60)
        print("REGISTRATION")
        print("="*60 + "\n")
        
        # Get user input
        while True:
            email = input("Email: ").strip()
            if validate_email(email):
                break
            print("[✗] Invalid email format")
        
        while True:
            username = input("Username: ").strip()
            if validate_username(username):
                break
            print("[✗] Username must be 3-20 alphanumeric characters")
        
        while True:
            password = getpass.getpass("Password: ")
            is_valid, msg = validate_password(password)
            if is_valid:
                break
            print(f"[✗] {msg}")
        
        # Create registration message with plaintext password
        # (will be encrypted by temp_cipher)
        reg_data = {
            "type": ProtocolMessage.TYPE_REGISTER,
            "email": email,
            "username": username,
            "password": password  # Send plaintext over encrypted channel
        }
        
        reg_json = json.dumps(reg_data)
        
        # Encrypt and send
        print("\n[*] Sending registration request...")
        encrypted_reg = self.temp_cipher.encrypt_to_base64(reg_json)
        send_message(self.socket, encrypted_reg)
        
        # Receive response
        response_json = receive_message(self.socket)
        if not response_json:
            return False, "No response from server"
        
        response = ProtocolMessage.parse(response_json)
        
        if response['success']:
            self.username = username
            return True, response['message']
        else:
            return False, response['message']
    
    def handle_login(self):
        """Handle user login."""
        print("\n" + "="*60)
        print("LOGIN")
        print("="*60 + "\n")
        
        email = input("Email: ").strip()
        password = getpass.getpass("Password: ")
        
        # Create login message with plaintext password
        login_data = {
            "type": ProtocolMessage.TYPE_LOGIN,
            "email": email,
            "password": password  # Send plaintext over encrypted channel
        }
        
        login_json = json.dumps(login_data)
        
        # Encrypt and send
        print("\n[*] Sending login request...")
        encrypted_login = self.temp_cipher.encrypt_to_base64(login_json)
        send_message(self.socket, encrypted_login)
        
        # Receive response
        response_json = receive_message(self.socket)
        if not response_json:
            return False, "No response from server"
        
        response = ProtocolMessage.parse(response_json)
        
        if response['success']:
            self.username = response.get('username', 'User')
            return True, response['message']
        else:
            return False, response['message']
    
    def handle_key_agreement(self):
        """Handle DH key agreement for session."""
        print("\n" + "="*60)
        print("PHASE 2: Key Agreement (Session Key Establishment)")
        print("="*60)
        
        # Create initiator DH
        print("\n[*] Generating DH parameters...")
        dh = DHKeyExchange.create_initiator()
        params = dh.get_public_parameters()
        
        print(f"[✓] DH parameters generated")
        print(f"    g = {params['g']}")
        print(f"    p = {params['p'].bit_length()} bits")
        print(f"    A = {params['public_key'].bit_length()} bits")
        
        # Send DH_CLIENT
        print("[*] Sending DH parameters...")
        dh_msg = ProtocolMessage.create_dh_client(params['g'], params['p'], params['public_key'])
        send_message(self.socket, dh_msg)
        
        # Receive DH_SERVER
        print("[*] Waiting for server DH response...")
        msg = receive_message(self.socket)
        if not msg:
            return False
        
        dh_response = ProtocolMessage.parse(msg)
        if dh_response['type'] != ProtocolMessage.TYPE_DH_SERVER:
            return False
        
        B = dh_response['B']
        print(f"[✓] Received server DH response")
        print(f"    B = {B.bit_length()} bits")
        
        # Compute shared secret and derive session key
        print("[*] Computing shared secret...")
        dh.compute_shared_secret(B)
        self.session_key = dh.derive_session_key()
        self.cipher = AESCipher(self.session_key)
        
        print(f"[✓] Session key established")
        print(f"    Key (hex): {self.session_key.hex()[:32]}...")
        
        # Initialize transcript
        transcript_file = create_transcript_path("client", self.username)
        self.transcript = TranscriptLogger(transcript_file, "client")
        
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
                readable, _, _ = select.select([self.socket, sys.stdin], [], [], 0.1)
                
                for source in readable:
                    if source == self.socket:
                        # Receive message from server
                        if not self.receive_chat_message():
                            return
                    
                    elif source == sys.stdin:
                        # Send message to server
                        message = sys.stdin.readline().strip()
                        if message:
                            if message.lower() == '/quit':
                                print("[*] Ending chat session...")
                                # Send disconnect message
                                disconnect_msg = ProtocolMessage.create_disconnect()
                                send_message(self.socket, disconnect_msg)
                                return
                            self.send_chat_message(message)
            except KeyboardInterrupt:
                print("\n[*] Chat interrupted. Ending session...")
                # Send disconnect message
                try:
                    disconnect_msg = ProtocolMessage.create_disconnect()
                    send_message(self.socket, disconnect_msg)
                except:
                    pass
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
        timestamp = now_ms()
        sig_b64 = SignatureManager.create_message_signature(
            self.seqno_sent,
            timestamp,
            ct_with_iv,
            self.pki.entity_private_key
        )
        
        # Create message
        msg = ProtocolMessage.create_chat_message(self.seqno_sent, ct_b64, sig_b64, timestamp)
        send_message(self.socket, msg)
        
        # Log to transcript
        peer_fingerprint = self.pki.get_certificate_fingerprint(self.peer_cert)
        self.transcript.log_message(
            self.seqno_sent,
            timestamp,
            ct_b64,
            sig_b64,
            peer_fingerprint
        )
        
        print(f"[Client] {plaintext}")
    
    def receive_chat_message(self):
        """Receive and verify encrypted chat message."""
        msg_json = receive_message(self.socket)
        if not msg_json:
            print("\n[*] Server disconnected")
            return False
        
        try:
            msg = ProtocolMessage.parse(msg_json)
            
            if msg['type'] == ProtocolMessage.TYPE_ERROR:
                print(f"\n[✗] Server error: {msg['error_code']} - {msg['message']}")
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
            
            print(f"[Server] {plaintext.decode('utf-8')}")
            
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
                "client",
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
    
    def cleanup(self):
        """Cleanup resources."""
        if self.transcript:
            self.transcript.close()
        
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        
        print("\n[✓] Client stopped")


if __name__ == '__main__':
    client = SecureChatClient()
    client.start()