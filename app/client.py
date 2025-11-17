#!/usr/bin/env python3
"""
SecureChat Client – FULLY WORKING (Register → Login → Chat → Receipt)
All Pydantic models include the required 'type' field explicitly.
"""

import socket, json, os, base64, time, sys
import hashlib
from dotenv import load_dotenv
load_dotenv()

# Crypto
from app.crypto.pki import verify_cert_against_ca, load_pem_cert
from app.crypto.dh import get_group, gen_keypair, compute_shared, derive_key_from_shared
from app.crypto.aes_util import aes_encrypt, aes_decrypt
from app.crypto.sign import load_rsa_private, sign_data, verify_signature

# Common helpers & protocol models
from app.common.utils import now_ms, b64e, b64d, sha256_hex
from app.common.protocol import *

# --------------------------------------------------------------------------- #
# -------------------------------- CONFIG ----------------------------------- #
# --------------------------------------------------------------------------- #

HOST            = os.getenv("SERVER_HOST", "127.0.0.1")
PORT            = int(os.getenv("SERVER_PORT", "9999"))
CA_CERT         = os.getenv("CA_CERT_PATH", "certs/ca.cert.pem")
CLIENT_CERT     = os.getenv("CLIENT_CERT_PATH", "certs/client.cert.pem")
CLIENT_KEY      = os.getenv("CLIENT_KEY_PATH", "certs/client.key.pem")

# --------------------------------------------------------------------------- #
# ------------------------------ JSON I/O ----------------------------------- #
# --------------------------------------------------------------------------- #

def send_json(sock, obj):
    data = json.dumps(
        obj.model_dump() if hasattr(obj, "model_dump") else obj
    ).encode()
    sock.sendall(len(data).to_bytes(4, "big") + data)

def recv_json(sock):
    try:
        length_bytes = sock.recv(4)
        if not length_bytes:
            return None
        length = int.from_bytes(length_bytes, "big")
        data = b""
        while len(data) < length:
            chunk = sock.recv(length - len(data))
            if not chunk:
                break
            data += chunk
        return json.loads(data.decode())
    except Exception:
        return None

# --------------------------------------------------------------------------- #
# ------------------------ CERTIFICATE EXCHANGE ----------------------------- #
# --------------------------------------------------------------------------- #

def exchange_and_verify_certs(sock):
    msg = recv_json(sock)
    if not msg:
        raise RuntimeError("Connection closed before server hello")
    try:
        hello = ServerHello(**msg)
    except Exception as e:
        raise RuntimeError(f"Invalid server hello: {e}")

    server_cert_pem = hello.server_cert.encode()
    ok, err = verify_cert_against_ca(server_cert_pem, CA_CERT, check_san_host=HOST)
    if not ok:
        raise RuntimeError(f"BAD SERVER CERT: {err}")

    with open(CLIENT_CERT, "rb") as f:
        my_cert = f.read()
    send_json(sock, Hello(type="hello", client_cert=my_cert.decode()))
    print("[+] Server certificate validated")
    return server_cert_pem

# --------------------------------------------------------------------------- #
# -------------------------- EPHEMERAL DH (Phase 4) -------------------------- #
# --------------------------------------------------------------------------- #

def perform_dh(sock, server_cert_pem):
    p, g = get_group()
    a, A = gen_keypair(p, g)

    send_json(sock, DHClient(type="dh client", p=str(p), g=str(g), A=str(A)))
    resp = recv_json(sock)
    if not resp:
        raise RuntimeError("Connection closed during DH")
    try:
        dh_srv = DHServer(**resp)
    except Exception:
        raise RuntimeError("Invalid DH server message")

    B = int(dh_srv.B)
    shared = compute_shared(a, B, p)
    base_key = derive_key_from_shared(shared)

    # Bind key to certificate fingerprints
    client_fp = sha256_hex(load_pem_cert(CLIENT_CERT).public_bytes(serialization.Encoding.DER))
    server_fp = sha256_hex(load_pem_cert(server_cert_pem).public_bytes(serialization.Encoding.DER))
    key_material = f"{base_key.hex()}:{client_fp}:{server_fp}".encode()
    aes_key = hashlib.sha256(key_material).digest()[:16]

    print("[+] Ephemeral AES key derived (with cert binding)")
    return aes_key

# --------------------------------------------------------------------------- #
# -------------------------- REGISTRATION / LOGIN --------------------------- #
# --------------------------------------------------------------------------- #

def encrypt_and_send_register(sock, aes_key, email, username, password):
    payload = json.dumps({"email": email, "username": username, "password": password}).encode()
    iv, ct = aes_encrypt(aes_key, payload)
    send_json(sock, Register(type="register", iv=b64e(iv), ct=b64e(ct)))
    resp = recv_json(sock)
    print("[Server]", resp)

def encrypt_and_send_login(sock, aes_key, email, password):
    payload = json.dumps({"email": email, "password": password}).encode()
    iv, ct = aes_encrypt(aes_key, payload)
    send_json(sock, Login(type="login", iv=b64e(iv), ct=b64e(ct)))
    resp = recv_json(sock)
    print("[Server]", resp)
    return resp.get("status") == "ok" if isinstance(resp, dict) else False

# --------------------------------------------------------------------------- #
# -------------------------- SESSION DH (Phase 4) ---------------------------- #
# --------------------------------------------------------------------------- #

def session_dh(sock):
    msg = recv_json(sock)
    if not msg:
        raise RuntimeError("Connection closed before session DH")
    try:
        sess_srv = SessionDHServer(**msg)
    except Exception:
        raise RuntimeError("Invalid session DH server message")

    p, g, B = int(sess_srv.p), int(sess_srv.g), int(sess_srv.B)
    a, A = gen_keypair(p, g)
    send_json(sock, SessionDHClient(type="session dh client", A=str(A)))
    shared = compute_shared(a, B, p)
    session_key = derive_key_from_shared(shared)
    print("[+] Session AES key derived")
    return session_key

# --------------------------------------------------------------------------- #
# -------------------------- CHAT LOOP (Phase 6-7) -------------------------- #
# --------------------------------------------------------------------------- #

def chat_loop(sock, session_key, server_cert_pem):
    seqno = 0
    priv = load_rsa_private(CLIENT_KEY)
    server_pub = load_pem_cert(server_cert_pem.decode()).public_key()

    print("[*] Chat started – type 'exit' to quit")
    while True:
        msg = input("You> ").strip()
        if msg.lower() in ("exit", "quit"):
            send_json(sock, Close(type="close"))
            break

        ts = now_ms()
        payload = json.dumps({"msg": msg}).encode()
        iv, ct = aes_encrypt(session_key, payload)
        data_to_sign = f"{seqno}{ts}{msg}".encode()
        sig = sign_data(priv, data_to_sign)

        send_json(
            sock,
            ChatMessage(
                type="chat",
                seqno=seqno,
                ts=ts,
                iv=b64e(iv),
                ct=b64e(ct),
                sig=b64e(sig)
            )
        )
        seqno += 1

    # Receive receipt
    receipt_msg = recv_json(sock)
    if receipt_msg and receipt_msg.get("type") == "receipt":
        try:
            receipt = Receipt(**receipt_msg)
            transcript_hash = b64d(receipt.transcript_hash)
            sig = b64d(receipt.signature)
            if verify_signature(server_pub, transcript_hash, sig):
                print("[+] Session receipt verified – non-repudiation OK")
            else:
                print("[-] Invalid receipt signature")
        except Exception as e:
            print("[-] Failed to parse receipt:", e)
    else:
        print("[-] No receipt received")

# --------------------------------------------------------------------------- #
# --------------------------------- MAIN ------------------------------------ #
# --------------------------------------------------------------------------- #

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((HOST, PORT))
        print(f"[*] Connected to {HOST}:{PORT}")

        # Phase 2: Cert exchange
        server_cert_pem = exchange_and_verify_certs(s)

        # Phase 4: Ephemeral DH
        temp_key = perform_dh(s, server_cert_pem)

        # Phase 3: Register / Login
        while True:
            print("\nChoose: 1) register  2) login  3) exit")
            choice = input("choice> ").strip()
            if choice == "1":
                email = input("email: ")
                username = input("username: ")
                password = input("password: ")
                encrypt_and_send_register(s, temp_key, email, username, password)
            elif choice == "2":
                email = input("email: ")
                password = input("password: ")
                if encrypt_and_send_login(s, temp_key, email, password):
                    break
            elif choice in ("3", "exit"):
                print("[*] Goodbye")
                return
            else:
                print("Invalid choice")

        # Phase 4: Session DH
        session_key = session_dh(s)

        # Phase 6-7: Chat + Receipt
        chat_loop(s, session_key, server_cert_pem)

    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        s.close()

if __name__ == "__main__":
    main()