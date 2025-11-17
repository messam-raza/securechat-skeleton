#!/usr/bin/env python3
"""
SecureChat Server – FULLY WORKING (Register → Login → Chat → Receipt)
All Pydantic models include the required 'type' field explicitly.
Ephemeral key binds to certificate fingerprints.
"""

import os, sys, socket, json, base64, hashlib, time
from dotenv import load_dotenv
load_dotenv()

# Crypto
from app.crypto.pki import verify_cert_against_ca, load_pem_cert
from app.crypto.dh import get_group, gen_keypair, compute_shared, derive_key_from_shared
from app.crypto.aes_util import aes_encrypt, aes_decrypt
from app.crypto.sign import sign_data, verify_signature, load_rsa_private
from app.storage.transcript import TranscriptLogger

# DB
import pymysql
import secrets

# Common helpers & protocol models
from app.common.utils import b64e, b64d, sha256_hex
from app.common.protocol import *

# --------------------------------------------------------------------------- #
# -------------------------------- CONFIG ----------------------------------- #
# --------------------------------------------------------------------------- #

HOST            = os.getenv("SERVER_HOST", "127.0.0.1")
PORT            = int(os.getenv("SERVER_PORT", "9999"))
CA_CERT         = os.getenv("CA_CERT_PATH", "certs/ca.cert.pem")
SERVER_CERT     = os.getenv("SERVER_CERT_PATH", "certs/server.cert.pem")
SERVER_KEY      = os.getenv("SERVER_KEY_PATH", "certs/server.key.pem")

DB_HOST         = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT         = int(os.getenv("DB_PORT", "3306"))
DB_USER         = os.getenv("DB_USER", "securechat_user")
DB_PASS         = os.getenv("DB_PASS", "")
DB_NAME         = os.getenv("DB_NAME", "securechat_db")

TRANSCRIPTS_DIR = os.getenv("TRANSCRIPTS_DIR", "transcripts")

# --------------------------------------------------------------------------- #
# ------------------------------- DB HELPERS -------------------------------- #
# --------------------------------------------------------------------------- #

def connect_db():
    return pymysql.connect(
        host=DB_HOST, port=DB_PORT, user=DB_USER,
        password=DB_PASS, db=DB_NAME, autocommit=True,
        cursorclass=pymysql.cursors.Cursor
    )

def user_exists(conn, username, email):
    with conn.cursor() as cur:
        cur.execute("SELECT 1 FROM users WHERE username=%s OR email=%s LIMIT 1", (username, email))
        return cur.fetchone() is not None

def store_user(conn, email, username, salt_bytes, pwd_hash_hex):
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s,%s,%s,%s)",
            (email, username, salt_bytes, pwd_hash_hex)
        )

def fetch_user(conn, email):
    with conn.cursor() as cur:
        cur.execute("SELECT salt, pwd_hash FROM users WHERE email=%s LIMIT 1", (email,))
        return cur.fetchone()

# --------------------------------------------------------------------------- #
# ----------------------------- JSON I/O ------------------------------------ #
# --------------------------------------------------------------------------- #

def send_json(sock, obj):
    data = json.dumps(obj.model_dump() if hasattr(obj, "model_dump") else obj).encode()
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
    # Send server hello with type
    with open(SERVER_CERT, "rb") as f:
        my_cert = f.read()
    send_json(sock, ServerHello(type="server hello", server_cert=my_cert.decode()))

    # Receive client hello
    msg = recv_json(sock)
    if not msg:
        raise RuntimeError("Connection closed before client hello")
    try:
        hello = Hello(**msg)
    except Exception as e:
        raise RuntimeError(f"Invalid client hello: {e}")

    client_cert_pem = hello.client_cert.encode()

    # Verify client cert
    ok, err = verify_cert_against_ca(client_cert_pem, CA_CERT, expected_cn="client")
    if not ok:
        raise RuntimeError(f"BAD CLIENT CERT: {err}")

    print("[+] Client certificate validated")
    return client_cert_pem

# --------------------------------------------------------------------------- #
# -------------------------- EPHEMERAL DH (Phase 4) -------------------------- #
# --------------------------------------------------------------------------- #

def perform_dh(sock, client_cert_pem):
    dh_msg = recv_json(sock)
    if not dh_msg:
        raise RuntimeError("Connection closed during DH")
    try:
        dh_client = DHClient(**dh_msg)
    except Exception as e:
        raise RuntimeError(f"Invalid DH client: {e}")

    p, g, A = int(dh_client.p), int(dh_client.g), int(dh_client.A)
    b, B = gen_keypair(p, g)

    # Send B
    send_json(sock, DHServer(type="dh server", B=str(B)))

    # Compute shared secret
    shared = compute_shared(b, A, p)
    base_key = derive_key_from_shared(shared)

    # Bind to certificate fingerprints
    client_fp = sha256_hex(load_pem_cert(client_cert_pem).public_bytes(serialization.Encoding.DER))
    server_fp = sha256_hex(load_pem_cert(SERVER_CERT).public_bytes(serialization.Encoding.DER))
    key_material = f"{base_key.hex()}:{client_fp}:{server_fp}".encode()
    aes_key = hashlib.sha256(key_material).digest()[:16]

    print("[+] Ephemeral AES key derived (with cert binding)")
    return aes_key

# --------------------------------------------------------------------------- #
# -------------------------- REGISTRATION / LOGIN --------------------------- #
# --------------------------------------------------------------------------- #

def handle_register(sock, aes_key, db_conn):
    msg = recv_json(sock)
    if not msg or msg.get("type") != "register":
        send_json(sock, Error(type="error", msg="expected register"))
        return
    try:
        reg = Register(**msg)
    except:
        send_json(sock, Error(type="error", msg="invalid register"))
        return

    iv = b64d(reg.iv)
    ct = b64d(reg.ct)
    try:
        pt = aes_decrypt(aes_key, iv, ct)
        payload = json.loads(pt.decode())
        email = payload["email"]
        username = payload["username"]
        password = payload["password"]
    except:
        send_json(sock, Error(type="error", msg="decrypt failed"))
        return

    if user_exists(db_conn, username, email):
        send_json(sock, {"status": "error", "msg": "user exists"})
        return

    salt = secrets.token_bytes(16)
    pwd_hash = hashlib.sha256(salt + password.encode()).hexdigest()
    store_user(db_conn, email, username, salt, pwd_hash)
    send_json(sock, {"status": "ok", "msg": "registered"})
    print(f"[+] Registered: {email}")

def handle_login(sock, aes_key, db_conn):
    msg = recv_json(sock)
    if not msg or msg.get("type") != "login":
        send_json(sock, Error(type="error", msg="expected login"))
        return None
    try:
        login = Login(**msg)
    except:
        send_json(sock, Error(type="error", msg="invalid login"))
        return None

    iv = b64d(login.iv)
    ct = b64d(login.ct)
    try:
        pt = aes_decrypt(aes_key, iv, ct)
        payload = json.loads(pt.decode())
        email = payload["email"]
        password = payload["password"]
    except:
        send_json(sock, Error(type="error", msg="decrypt failed"))
        return None

    row = fetch_user(db_conn, email)
    if not row:
        send_json(sock, {"status": "error", "msg": "invalid creds"})
        return None

    salt, stored_hash = row
    computed = hashlib.sha256(salt + password.encode()).hexdigest()
    if computed != stored_hash:
        send_json(sock, {"status": "error", "msg": "invalid creds"})
        return None

    send_json(sock, {"status": "ok", "msg": "logged in"})
    print(f"[+] Login: {email}")
    return email

# --------------------------------------------------------------------------- #
# -------------------------- SESSION DH (Phase 4) ---------------------------- #
# --------------------------------------------------------------------------- #

def session_dh(sock):
    p, g = get_group()
    b, B = gen_keypair(p, g)
    send_json(sock, SessionDHServer(type="session dh server", p=str(p), g=str(g), B=str(B)))

    msg = recv_json(sock)
    if not msg:
        raise RuntimeError("Connection closed during session DH")
    try:
        sess_client = SessionDHClient(**msg)
    except Exception as e:
        raise RuntimeError(f"Invalid session DH client: {e}")

    A = int(sess_client.A)
    shared = compute_shared(b, A, p)
    session_key = derive_key_from_shared(shared)
    print("[+] Session AES key derived")
    return session_key

# --------------------------------------------------------------------------- #
# -------------------------- CHAT HANDLER (Phase 6-7) ----------------------- #
# --------------------------------------------------------------------------- #

def handle_chat(sock, session_key, client_email, client_cert_pem):
    transcript = TranscriptLogger(client_email, TRANSCRIPTS_DIR)
    expected_seq = 0
    client_pub = load_pem_cert(client_cert_pem).public_key()
    server_priv = load_rsa_private(SERVER_KEY)

    print("[*] Chat session started")

    while True:
        msg = recv_json(sock)
        if not msg:
            break

        if msg.get("type") == "chat":
            try:
                chat = ChatMessage(**msg)

                if chat.seqno != expected_seq:
                    send_json(sock, Error(type="error", msg="SEQNO_MISMATCH"))
                    continue

                iv = b64d(chat.iv)
                ct = b64d(chat.ct)
                sig = b64d(chat.sig)

                pt = aes_decrypt(session_key, iv, ct)
                payload = json.loads(pt.decode())
                content = payload["msg"]

                data_to_sign = f"{chat.seqno}{chat.ts}{content}".encode()
                if not verify_signature(client_pub, data_to_sign, sig):
                    send_json(sock, Error(type="error", msg="BAD_SIG"))
                    continue

                if abs(int(time.time() * 1000) - chat.ts) > 5000:
                    send_json(sock, Error(type="error", msg="MSG_EXPIRED"))
                    continue

                transcript.log_message(chat.seqno, chat.ts, content, sig)
                print(f"[{chat.seqno}] {client_email}: {content}")
                expected_seq += 1

            except Exception as e:
                print("[!] Chat error:", e)
                continue

        elif msg.get("type") == "close":
            transcript.finalize()

            with open(transcript.filepath, "rb") as f:
                transcript_bytes = f.read()
            transcript_hash = hashlib.sha256(transcript_bytes).digest()
            signature = sign_data(server_priv, transcript_hash)

            send_json(
                sock,
                Receipt(
                    type="receipt",
                    transcript_hash=b64e(transcript_hash),
                    signature=b64e(signature)
                )
            )
            print("[*] Session closed – receipt sent")
            break

        else:
            send_json(sock, Error(type="error", msg="unknown message type"))

# --------------------------------------------------------------------------- #
# ------------------------------ MAIN SERVER --------------------------------- #
# --------------------------------------------------------------------------- #

def main():
    db_conn = connect_db()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(5)
    print(f"[+] Server listening on {HOST}:{PORT}")

    try:
        while True:
            sock, addr = srv.accept()
            print(f"\n[*] Connection from {addr}")
            try:
                client_cert_pem = exchange_and_verify_certs(sock)
                aes_key = perform_dh(sock, client_cert_pem)

                client_email = None
                while not client_email:
                    msg = recv_json(sock)
                    if not msg:
                        break
                    if msg.get("type") == "register":
                        handle_register(sock, aes_key, db_conn)
                    elif msg.get("type") == "login":
                        client_email = handle_login(sock, aes_key, db_conn)
                    else:
                        send_json(sock, Error(type="error", msg="expected register/login"))

                if not client_email:
                    continue

                session_key = session_dh(sock)
                handle_chat(sock, session_key, client_email, client_cert_pem)

            except Exception as e:
                print("[!] Handler exception:", e)
            finally:
                try:
                    sock.close()
                except:
                    pass

    except KeyboardInterrupt:
        print("\n[!] Shutting down")
    finally:
        srv.close()
        db_conn.close()

if __name__ == "__main__":
    main()