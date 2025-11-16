# #!/usr/bin/env python3
# """
# app/server.py

# Control-plane server (registration / login) for SecureChat assignment Phase 2.

# - Exchanges PEM certs with client and verifies them against CA (app.crypto.pki).
# - Performs ephemeral Diffie-Hellman (app.crypto.dh) to derive a temporary AES-128 key.
# - Accepts encrypted JSON messages for "register" and "login" (AES-CBC + PKCS7).
# - Stores users in MySQL: users(email, username UNIQUE, salt VARBINARY(16), pwd_hash CHAR(64)).
# - Use: python3 -m app.server  (from project root)
# """

# import os
# import sys
# import socket
# import json
# import base64
# import hashlib
# from dotenv import load_dotenv

# # load .env from project root
# load_dotenv()

# # import crypto utilities from your repo layout
# # NOTE: your repo has app/crypto/*.py so we import app.crypto.*
# from app.crypto.pki import verify_cert_against_ca, load_pem_cert, get_cert_fingerprint
# from app.crypto.dh import get_group, gen_keypair, compute_shared, derive_key_from_shared
# from app.crypto.aes_util import aes_decrypt

# # MySQL client
# import pymysql

# # -------------------------
# # Configuration (from env)
# # -------------------------
# HOST = os.getenv("SERVER_HOST", "127.0.0.1")
# PORT = int(os.getenv("SERVER_PORT", "9999"))

# CA_CERT = os.getenv("CA_CERT_PATH", "certs/ca.cert.pem")
# SERVER_CERT = os.getenv("SERVER_CERT_PATH", "certs/server.cert.pem")
# SERVER_KEY = os.getenv("SERVER_KEY_PATH", "certs/server.key.pem")

# DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
# DB_PORT = int(os.getenv("DB_PORT", "3306"))
# DB_USER = os.getenv("DB_USER", "securechat_user")
# DB_PASS = os.getenv("DB_PASS", "")
# DB_NAME = os.getenv("DB_NAME", "securechat_db")

# # Debug print to confirm .env loading (safe: masks password partially)
# def _debug_env():
#     masked = (DB_PASS[:2] + "..." + DB_PASS[-1:]) if DB_PASS else "<EMPTY>"
#     print(f"[DEBUG] DB_HOST={DB_HOST} DB_PORT={DB_PORT} DB_USER={DB_USER} DB_PASS={masked} DB_NAME={DB_NAME}")
#     print(f"[DEBUG] CA_CERT={CA_CERT} SERVER_CERT={SERVER_CERT}")

# _debug_env()

# # -------------------------
# # Database helpers
# # -------------------------
# def connect_db():
#     try:
#         conn = pymysql.connect(
#             host=DB_HOST,
#             port=DB_PORT,
#             user=DB_USER,
#             password=DB_PASS,
#             db=DB_NAME,
#             autocommit=True,
#             cursorclass=pymysql.cursors.Cursor,
#         )
#         return conn
#     except Exception as e:
#         print("[!] Failed to connect to MySQL:", e)
#         print("    Please check .env and MySQL user/privileges. Exiting.")
#         sys.exit(1)

# def user_exists(conn, username, email):
#     with conn.cursor() as cur:
#         cur.execute("SELECT id FROM users WHERE username=%s OR email=%s LIMIT 1", (username, email))
#         return cur.fetchone() is not None

# def store_user(conn, email, username, salt_bytes, pwd_hash_hex):
#     with conn.cursor() as cur:
#         cur.execute(
#             "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)",
#             (email, username, salt_bytes, pwd_hash_hex),
#         )

# # -------------------------
# # Networking helpers (length-prefixed JSON)
# # -------------------------
# def send_json(sock, obj):
#     data = json.dumps(obj).encode("utf-8")
#     sock.sendall(len(data).to_bytes(4, "big") + data)

# def recv_json(sock):
#     # read 4 byte length prefix
#     l = sock.recv(4)
#     if not l:
#         return None
#     ln = int.from_bytes(l, "big")
#     data = b""
#     while len(data) < ln:
#         chunk = sock.recv(ln - len(data))
#         if not chunk:
#             break
#         data += chunk
#     try:
#         return json.loads(data.decode("utf-8"))
#     except Exception:
#         return None

# # -------------------------
# # Control plane handlers
# # -------------------------
# def read_pem_send_and_get_peer(sock):
#     """Server sends server cert and receives client's cert (both PEM strings)."""
#     with open(SERVER_CERT, "rb") as f:
#         my_cert = f.read()
#     send_json(sock, {"type": "server hello", "server cert": my_cert.decode("utf-8")})

#     msg = recv_json(sock)
#     if not msg or msg.get("type") != "hello":
#         raise RuntimeError("Protocol error: expected 'hello' from client")
#     peer_pem = msg.get("client cert")
#     if not peer_pem:
#         raise RuntimeError("Protocol error: client did not send certificate")
#     return my_cert, peer_pem.encode("utf-8")

# def handle_register_encrypted(sock, aes_key, msg_obj, db_conn):
#     try:
#         iv = base64.b64decode(msg_obj["iv"])
#         ct = base64.b64decode(msg_obj["ct"])
#         pt = aes_decrypt(aes_key, iv, ct)
#     except Exception as e:
#         send_json(sock, {"type": "error", "msg": "DECRYPT_FAIL"})
#         return

#     try:
#         payload = json.loads(pt.decode("utf-8"))
#         email = payload.get("email")
#         username = payload.get("username")
#         password = payload.get("password")
#     except Exception:
#         send_json(sock, {"type": "error", "msg": "BAD_PAYLOAD"})
#         return

#     if not email or not username or not password:
#         send_json(sock, {"type": "error", "msg": "BAD_PAYLOAD"})
#         return

#     if user_exists(db_conn, username, email):
#         send_json(sock, {"type": "register response", "status": "exists"})
#         return

#     # salt (16 bytes)
#     salt = os.urandom(16)
#     h = hashlib.sha256()
#     h.update(salt + password.encode("utf-8"))
#     pwd_hash = h.hexdigest()

#     store_user(db_conn, email, username, salt, pwd_hash)
#     send_json(sock, {"type": "register response", "status": "ok"})

# def handle_login_encrypted(sock, aes_key, msg_obj, db_conn):
#     try:
#         iv = base64.b64decode(msg_obj["iv"])
#         ct = base64.b64decode(msg_obj["ct"])
#         pt = aes_decrypt(aes_key, iv, ct)
#     except Exception:
#         send_json(sock, {"type": "error", "msg": "DECRYPT_FAIL"})
#         return

#     try:
#         payload = json.loads(pt.decode("utf-8"))
#         email = payload.get("email")
#         password = payload.get("password")
#     except Exception:
#         send_json(sock, {"type": "error", "msg": "BAD_PAYLOAD"})
#         return

#     if not email or not password:
#         send_json(sock, {"type": "error", "msg": "BAD_PAYLOAD"})
#         return

#     with db_conn.cursor() as cur:
#         cur.execute("SELECT salt, pwd_hash FROM users WHERE email=%s LIMIT 1", (email,))
#         row = cur.fetchone()
#     if not row:
#         send_json(sock, {"type": "login response", "status": "no_user"})
#         return
#     salt_bytes, stored_hash = row[0], row[1]
#     h = hashlib.sha256()
#     h.update(salt_bytes + password.encode("utf-8"))
#     if h.hexdigest() == stored_hash:
#         send_json(sock, {"type": "login response", "status": "ok"})
#     else:
#         send_json(sock, {"type": "login response", "status": "bad_credentials"})

# # -------------------------
# # Main server loop
# # -------------------------
# def main():
#     # quick checks
#     if not os.path.exists(SERVER_CERT) or not os.path.exists(SERVER_KEY) or not os.path.exists(CA_CERT):
#         print("[!] Missing certificates in certs/ - run scripts/gen_ca.py and scripts/gen_cert.py")
#         sys.exit(1)

#     # connect to DB (exits with message if fails)
#     db_conn = connect_db()

#     print(f"[+] Starting server on {HOST}:{PORT}")
#     srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#     srv.bind((HOST, PORT))
#     srv.listen(1)

#     try:
#         while True:
#             print("[*] Waiting for connection...")
#             sock, addr = srv.accept()
#             print("[*] Connection from", addr)
#             try:
#                 # 1) cert exchange
#                 mycert_pem, peer_pem = read_pem_send_and_get_peer(sock)

#                 # 2) verify peer cert against CA - check SAN/hostname 'localhost' by default
#                 ok, err = verify_cert_against_ca(peer_pem, CA_CERT, expected_cn=None, check_san_host="localhost")
#                 if not ok:
#                     send_json(sock, {"type": "error", "msg": err})
#                     print("[!] Client presented bad cert:", err)
#                     sock.close()
#                     continue
#                 print("[+] Client certificate verified OK")

#                 # 3) DH handshake - expect client to send dh client JSON
#                 dh_msg = recv_json(sock)
#                 if not dh_msg or dh_msg.get("type") != "dh client":
#                     send_json(sock, {"type": "error", "msg": "expected dh client"})
#                     sock.close()
#                     continue
#                 # p, g, A may be large ints passed as strings
#                 p = int(dh_msg["p"])
#                 g = int(dh_msg["g"])
#                 A = int(dh_msg["A"])

#                 # generate server DH pair and reply with B
#                 b, B = gen_keypair(p, g)
#                 send_json(sock, {"type": "dh server", "B": str(B)})

#                 # derive ephemeral AES key
#                 shared = compute_shared(b, A, p)
#                 temp_key = derive_key_from_shared(shared)  # 16 bytes
#                 print("[+] Derived ephemeral AES key for control-plane")

#                 # 4) process encrypted register/login messages
#                 while True:
#                     msg = recv_json(sock)
#                     if msg is None:
#                         print("[*] Client closed connection")
#                         break
#                     mtype = msg.get("type")
#                     if mtype == "register":
#                         handle_register_encrypted(sock, temp_key, msg, db_conn)
#                     elif mtype == "login":
#                         handle_login_encrypted(sock, temp_key, msg, db_conn)
#                     elif mtype == "close":
#                         send_json(sock, {"type": "bye"})
#                         break
#                     else:
#                         send_json(sock, {"type": "error", "msg": "unknown message type"})
#                 sock.close()
#             except Exception as e:
#                 print("[!] Exception while handling client:", e)
#                 try:
#                     sock.close()
#                 except Exception:
#                     pass
#     except KeyboardInterrupt:
#         print("\n[!] Server shutting down (keyboard interrupt)")
#     finally:
#         srv.close()
#         try:
#             db_conn.close()
#         except Exception:
#             pass

# if __name__ == "__main__":
#     # Running as script or module both supported
#     main()
#!/usr/bin/env python3
#!/usr/bin/env python3
"""
SecureChat Server — Phase 4 Complete
- Control-plane AES key via DH
- Encrypted registration/login
- Session AES key via second DH
- MySQL storage
"""

import os, sys, socket, json, base64, hashlib
from dotenv import load_dotenv
load_dotenv()

from app.crypto.pki import verify_cert_against_ca
from app.crypto.dh import get_group, gen_keypair, compute_shared, derive_key_from_shared





#!/usr/bin/env python3
"""
app/server.py
SecureChat Server — Phases 2/3 (Control-plane AES)
- Exchanges PEM certs with client and validates against CA
- Performs ephemeral DH to derive AES key
- Handles encrypted register/login
- MySQL user storage: salt + SHA256(password)
"""

import os, sys, socket, json, base64, hashlib
from dotenv import load_dotenv
load_dotenv()

# Crypto
from app.crypto.pki import verify_cert_against_ca
from app.crypto.dh import get_group, gen_keypair, compute_shared, derive_key_from_shared
from app.crypto.aes_util import aes_decrypt

# MySQL
import pymysql

# ----------------- Config -----------------
HOST = os.getenv("SERVER_HOST", "127.0.0.1")
PORT = int(os.getenv("SERVER_PORT", "9999"))
CA_CERT = os.getenv("CA_CERT_PATH", "certs/ca.cert.pem")
SERVER_CERT = os.getenv("SERVER_CERT_PATH", "certs/server.cert.pem")
SERVER_KEY = os.getenv("SERVER_KEY_PATH", "certs/server.key.pem")
DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_USER = os.getenv("DB_USER", "securechat_user")
DB_PASS = os.getenv("DB_PASS", "")
DB_NAME = os.getenv("DB_NAME", "securechat_db")

# Debug
masked = (DB_PASS[:2] + "..." + DB_PASS[-1:]) if DB_PASS else "<EMPTY>"
print(f"[DEBUG] DB_USER={DB_USER}, DB_NAME={DB_NAME}, CA_CERT={CA_CERT}, SERVER_CERT={SERVER_CERT}")

# ----------------- Database helpers -----------------
def connect_db():
    try:
        conn = pymysql.connect(
            host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASS,
            db=DB_NAME, autocommit=True, cursorclass=pymysql.cursors.Cursor
        )
        return conn
    except Exception as e:
        print("[!] Failed to connect to MySQL:", e)
        sys.exit(1)

def user_exists(conn, username, email):
    with conn.cursor() as cur:
        cur.execute("SELECT id FROM users WHERE username=%s OR email=%s LIMIT 1", (username, email))
        return cur.fetchone() is not None

def store_user(conn, email, username, salt_bytes, pwd_hash_hex):
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s,%s,%s,%s)",
            (email, username, salt_bytes, pwd_hash_hex)
        )

# ----------------- Networking -----------------
def send_json(sock, obj):
    data = json.dumps(obj).encode("utf-8")
    sock.sendall(len(data).to_bytes(4, "big") + data)

def recv_json(sock):
    l = sock.recv(4)
    if not l: return None
    ln = int.from_bytes(l, "big")
    data = b""
    while len(data) < ln:
        chunk = sock.recv(ln - len(data))
        if not chunk: break
        data += chunk
    try: return json.loads(data.decode("utf-8"))
    except: return None

# ----------------- Cert Exchange -----------------
def read_pem_send_and_get_peer(sock):
    with open(SERVER_CERT, "rb") as f:
        my_cert = f.read()
    send_json(sock, {"type":"server hello", "server cert":my_cert.decode()})
    msg = recv_json(sock)
    if not msg or msg.get("type") != "hello":
        raise RuntimeError("Expected 'hello' from client")
    peer_pem = msg.get("client cert")
    if not peer_pem:
        raise RuntimeError("Client did not send certificate")
    return my_cert, peer_pem.encode("utf-8")

# ----------------- AES handlers -----------------
def handle_register_encrypted(sock, aes_key, msg_obj, db_conn):
    try:
        iv = base64.b64decode(msg_obj["iv"])
        ct = base64.b64decode(msg_obj["ct"])
        pt = aes_decrypt(aes_key, iv, ct)
    except:
        send_json(sock, {"type":"error","msg":"DECRYPT_FAIL"}); return

    try:
        payload = json.loads(pt.decode())
        email, username, password = payload.get("email"), payload.get("username"), payload.get("password")
    except:
        send_json(sock, {"type":"error","msg":"BAD_PAYLOAD"}); return

    if not email or not username or not password:
        send_json(sock, {"type":"error","msg":"BAD_PAYLOAD"}); return

    if user_exists(db_conn, username, email):
        send_json(sock, {"type":"register response","status":"exists"}); return

    salt = os.urandom(16)
    h = hashlib.sha256()
    h.update(salt + password.encode())
    pwd_hash = h.hexdigest()
    store_user(db_conn, email, username, salt, pwd_hash)
    send_json(sock, {"type":"register response","status":"ok"})

def handle_login_encrypted(sock, aes_key, msg_obj, db_conn):
    try:
        iv = base64.b64decode(msg_obj["iv"])
        ct = base64.b64decode(msg_obj["ct"])
        pt = aes_decrypt(aes_key, iv, ct)
    except:
        send_json(sock, {"type":"error","msg":"DECRYPT_FAIL"}); return

    try:
        payload = json.loads(pt.decode())
        email, password = payload.get("email"), payload.get("password")
    except:
        send_json(sock, {"type":"error","msg":"BAD_PAYLOAD"}); return

    if not email or not password:
        send_json(sock, {"type":"error","msg":"BAD_PAYLOAD"}); return

    with db_conn.cursor() as cur:
        cur.execute("SELECT salt, pwd_hash FROM users WHERE email=%s LIMIT 1", (email,))
        row = cur.fetchone()
    if not row:
        send_json(sock, {"type":"login response","status":"no_user"}); return

    salt_bytes, stored_hash = row[0], row[1]
    h = hashlib.sha256()
    h.update(salt_bytes + password.encode())
    if h.hexdigest() == stored_hash:
        send_json(sock, {"type":"login response","status":"ok"})
    else:
        send_json(sock, {"type":"login response","status":"bad_credentials"})

# ----------------- Main -----------------
def main():
    if not os.path.exists(SERVER_CERT) or not os.path.exists(SERVER_KEY) or not os.path.exists(CA_CERT):
        print("[!] Missing certs"); sys.exit(1)
    db_conn = connect_db()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT)); srv.listen(5)
    print(f"[+] Server listening on {HOST}:{PORT}")

    try:
        while True:
            sock, addr = srv.accept()
            print("[*] Connection from", addr)
            try:
                mycert_pem, peer_pem = read_pem_send_and_get_peer(sock)

                # verify client cert
                ok, err = verify_cert_against_ca(peer_pem, CA_CERT, expected_cn="client")
                if not ok:
                    send_json(sock, {"type":"error","msg":"BAD_CLIENT_CERT"})
                    sock.close(); continue
                print("[+] Client cert OK")

                # Control-plane DH
                dh_msg = recv_json(sock)
                if not dh_msg or dh_msg.get("type")!="dh client":
                    send_json(sock, {"type":"error","msg":"expected dh client"}); sock.close(); continue
                p, g, A = int(dh_msg["p"]), int(dh_msg["g"]), int(dh_msg["A"])
                b, B = gen_keypair(p, g)
                send_json(sock, {"type":"dh server","B":str(B)})
                shared = compute_shared(b, A, p)
                temp_key = derive_key_from_shared(shared)
                print("[+] Derived ephemeral AES key")

                # main message loop
                while True:
                    msg = recv_json(sock)
                    if msg is None: break
                    mtype = msg.get("type")
                    if mtype=="register":
                        handle_register_encrypted(sock, temp_key, msg, db_conn)
                    elif mtype=="login":
                        handle_login_encrypted(sock, temp_key, msg, db_conn)
                    elif mtype=="close":
                        send_json(sock, {"type":"bye"}); break
                    else:
                        send_json(sock, {"type":"error","msg":"unknown message type"})
                sock.close()
            except Exception as e:
                print("[!] Exception:", e)
                try: sock.close()
                except: pass
    except KeyboardInterrupt:
        print("\n[!] Server shutting down")
    finally:
        srv.close()
        try: db_conn.close()
        except: pass

if __name__=="__main__":
    main()
