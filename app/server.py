#!/usr/bin/env python3
"""
SecureChat Server — Full Phases 2–7 Integrated
1. Certificate validation (Phase 2)
2. Registration/Login (Phase 3)
3. Session DH (Phase 4)
4. AES encryption/decryption (Phase 5)
5. Message integrity & signatures (Phase 6)
6. Transcript logging & session receipt (Phase 7)
"""

import os, sys, socket, json, base64, hashlib, time
from dotenv import load_dotenv
load_dotenv()

# Crypto
from app.crypto.pki import verify_cert_against_ca
from app.crypto.dh import get_group, gen_keypair, compute_shared, derive_key_from_shared
from app.crypto.aes_util import aes_encrypt, aes_decrypt, pad_pkcs7, unpad_pkcs7
from app.crypto.sign import sign_data, verify_signature, load_rsa_private, load_rsa_public

# MySQL
import pymysql

# Transcript storage
from app.storage.transcript import TranscriptLogger

# ----------------- Config -----------------
HOST = os.getenv("SERVER_HOST","127.0.0.1")
PORT = int(os.getenv("SERVER_PORT","9999"))
CA_CERT = os.getenv("CA_CERT_PATH","certs/ca.cert.pem")
SERVER_CERT = os.getenv("SERVER_CERT_PATH","certs/server.cert.pem")
SERVER_KEY = os.getenv("SERVER_KEY_PATH","certs/server.key.pem")

DB_HOST = os.getenv("DB_HOST","127.0.0.1")
DB_PORT = int(os.getenv("DB_PORT","3306"))
DB_USER = os.getenv("DB_USER","securechat_user")
DB_PASS = os.getenv("DB_PASS","")
DB_NAME = os.getenv("DB_NAME","securechat_db")

TRANSCRIPTS_DIR = os.getenv("TRANSCRIPTS_DIR","transcripts")

# ----------------- MySQL helpers -----------------
def connect_db():
    try:
        conn = pymysql.connect(host=DB_HOST, port=DB_PORT, user=DB_USER,
                               password=DB_PASS, db=DB_NAME, autocommit=True,
                               cursorclass=pymysql.cursors.Cursor)
        return conn
    except Exception as e:
        print("[!] DB connection failed:", e)
        sys.exit(1)

def user_exists(conn, username, email):
    with conn.cursor() as cur:
        cur.execute("SELECT id FROM users WHERE username=%s OR email=%s LIMIT 1",(username,email))
        return cur.fetchone() is not None

def store_user(conn,email,username,salt_bytes,pwd_hash_hex):
    with conn.cursor() as cur:
        cur.execute("INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s,%s,%s,%s)",
                    (email,username,salt_bytes,pwd_hash_hex))

def fetch_user(conn,email):
    with conn.cursor() as cur:
        cur.execute("SELECT salt, pwd_hash FROM users WHERE email=%s LIMIT 1",(email,))
        return cur.fetchone()

# ----------------- JSON helpers -----------------
def send_json(sock,obj):
    data=json.dumps(obj).encode()
    sock.sendall(len(data).to_bytes(4,"big")+data)

def recv_json(sock):
    l = sock.recv(4)
    if not l: return None
    ln=int.from_bytes(l,"big")
    data=b""
    while len(data)<ln:
        chunk=sock.recv(ln-len(data))
        if not chunk: break
        data+=chunk
    try: return json.loads(data.decode())
    except: return None

# ----------------- Certificate Exchange -----------------
def exchange_and_verify_certs(sock):
    # send server cert
    with open(SERVER_CERT,"rb") as f: my_cert=f.read()
    send_json(sock,{"type":"server hello","server cert":my_cert.decode()})

    msg=recv_json(sock)
    if not msg or msg.get("type")!="hello":
        raise RuntimeError("Expected client hello")
    client_cert_pem = msg.get("client cert").encode()
    ok,err = verify_cert_against_ca(client_cert_pem, CA_CERT, expected_cn="client")
    if not ok: raise RuntimeError("BAD CLIENT CERT: "+err)
    print("[+] Client certificate OK")
    return client_cert_pem

# ----------------- DH helpers -----------------
def perform_dh(sock):
    # Receive client DH, respond with server DH
    dh_msg=recv_json(sock)
    if not dh_msg or dh_msg.get("type")!="dh client":
        send_json(sock,{"type":"error","msg":"expected dh client"}); sock.close(); return None
    p,g,A=int(dh_msg["p"]),int(dh_msg["g"]),int(dh_msg["A"])
    b,B=gen_keypair(p,g)
    send_json(sock,{"type":"dh server","B":str(B)})
    shared=compute_shared(b,A,p)
    key=derive_key_from_shared(shared)
    print("[+] Derived ephemeral AES key")
    return key

# ----------------- AES + Message handlers -----------------
def handle_register(sock,aes_key,msg_obj,db_conn):
    try:
        iv=base64.b64decode(msg_obj["iv"])
        ct=base64.b64decode(msg_obj["ct"])
        pt=aes_decrypt(aes_key,iv,ct)
        payload=json.loads(pt.decode())
        email,pwd,username=payload.get("email"),payload.get("password"),payload.get("username")
    except:
        send_json(sock,{"type":"error","msg":"BAD_PAYLOAD"}); return

    if not email or not username or not pwd:
        send_json(sock,{"type":"error","msg":"BAD_PAYLOAD"}); return

    if user_exists(db_conn,username,email):
        send_json(sock,{"type":"register response","status":"exists"}); return

    salt=os.urandom(16)
    h=hashlib.sha256(); h.update(salt+pwd.encode())
    pwd_hash=h.hexdigest()
    store_user(db_conn,email,username,salt,pwd_hash)
    send_json(sock,{"type":"register response","status":"ok"})

def handle_login(sock,aes_key,msg_obj,db_conn):
    try:
        iv=base64.b64decode(msg_obj["iv"])
        ct=base64.b64decode(msg_obj["ct"])
        pt=aes_decrypt(aes_key,iv,ct)
        payload=json.loads(pt.decode())
        email,pwd=payload.get("email"),payload.get("password")
    except:
        send_json(sock,{"type":"error","msg":"BAD_PAYLOAD"}); return None

    row=fetch_user(db_conn,email)
    if not row:
        send_json(sock,{"type":"login response","status":"no_user"}); return None
    salt_bytes,stored_hash=row[0],row[1]
    h=hashlib.sha256(); h.update(salt_bytes+pwd.encode())
    if h.hexdigest()!=stored_hash:
        send_json(sock,{"type":"login response","status":"bad_credentials"}); return None

    send_json(sock,{"type":"login response","status":"ok"})
    print("[+] User logged in:",email)
    return email

# ----------------- Phase 4: Chat Session Key -----------------
def session_dh(sock):
    p,g=get_group()
    b,B=gen_keypair(p,g)
    send_json(sock,{"type":"session dh server","p":str(p),"g":str(g),"B":str(B)})
    msg=recv_json(sock)
    if not msg or msg.get("type")!="session dh client": raise RuntimeError("Expected session dh client")
    A=int(msg["A"])
    shared=compute_shared(b,A,p)
    session_key=derive_key_from_shared(shared)
    print("[+] Session AES key derived")
    return session_key

# ----------------- Phase 6 & 7: Chat Message Handling -----------------
def handle_chat(sock,session_key,client_email):
    transcript=TranscriptLogger(client_email,TRANSCRIPTS_DIR)
    seqno=0
    print("[*] Chat session started. Waiting for messages...")
    while True:
        msg=recv_json(sock)
        if not msg: break
        if msg.get("type")=="chat":
            try:
                iv=base64.b64decode(msg["iv"])
                ct=base64.b64decode(msg["ct"])
                sig=base64.b64decode(msg["sig"])
                ts=msg.get("ts")
                seq=msg.get("seqno")
                pt=aes_decrypt(session_key,iv,ct)
                payload=json.loads(pt.decode())
                content=payload.get("msg")

                # Verify signature
                client_pub=load_rsa_public("certs/client.cert.pem")
                data_to_verify=(str(seq)+str(ts)+content).encode()
                if not verify_signature(client_pub,data_to_verify,sig):
                    send_json(sock,{"type":"error","msg":"BAD_SIG"}); continue

                # Check timestamp freshness (<5s)
                if abs(int(time.time()*1000)-ts)>5000:
                    send_json(sock,{"type":"error","msg":"MSG_EXPIRED"}); continue

                # Log to transcript
                transcript.log_message(seq,ts,content,sig)

                print(f"[{seq}] {client_email}: {content}")
                seqno+=1
            except Exception as e:
                print("[!] Chat message error:",e)
                continue
        elif msg.get("type")=="close":
            print("[*] Chat session ended")
            send_json(sock,{"type":"bye"})
            transcript.finalize()
            break
        else:
            send_json(sock,{"type":"error","msg":"unknown message type"})

# ----------------- Main server loop -----------------
def main():
    db_conn=connect_db()
    srv=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    srv.bind((HOST,PORT)); srv.listen(5)
    print(f"[+] Server listening on {HOST}:{PORT}")

    try:
        while True:
            sock,addr=srv.accept()
            print("[*] Connection from",addr)
            try:
                exchange_and_verify_certs(sock)
                temp_key=perform_dh(sock)

                # Registration/Login
                while True:
                    msg=recv_json(sock)
                    if not msg: break
                    mtype=msg.get("type")
                    if mtype=="register":
                        handle_register(sock,temp_key,msg,db_conn)
                    elif mtype=="login":
                        client_email=handle_login(sock,temp_key,msg,db_conn)
                        if client_email: break
                    else:
                        send_json(sock,{"type":"error","msg":"expected register/login"})

                # Phase 4: Session DH
                session_key=session_dh(sock)

                # Phase 6-7: Chat session
                handle_chat(sock,session_key,client_email)

                sock.close()
            except Exception as e:
                print("[!] Exception:",e)
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
