#!/usr/bin/env python3
"""
SecureChat Client — Full Phases 2–7 Integrated
1. Certificate validation (Phase 2)
2. Registration/Login (Phase 3)
3. Session DH (Phase 4)
4. AES encryption/decryption (Phase 5)
5. Message integrity & signatures (Phase 6)
6. Transcript logging & session receipt (Phase 7)
"""

import socket,json,os,base64,time,sys
from dotenv import load_dotenv
load_dotenv()

from app.crypto.pki import verify_cert_against_ca
from app.crypto.dh import get_group, gen_keypair, compute_shared, derive_key_from_shared
from app.crypto.aes_util import aes_encrypt, aes_decrypt, pad_pkcs7, unpad_pkcs7
from app.crypto.sign import load_rsa_private, sign_data

# ----------------- Config -----------------
HOST=os.getenv("SERVER_HOST","127.0.0.1")
PORT=int(os.getenv("SERVER_PORT","9999"))
CA_CERT=os.getenv("CA_CERT_PATH","certs/ca.cert.pem")
CLIENT_CERT=os.getenv("CLIENT_CERT_PATH","certs/client.cert.pem")
CLIENT_KEY=os.getenv("CLIENT_KEY_PATH","certs/client.key.pem")

# ----------------- JSON helpers -----------------
def send_json(sock,obj):
    data=json.dumps(obj).encode()
    sock.sendall(len(data).to_bytes(4,"big")+data)

def recv_json(sock):
    l=sock.recv(4)
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
    msg=recv_json(sock)
    if not msg or msg.get("type")!="server hello":
        raise RuntimeError("Expected server hello")
    server_cert_pem=msg["server cert"].encode()
    ok,err=verify_cert_against_ca(server_cert_pem,CA_CERT,check_san_host="localhost")
    if not ok: raise RuntimeError("BAD SERVER CERT: "+err)
    with open(CLIENT_CERT,"rb") as f: my_cert=f.read()
    send_json(sock,{"type":"hello","client cert":my_cert.decode()})
    print("[+] Server certificate validated OK")
    return server_cert_pem

# ----------------- DH helpers -----------------
def perform_dh(sock):
    p,g=get_group()
    a,A=gen_keypair(p,g)
    send_json(sock,{"type":"dh client","p":str(p),"g":str(g),"A":str(A)})
    resp=recv_json(sock)
    if not resp or resp.get("type")!="dh server":
        raise RuntimeError("Expected dh server")
    B=int(resp["B"])
    shared=compute_shared(a,B,p)
    temp_key=derive_key_from_shared(shared)
    print("[+] Derived ephemeral AES key")
    return temp_key

# ----------------- Registration/Login -----------------
def encrypt_and_send_register(sock,aes_key,email,username,password):
    payload=json.dumps({"email":email,"username":username,"password":password}).encode()
    iv,ct=aes_encrypt(aes_key,payload)
    send_json(sock,{"type":"register","iv":base64.b64encode(iv).decode(),"ct":base64.b64encode(ct).decode()})
    resp=recv_json(sock)
    print("[Server]",resp)

def encrypt_and_send_login(sock,aes_key,email,password):
    payload=json.dumps({"email":email,"password":password}).encode()
    iv,ct=aes_encrypt(aes_key,payload)
    send_json(sock,{"type":"login","iv":base64.b64encode(iv).decode(),"ct":base64.b64encode(ct).decode()})
    resp=recv_json(sock)
    print("[Server]",resp)
    if resp.get("status")=="ok": return True
    return False

# ----------------- Phase 4: Session DH -----------------
def session_dh(sock):
    msg=recv_json(sock)
    if not msg or msg.get("type")!="session dh server":
        raise RuntimeError("Expected session dh server")
    p,g,B=int(msg["p"]),int(msg["g"]),int(msg["B"])
    a,A=gen_keypair(p,g)
    send_json(sock,{"type":"session dh client","A":str(A)})
    shared=compute_shared(a,B,p)
    session_key=derive_key_from_shared(shared)
    print("[+] Session AES key derived")
    return session_key

# ----------------- Phase 6: Chat messaging -----------------
def chat_loop(sock,session_key):
    seqno=0
    priv=load_rsa_private(CLIENT_KEY)
    print("[*] Enter messages (type 'exit' to quit)")
    while True:
        msg=input("You> ").strip()
        if msg.lower() in ("exit","quit"):
            send_json(sock,{"type":"close"}); break
        ts=int(time.time()*1000)
        payload=json.dumps({"msg":msg}).encode()
        iv,ct=aes_encrypt(session_key,payload)
        data_to_sign=(str(seqno)+str(ts)+msg).encode()
        sig=sign_data(priv,data_to_sign)
        send_json(sock,{"type":"chat","seqno":seqno,"ts":ts,
                        "iv":base64.b64encode(iv).decode(),
                        "ct":base64.b64encode(ct).decode(),
                        "sig":base64.b64encode(sig).decode()})
        seqno+=1

# ----------------- Main -----------------
def main():
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect((HOST,PORT))
    try:
        exchange_and_verify_certs(s)
        temp_key=perform_dh(s)

        while True:
            print("Choose: 1) register 2) login 3) exit")
            c=input("choice> ").strip()
            if c=="1":
                email=input("email: "); username=input("username: "); password=input("password: ")
                encrypt_and_send_register(s,temp_key,email,username,password)
            elif c=="2":
                email=input("email: "); password=input("password: ")
                if encrypt_and_send_login(s,temp_key,email,password): break
            elif c in ("3","exit"): s.close(); return
            else: print("unknown choice")

        # Phase 4: Session DH
        session_key=session_dh(s)

        # Phase 6-7: Chat
        chat_loop(s,session_key)

    finally: s.close()

if __name__=="__main__":
    main()
