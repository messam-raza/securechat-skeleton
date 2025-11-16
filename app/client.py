# #!/usr/bin/env python3
# """
# app/client.py
# Control-plane client demonstration:
#  - loads client cert and key
#  - connects to server, validates server cert
#  - performs ephemeral DH and derives temporary AES key
#  - sends encrypted 'register' or 'login' messages
# """

# import socket
# import json
# import base64
# import os
# import sys
# from dotenv import load_dotenv
# load_dotenv()

# # FIXED imports
# from app.crypto.pki import verify_cert_against_ca, load_pem_cert, get_cert_fingerprint
# from app.crypto.dh import get_group, gen_keypair, compute_shared, derive_key_from_shared
# from app.crypto.aes_util import aes_encrypt
# import hashlib


# # Config
# HOST = os.getenv("SERVER_HOST", "127.0.0.1")
# PORT = int(os.getenv("SERVER_PORT", "9999"))
# CA_CERT = os.getenv("CA_CERT_PATH", "certs/ca.cert.pem")
# CLIENT_CERT = os.getenv("CLIENT_CERT_PATH", "certs/client.cert.pem")
# CLIENT_KEY = os.getenv("CLIENT_KEY_PATH", "certs/client.key.pem")

# def send_json(sock, obj):
#     data = json.dumps(obj).encode()
#     sock.sendall(len(data).to_bytes(4, "big") + data)

# def recv_json(sock):
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
#     return json.loads(data.decode())

# def exchange_certs_and_validate(sock):
#     # receive server hello
#     msg = recv_json(sock)
#     if not msg or msg.get("type") != "server hello":
#         raise RuntimeError("Protocol error: expected server hello")
#     server_cert_pem = msg.get("server cert").encode()

#     # verify server cert with CA
#     ok, err = verify_cert_against_ca(server_cert_pem, CA_CERT, expected_cn=None, check_san_host="localhost")
#     if not ok:
#         raise RuntimeError("BAD_SERVER_CERT: " + err)
#     print("[+] Server certificate validated OK")

#     # send client hello
#     with open(CLIENT_CERT, "rb") as f:
#         my_cert = f.read()
#     send_json(sock, {"type":"hello", "client cert": my_cert.decode()})
#     return server_cert_pem

# def do_dh_and_get_temp_key(sock):
#     p, g = get_group()
#     a, A = gen_keypair(p, g)
#     send_json(sock, {"type":"dh client", "p": str(p), "g": str(g), "A": str(A)})
#     msg = recv_json(sock)
#     if not msg or msg.get("type") != "dh server":
#         raise RuntimeError("expected dh server")
#     B = int(msg["B"])
#     shared = compute_shared(a, B, p)
#     key = derive_key_from_shared(shared)
#     print("[+] Derived ephemeral AES key (control plane)")
#     return key

# def encrypt_and_send_register(sock, aes_key, email, username, password):
#     payload = json.dumps({"email":email, "username":username, "password":password}).encode()
#     iv, ct = aes_encrypt(aes_key, payload)
#     send_json(sock, {"type":"register", "iv": base64.b64encode(iv).decode(), "ct": base64.b64encode(ct).decode()})
#     resp = recv_json(sock)
#     print("Server response:", resp)

# def encrypt_and_send_login(sock, aes_key, email, password):
#     payload = json.dumps({"email":email, "password":password}).encode()
#     iv, ct = aes_encrypt(aes_key, payload)
#     send_json(sock, {"type":"login", "iv": base64.b64encode(iv).decode(), "ct": base64.b64encode(ct).decode()})
#     resp = recv_json(sock)
#     print("Server response:", resp)

# def interactive_flow():
#     s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     s.connect((HOST, PORT))
#     try:
#         exchange_certs_and_validate(s)
#         temp_key = do_dh_and_get_temp_key(s)

#         while True:
#             print("\nChoose: 1) register  2) login  3) exit")
#             c = input("choice> ").strip()
#             if c == "1":
#                 email = input("email: ").strip()
#                 username = input("username: ").strip()
#                 password = input("password: ").strip()
#                 encrypt_and_send_register(s, temp_key, email, username, password)
#             elif c == "2":
#                 email = input("email: ").strip()
#                 password = input("password: ").strip()
#                 encrypt_and_send_login(s, temp_key, email, password)
#             elif c in ("3", "quit", "exit"):
#                 send_json(s, {"type":"close"})
#                 break
#             else:
#                 print("unknown choice")
#     finally:
#         s.close()


# def do_session_dh(sock):
#     """
#     Phase 4: Perform a second DH exchange to establish session AES key.
#     """
#     # Generate DH parameters
#     p, g = get_group()
#     a, A = gen_keypair(p, g)

#     # Send client session DH value
#     send_json(sock, {"type":"dh session", "p": str(p), "g": str(g), "A": str(A)})

#     # Receive server DH value
#     resp = recv_json(sock)
#     if not resp or resp.get("type") != "dh session":
#         raise RuntimeError("Phase4: Expected 'dh session' from server")

#     B = int(resp["B"])
#     session_shared = compute_shared(a, B, p)
#     session_aes_key = derive_key_from_shared(session_shared)  # 16 bytes AES-128

#     print("[+] Derived session AES key for chat messages")
#     return session_aes_key


# if __name__ == "__main__":
#     if not os.path.exists(CLIENT_CERT) or not os.path.exists(CLIENT_KEY):
#         print("Client certificate/key missing; create certs with scripts/gen_cert.py")
#         sys.exit(1)
#     interactive_flow()



#!/usr/bin/env python3
"""
app/client.py
- Connects to server
- Validates server cert
- Performs control-plane DH
- Sends AES-encrypted register/login messages
"""

import socket, json, base64, os, sys
from dotenv import load_dotenv
load_dotenv()

from app.crypto.pki import verify_cert_against_ca
from app.crypto.dh import get_group, gen_keypair, compute_shared, derive_key_from_shared
from app.crypto.aes_util import aes_encrypt

# ----------------- Config -----------------
HOST = os.getenv("SERVER_HOST", "127.0.0.1")
PORT = int(os.getenv("SERVER_PORT", "9999"))
CA_CERT = os.getenv("CA_CERT_PATH", "certs/ca.cert.pem")
CLIENT_CERT = os.getenv("CLIENT_CERT_PATH", "certs/client.cert.pem")
CLIENT_KEY = os.getenv("CLIENT_KEY_PATH", "certs/client.key.pem")

def send_json(sock,obj):
    data = json.dumps(obj).encode()
    sock.sendall(len(data).to_bytes(4,"big")+data)

def recv_json(sock):
    l = sock.recv(4); ln=int.from_bytes(l,"big"); data=b""
    while len(data)<ln:
        chunk=sock.recv(ln-len(data))
        if not chunk: break
        data+=chunk
    return json.loads(data.decode())

def exchange_certs(sock):
    msg=recv_json(sock)
    if msg.get("type")!="server hello": raise RuntimeError("expected server hello")
    server_cert=msg["server cert"].encode()
    ok, err = verify_cert_against_ca(server_cert, CA_CERT, check_san_host="localhost")
    if not ok: raise RuntimeError("BAD_SERVER_CERT: "+err)
    with open(CLIENT_CERT,"rb") as f: my_cert=f.read()
    send_json(sock, {"type":"hello","client cert":my_cert.decode()})
    print("[+] Server certificate validated OK")
    return server_cert

def do_dh(sock):
    p,g=get_group()
    a,A=gen_keypair(p,g)
    send_json(sock, {"type":"dh client","p":str(p),"g":str(g),"A":str(A)})
    resp=recv_json(sock)
    if resp.get("type")!="dh server": raise RuntimeError("expected dh server")
    B=int(resp["B"]); shared=compute_shared(a,B,p)
    key=derive_key_from_shared(shared)
    print("[+] Derived ephemeral AES key (control plane)")
    return key

def encrypt_and_send_register(sock,aes_key,email,username,password):
    payload=json.dumps({"email":email,"username":username,"password":password}).encode()
    iv,ct=aes_encrypt(aes_key,payload)
    send_json(sock, {"type":"register","iv":base64.b64encode(iv).decode(),"ct":base64.b64encode(ct).decode()})
    resp=recv_json(sock)
    print("Server response:", resp)

def encrypt_and_send_login(sock,aes_key,email,password):
    payload=json.dumps({"email":email,"password":password}).encode()
    iv,ct=aes_encrypt(aes_key,payload)
    send_json(sock, {"type":"login","iv":base64.b64encode(iv).decode(),"ct":base64.b64encode(ct).decode()})
    resp=recv_json(sock)
    print("Server response:", resp)

def interactive_flow():
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect((HOST,PORT))
    try:
        exchange_certs(s)
        temp_key=do_dh(s)
        while True:
            print("\nChoose: 1) register 2) login 3) exit")
            c=input("choice> ").strip()
            if c=="1":
                email=input("email: ").strip()
                username=input("username: ").strip()
                password=input("password: ").strip()
                encrypt_and_send_register(s,temp_key,email,username,password)
            elif c=="2":
                email=input("email: ").strip()
                password=input("password: ").strip()
                encrypt_and_send_login(s,temp_key,email,password)
            elif c in ("3","exit"):
                send_json(s,{"type":"close"}); break
            else: print("unknown choice")
    finally: s.close()

if __name__=="__main__":
    if not os.path.exists(CLIENT_CERT) or not os.path.exists(CLIENT_KEY):
        print("Client certificate/key missing"); sys.exit(1)
    interactive_flow()
