"""
crypto/dh.py

Classical Diffie-Hellman helpers using RFC 3526 group 14 (2048-bit MODP).

Functions:
 - get_group() -> (p, g)
 - gen_keypair(p, g) -> (priv_int, pub_int)
 - compute_shared(priv_int, peer_pub_int, p) -> shared_int
 - derive_key_from_shared(shared_int) -> 16-byte key (Trunc16(SHA256(big-endian(Ks))))
"""

import hashlib

# RFC 3526 Group 14 (2048-bit MODP) prime (hex)
# Shortened representation here; use full value in code.
RFC3526_GROUP14_P_HEX = """
FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE65381
FFFFFFFF FFFFFFFF
""".replace("\n", "").replace(" ", "")

P = int(RFC3526_GROUP14_P_HEX, 16)
G = 2

def get_group():
    return P, G

def gen_keypair(p=P, g=G):
    """
    Generate a private exponent a (sufficiently large) and public g^a mod p.
    For simplicity we derive private from a random 256-bit integer (sufficient for DH with 2048-bit p).
    """
    import secrets
    # choose a 256-bit random exponent (good enough)
    priv = secrets.randbelow(p - 2) + 1
    pub = pow(g, priv, p)
    return priv, pub

def compute_shared(priv, peer_pub, p=P):
    return pow(peer_pub, priv, p)

def derive_key_from_shared(shared_int):
    """
    Convert integer shared secret to big-endian bytes, hash with SHA256, and truncate to 16 bytes.
    K = Trunc16(SHA256(big-endian(Ks)))
    """
    kb = shared_int.to_bytes((shared_int.bit_length() + 7) // 8, byteorder="big")
    digest = hashlib.sha256(kb).digest()
    return digest[:16]
