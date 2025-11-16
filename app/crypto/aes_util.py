"""
crypto/aes_util.py

AES-128 CBC encrypt/decrypt with PKCS#7 padding.
Uses cryptography.hazmat primitives.

Functions:
 - pad_pkcs7(data, block_size=16)
 - unpad_pkcs7(padded)
 - aes_encrypt(key16, plaintext) -> iv + ciphertext (both bytes)
 - aes_decrypt(key16, iv, ciphertext) -> plaintext bytes
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
import os

BLOCK_SIZE = 16

def pad_pkcs7(data: bytes) -> bytes:
    padder = sym_padding.PKCS7(BLOCK_SIZE * 8).padder()
    return padder.update(data) + padder.finalize()

def unpad_pkcs7(padded: bytes) -> bytes:
    unpadder = sym_padding.PKCS7(BLOCK_SIZE * 8).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

def aes_encrypt(key: bytes, plaintext: bytes):
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes for AES-128")
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    pt_padded = pad_pkcs7(plaintext)
    ct = encryptor.update(pt_padded) + encryptor.finalize()
    return iv, ct

def aes_decrypt(key: bytes, iv: bytes, ciphertext: bytes):
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes for AES-128")
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    return unpad_pkcs7(padded)
