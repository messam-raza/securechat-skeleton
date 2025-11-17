import time
import base64
import hashlib
from typing import overload

def now_ms() -> int:
    return int(time.time() * 1000)

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()

def b64d(s: str) -> bytes:
    return base64.b64decode(s)

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()