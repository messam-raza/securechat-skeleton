from pydantic import BaseModel, Field
from typing import Literal

class Hello(BaseModel):
    type: Literal["hello"]
    client_cert: str

class ServerHello(BaseModel):
    type: Literal["server hello"]
    server_cert: str

class Register(BaseModel):
    type: Literal["register"]
    iv: str
    ct: str

class Login(BaseModel):
    type: Literal["login"]
    iv: str
    ct: str

class DHClient(BaseModel):
    type: Literal["dh client"]
    p: str
    g: str
    A: str

class DHServer(BaseModel):
    type: Literal["dh server"]
    B: str

class SessionDHServer(BaseModel):
    type: Literal["session dh server"]
    p: str
    g: str
    B: str

class SessionDHClient(BaseModel):
    type: Literal["session dh client"]
    A: str

class ChatMessage(BaseModel):
    type: Literal["chat"]
    seqno: int
    ts: int
    iv: str
    ct: str
    sig: str

class Close(BaseModel):
    type: Literal["close"]

class Receipt(BaseModel):
    type: Literal["receipt"]
    transcript_hash: str
    signature: str

class Error(BaseModel):
    type: Literal["error"]
    msg: str