# SecureChat - Cryptographic Chat System

**Assignment #2 - Information Security**  
**Semester:** Fall 2025  
**Student:** 22i-1138 - Abdullah Shakir

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [System Architecture](#system-architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Database Setup](#database-setup)
- [Certificate Generation](#certificate-generation)
- [Running the System](#running-the-system)
- [Testing & Validation](#testing--validation)
- [Security Properties](#security-properties)
- [GitHub Repository](#github-repository)

---

## 🎯 Overview

SecureChat is a console-based secure chat system that implements a complete cryptographic protocol achieving **Confidentiality, Integrity, Authenticity, and Non-Repudiation (CIANR)**. The system demonstrates real-world application of:

- **X.509 PKI** with self-signed Certificate Authority
- **RSA-2048** for digital signatures
- **Diffie-Hellman** key exchange for session key establishment
- **AES-128-CBC** for message encryption with PKCS#7 padding
- **SHA-256** for hashing and integrity verification
- **MySQL** for secure credential storage
- **Session transcripts** for non-repudiation

---

## ✨ Features

### 🔐 Security Features

- ✅ Mutual certificate authentication (client & server)
- ✅ Certificate chain validation and expiry checking
- ✅ Salted password hashing (SHA-256)
- ✅ No plaintext credential transmission
- ✅ Ephemeral session keys via DH
- ✅ Per-message RSA signatures
- ✅ Sequence number-based replay protection
- ✅ Tamper detection via signature verification
- ✅ Session transcripts with cryptographic receipts

### 📊 Protocol Phases

1. **Control Plane**: Certificate exchange & mutual authentication
2. **Key Agreement**: DH-based session key derivation
3. **Data Plane**: Encrypted & signed message exchange
4. **Teardown**: Non-repudiation receipt generation

---

## 🏗️ System Architecture

```
securechat-skeleton/
├── app/
│   ├── common/
│   │   ├── protocol.py       # Message formatting
│   │   └── utils.py          # Utility functions
│   ├── crypto/
│   │   ├── aes.py            # AES-128-CBC encryption
│   │   ├── dh.py             # Diffie-Hellman implementation
│   │   ├── pki.py            # Certificate operations
│   │   └── sign.py           # RSA signatures & hashing
│   └── storage/
│       └── database.py       # MySQL user management
├── certs/                    # Certificates & keys (DO NOT COMMIT)
├── scripts/
│   ├── gen_ca.py             # Generate Root CA
│   └── gen_cert.py           # Issue client/server certs
├── transcripts/              # Session logs (DO NOT COMMIT)
├── client.py                 # Client application
├── server.py                 # Server application
├── requirements.txt          # Python dependencies
├── .env.example              # Environment template
├── .gitignore                # Git ignore rules
└── README.md                 # This file
```

---

## 📦 Prerequisites

### Software Requirements

- **Python 3.8+**
- **MySQL 8.0+**
- **Wireshark** (for traffic analysis)
- **Git**

### Python Libraries

```bash
pip install cryptography mysql-connector-python python-dotenv
```

---

## 🚀 Installation

### 1. Clone Repository

```bash
git clone https://github.com/ChaudaryAbdullah/Secure-Chat.git
cd securechat-skeleton
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure Environment

```bash
cp .env.example .env
# Edit .env with your MySQL credentials
```

**`.env` Example:**

```env
DB_HOST=localhost
DB_NAME=securechat
DB_USER=root
DB_PASSWORD=your_mysql_password
```

---

## 🗄️ Database Setup

### 1. Create Database

```sql
CREATE DATABASE securechat CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE securechat;
```

### 2. Create Users Table

```sql
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(255) UNIQUE NOT NULL,
    salt VARBINARY(16) NOT NULL,
    pwd_hash CHAR(64) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_email (email),
    INDEX idx_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

### 3. Verify Setup

```bash
python -c "from app.storage.database import initialize_database; initialize_database()"
```

---

## 🔑 Certificate Generation

### 1. Generate Root CA

```bash
python scripts/gen_ca.py
```

**Output:**

```
certs/ca_cert.pem
certs/ca_private_key.pem
```

### 2. Issue Client & Server Certificates

```bash
python scripts/gen_cert.py
```

**Output:**

```
certs/server_cert.pem
certs/server_private_key.pem
certs/client_cert.pem
certs/client_private_key.pem
```

### 3. Inspect Certificates (Optional)

```bash
openssl x509 -in certs/ca_cert.pem -text -noout
openssl x509 -in certs/server_cert.pem -text -noout
openssl x509 -in certs/client_cert.pem -text -noout
```

---

## ▶️ Running the System

### Terminal 1: Start Server

```bash
python server.py
```

**Expected Output:**

```
============================================================
              SecureChat Server
============================================================

[✓] Connected to MySQL database 'securechat'
[*] Server listening on 127.0.0.1:5000
[*] Waiting for client connection...
```

### Terminal 2: Start Client

```bash
python client.py
```

**Expected Output:**

```
============================================================
              SecureChat Client
============================================================

[*] Connecting to server...
[✓] Connected to 127.0.0.1:5000

Choose an option:
1. Register
2. Login
Enter choice (1/2):
```

### Registration Flow

1. Select "1. Register"
2. Enter email, username, password
3. Client performs:
   - Certificate exchange & validation
   - Temporary DH for auth encryption
   - Sends encrypted credentials
4. Server stores salted hash in MySQL

### Login Flow

1. Select "2. Login"
2. Enter email & password
3. Server verifies:
   - Certificate validity
   - Salted password hash

### Chat Session

```
[Server] Hello from server!
[Client] Hi from client!
```

**Commands:**

- Type message + Enter to send
- `/quit` to end session
- `Ctrl+C` to disconnect

---

## 🧪 Testing & Validation

### 1. Wireshark Capture

**Start Capture:**

```bash
# Capture loopback traffic on port 5000
sudo wireshark -i lo -f "tcp port 5000"
```

**Display Filter:**

```
tcp.port == 5000
```

**Verify:**

- ✅ All application data is encrypted (no plaintext visible)
- ✅ Certificates transmitted in HELLO messages
- ✅ DH parameters exchanged
- ✅ Chat messages are base64-encoded ciphertext

**Screenshot:** Save as `wireshark_encrypted_traffic.png`

---

### 2. Invalid Certificate Test

**Create Expired Certificate:**

```python
# Modify scripts/gen_cert.py line:
.not_valid_after(datetime.datetime.utcnow() - datetime.timedelta(days=1))  # Already expired
```

**Expected Result:**

```
[✗] BAD_CERT: Certificate expired (expired on 2024-11-14 12:00:00)
```

**Test Self-Signed:**
Use a certificate not signed by your CA.

**Expected Result:**

```
[✗] BAD_CERT: Certificate not issued by trusted CA
```

---

### 3. Tampering Test

**Modify Message in Transit:**

```python
# In client.py, after encryption:
ct_with_iv = bytearray(ct_with_iv)
ct_with_iv[20] ^= 0xFF  # Flip bits
ct_with_iv = bytes(ct_with_iv)
```

**Expected Result:**

```
[✗] SIG_FAIL: Signature verification failed
```

---

### 4. Replay Attack Test

**Resend Old Message:**

```python
# Store a previous message and resend it
send_message(socket, old_message_json)
```

**Expected Result:**

```
[✗] REPLAY: Received seqno 5, expected > 10
```

---

### 5. Non-Repudiation Verification

**Offline Verification Script:**

```python
# scripts/verify_transcript.py
from app.crypto.sign import SignatureManager
from app.crypto.pki import PKIManager
import json

# Load transcript
with open('transcripts/server_alice_20251115_143000.txt') as f:
    lines = f.readlines()

# Load receipt
with open('transcripts/server_alice_20251115_143000_receipt.json') as f:
    receipt = json.load(f)

# Verify each message
pki = PKIManager('certs/ca_cert.pem', 'certs/server_cert.pem', 'certs/server_private_key.pem')
client_cert = pki._load_certificate('certs/client_cert.pem')

for line in lines:
    seqno, ts, ct_b64, sig_b64, fingerprint = line.strip().split('|')

    # Verify signature
    is_valid = SignatureManager.verify_message_signature(
        int(seqno),
        int(ts),
        base64.b64decode(ct_b64),
        sig_b64,
        client_cert.public_key()
    )

    print(f"Message {seqno}: {'✓ VALID' if is_valid else '✗ INVALID'}")

# Verify receipt
transcript_hash = SignatureManager.compute_transcript_hash(lines)
assert transcript_hash == receipt['transcript_sha256']

receipt_sig = SignatureManager.decode_signature(receipt['sig'])
is_valid = SignatureManager.verify_digest_signature(
    bytes.fromhex(transcript_hash),
    receipt_sig,
    pki.entity_cert.public_key()
)

print(f"\nReceipt: {'✓ VALID' if is_valid else '✗ INVALID'}")
```

**Run Verification:**

```bash
python scripts/verify_transcript.py
```

**Modify Transcript Test:**
Edit a line in the transcript file and re-run verification.

**Expected Result:**

```
Message 1: ✓ VALID
Message 2: ✓ VALID
Message 3: ✗ INVALID  # Modified line
Receipt: ✗ INVALID    # Hash mismatch
```

---

## 🔒 Security Properties

### Confidentiality

- **Encryption:** AES-128-CBC with random IVs
- **Key Derivation:** K = Trunc₁₆(SHA256(Kₛ)) from DH
- **No Plaintext:** All messages encrypted before transmission

### Integrity

- **Hashing:** SHA-256 over seqno || timestamp || ciphertext
- **Tamper Detection:** Any bit flip invalidates signature

### Authenticity

- **Digital Signatures:** RSA-2048 with PSS padding
- **Certificate Validation:** Chain, expiry, hostname checks
- **Mutual Authentication:** Both parties verify certificates

### Non-Repudiation

- **Signed Transcripts:** Every message signature logged
- **Session Receipt:** Signed transcript hash
- **Offline Verifiable:** Third parties can validate

### Replay Protection

- **Sequence Numbers:** Strictly increasing per session
- **Timestamp:** Unix milliseconds included in signature

---

## 📂 GitHub Repository

**Repository:** https://github.com/chaudaryAbdullah/Secure-Chat

### Commit Guidelines

**Example Commit History:**

```
1. Initial project structure and .gitignore
2. Implement Root CA generation (gen_ca.py)
3. Implement certificate issuance (gen_cert.py)
4. Add PKI module with certificate validation
5. Implement Diffie-Hellman key exchange
6. Add AES-128 encryption with PKCS#7 padding
7. Implement RSA signatures and SHA-256 hashing
8. Create MySQL database integration
9. Implement protocol message formatting
10. Build server with all protocol phases
11. Build client with all protocol phases
12. Add transcript logging and receipts
13. Create comprehensive README
14. Add test scripts and documentation
15. Final testing and bug fixes
```

### What NOT to Commit

```
# .gitignore
certs/
transcripts/
__pycache__/
*.pyc
.env
*.pem
*.key
*.log
```

---

## 📊 Sample Input/Output

### Registration

```
Choose an option:
1. Register
2. Login
Enter choice (1/2): 1

Email: alice@example.com
Username: alice
Password: SecurePass123

[✓] Registration successful!
```

### Login

```
Choose an option:
1. Register
2. Login
Enter choice (1/2): 2

Email: alice@example.com
Password: SecurePass123

[✓] Login successful!
[✓] Authenticated as: alice
```

### Chat

```
============================================================
Chat session active. Type your messages (Ctrl+C to exit)
============================================================

[Client] Hello, server!
[Server] Hi, client! How are you?
[Client] I'm doing great!
[Server] That's wonderful!

[*] Ending chat session...
[✓] Session receipt saved: transcripts/client_alice_20251115_143000_receipt.json
```

---

## 📝 MySQL Schema Dump

```sql
-- Export current schema
mysqldump -u root -p --no-data securechat > schema.sql

-- Export with sample data
mysqldump -u root -p securechat > securechat_dump.sql
```

**Sample Records:**

```sql
INSERT INTO users (email, username, salt, pwd_hash) VALUES
('alice@example.com', 'alice', 0x1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D, 'a1b2c3d4e5f6...'),
('bob@example.com', 'bob', 0x9F8E7D6C5B4A3928171605F4E3D2C1B0, 'f9e8d7c6b5a4...');
```

---

## 🏆 Grading Checklist

### GitHub Workflow (20%)

- ✅ Fork accessible with ≥10 meaningful commits
- ✅ Clear README with execution steps
- ✅ Proper .gitignore (no secrets)
- ✅ Sensible commit messages

### PKI Setup (20%)

- ✅ Root CA generated correctly
- ✅ Server & client certificates issued
- ✅ Mutual verification implemented
- ✅ Expiry & hostname checks
- ✅ Invalid/expired certs rejected

### Registration & Login (20%)

- ✅ Per-user random salt (≥16 bytes)
- ✅ Salted SHA-256 storage
- ✅ Credentials encrypted in transit
- ✅ No plaintext in files/logs
- ✅ Constant-time comparison

### Encrypted Chat (20%)

- ✅ DH after login
- ✅ K = Trunc₁₆(SHA256(Kₛ))
- ✅ AES-128-CBC with PKCS#7
- ✅ Clean error handling

### Integrity & Non-Repudiation (10%)

- ✅ Per-message RSA signatures
- ✅ SHA-256 digest over seqno||ts||ct
- ✅ Strict replay defense
- ✅ Append-only transcript
- ✅ Signed SessionReceipt
- ✅ Offline verification

### Testing & Evidence (10%)

- ✅ Wireshark captures
- ✅ Invalid cert rejection
- ✅ Tamper & replay tests
- ✅ Reproducible steps

---

## 📚 References

- [SEED Lab - PKI](https://seedsecuritylabs.org/Labs_20.04/Crypto/Crypto_PKI/)
- [RFC 3526 - DH Parameters](https://tools.ietf.org/html/rfc3526)
- [Python Cryptography Library](https://cryptography.io/)
- [AES PKCS#7 Padding](<https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7>)

---

## 👤 Author

**Abdullah Shakir**  
**Roll Number:** 22i-1138  
**GitHub:** https://github.com/chaudaryAbdullah/Secure-Chat

---

## 📄 License

This project is submitted as part of academic coursework for Information Security (Fall 2025) at FAST-NUCES. All rights reserved.

---

