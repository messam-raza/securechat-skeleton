#!/usr/bin/env python3
"""
Transcript logger for secure chat sessions.
Logs messages with seqno, timestamp, content, and signature.
"""

import os
import json
from datetime import datetime

class TranscriptLogger:
    def __init__(self, user_email, out_dir="transcripts"):
        self.user_email = user_email
        self.out_dir = out_dir
        os.makedirs(out_dir, exist_ok=True)
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        self.filepath = os.path.join(out_dir, f"{user_email}_{timestamp}.json")
        self.entries = []

    def log_message(self, seqno, ts, content, signature):
        self.entries.append({
            "seqno": seqno,
            "timestamp": ts,
            "message": content,
            "signature": signature.hex() if isinstance(signature, bytes) else signature
        })

    def finalize(self):
        with open(self.filepath, "w") as f:
            json.dump(self.entries, f, indent=2)
        print(f"[+] Transcript saved: {self.filepath}")
