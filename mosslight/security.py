"""Small, explicit controls. No custom cryptographic primitive implementations."""
from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from collections import deque

ITERATIONS = 600_000
SESSION_SECONDS = 1800
MAX_BODY = 16_384


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS)
    return f"pbkdf2_sha256${ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, rounds, salt, expected = encoded.split("$")
        if algorithm != "pbkdf2_sha256" or int(rounds) != ITERATIONS:
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(rounds))
        return hmac.compare_digest(actual.hex(), expected)
    except (ValueError, TypeError):
        return False


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class Limiter:
    """In-memory fixed-capacity sliding windows. Reset on process restart."""
    def __init__(self):
        self.entries: dict[str, deque] = {}
        self.lock = threading.Lock()

    def allow(self, key: str, maximum: int, window: int = 60) -> bool:
        now = time.monotonic()
        with self.lock:
            for old in list(self.entries):
                if not self.entries[old] or self.entries[old][-1] <= now - window:
                    del self.entries[old]
            if key not in self.entries and len(self.entries) >= 2048:
                return False
            events = self.entries.setdefault(key, deque())
            while events and events[0] <= now - window:
                events.popleft()
            if len(events) >= maximum:
                return False
            events.append(now)
            return True
