"""SQLite persistence and fictional data. Runtime databases never enter Git."""
from __future__ import annotations

import json
import os
import secrets
import sqlite3
from pathlib import Path

from .security import hash_password

ROOT = Path(__file__).resolve().parent.parent

SCHEMA = """
CREATE TABLE users (
 id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
 tenant TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('submitter','reviewer')),
 password_hash TEXT NOT NULL
);
CREATE TABLE sessions (
 token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
 csrf TEXT NOT NULL, expires INTEGER NOT NULL
);
CREATE TABLE permits (
 id INTEGER PRIMARY KEY, tenant TEXT NOT NULL, owner_id INTEGER NOT NULL REFERENCES users(id),
 species TEXT NOT NULL, location TEXT NOT NULL, purpose TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('pending','approved','rejected')),
 submitted TEXT NOT NULL, reviewed_by INTEGER REFERENCES users(id),
 review_note TEXT, version INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE audit (
 id INTEGER PRIMARY KEY, created TEXT NOT NULL, tenant TEXT NOT NULL,
 actor_id INTEGER NOT NULL REFERENCES users(id), action TEXT NOT NULL,
 object_id INTEGER, detail TEXT NOT NULL
);
CREATE INDEX permits_tenant_owner ON permits(tenant, owner_id);
CREATE INDEX audit_tenant ON audit(tenant, id);
CREATE INDEX sessions_expiry ON sessions(expires);
"""


def connect(path: Path) -> sqlite3.Connection:
    db = sqlite3.connect(path, timeout=5)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def initialize(path: Path, credentials_path: Path | None = None) -> dict[str, str] | None:
    if path.exists():
        return None
    path.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation prevents accidentally replacing an existing application's data.
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)
    fixture = json.loads((ROOT / "data" / "fictional_permits.json").read_text())
    credentials = {}
    with connect(path) as db:
        db.executescript(SCHEMA)
        for user in fixture["users"]:
            password = secrets.token_urlsafe(18)
            credentials[user["username"]] = password
            db.execute("INSERT INTO users VALUES(?,?,?,?,?,?)", (
                user["id"], user["username"], user["name"], user["tenant"],
                user["role"], hash_password(password)))
        for permit in fixture["permits"]:
            db.execute("INSERT INTO permits VALUES(?,?,?,?,?,?,?,?,?,?,?)", (
                permit["id"], permit["tenant"], permit["owner_id"], permit["species"],
                permit["location"], permit["purpose"], permit["status"], permit["submitted"],
                permit.get("reviewed_by"), permit.get("review_note"), 1))
    if credentials_path is not None:
        fd = os.open(credentials_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as target:
            target.write("LOCAL FICTIONAL LAB ACCOUNTS. Do not reuse these passwords.\n\n")
            for name, password in credentials.items():
                target.write(f"{name}: {password}\n")
    return credentials
