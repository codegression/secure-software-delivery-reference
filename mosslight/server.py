"""Loopback HTTP reference server; intentionally not a production deployment stack."""
from __future__ import annotations

import hmac
import json
import re
import secrets
import sqlite3
import threading
import time
from contextlib import closing
from datetime import datetime, timezone
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from .security import Limiter, MAX_BODY, SESSION_SECONDS, hash_password, token_hash, verify_password
from .store import ROOT, connect

STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/fern.svg": ("fern.svg", "image/svg+xml"),
}
CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"


class Rejected(Exception):
    def __init__(self, code: int, message: str):
        self.code, self.message = code, message


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def fields(data: dict, specification: dict[str, tuple[int, int]]) -> dict:
    if set(data) != set(specification):
        raise Rejected(400, "Unexpected or missing fields")
    for key, (minimum, maximum) in specification.items():
        value = data[key]
        if not isinstance(value, str) or not minimum <= len(value.strip()) <= maximum:
            raise Rejected(400, f"Invalid {key}")
        if any(ord(char) < 32 and char not in "\n\t" for char in value):
            raise Rejected(400, f"Invalid {key}")
    return data


class FieldbookServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, path: Path, port: int = 8767):
        self.database = Path(path)
        self.limiter = Limiter()
        self.slots = threading.BoundedSemaphore(16)
        self.dummy_hash = hash_password(secrets.token_urlsafe(24))
        # No option to bind externally: changing this code requires revisiting deployment design.
        super().__init__(("127.0.0.1", port), Handler)
        self.expected_host = f"127.0.0.1:{self.server_port}"
        self.origin = f"http://{self.expected_host}"

    def get_request(self):
        sock, address = super().get_request()
        sock.settimeout(5)
        return sock, address

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()


class Handler(BaseHTTPRequestHandler):
    server_version = "MosslightLab/1"
    sys_version = ""

    def log_message(self, fmt, *args):
        # API action audit is structured in SQLite; omit raw URL/header/request logging.
        pass

    def reply(self, code: int, payload, content_type="application/json; charset=utf-8", cookie=None):
        body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        if code == 429:
            self.send_header("Retry-After", "60")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def reject(self, code: int, message: str):
        self.reply(code, {"error": message})

    def common(self, write=False):
        if len(self.path) > 512:
            raise Rejected(414, "Request path too long")
        hosts = self.headers.get_all("Host", [])
        if hosts != [self.server.expected_host]:
            raise Rejected(400, "Unrecognized Host")
        if write:
            if self.headers.get_all("Origin", []) != [self.server.origin]:
                raise Rejected(403, "Same-origin request required")
            if self.headers.get("Sec-Fetch-Site", "same-origin") != "same-origin":
                raise Rejected(403, "Cross-site request denied")
        parsed = urlsplit(self.path)
        if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
            raise Rejected(400, "Use an exact local API path")
        return parsed.path

    def body(self):
        if self.headers.get("Transfer-Encoding"):
            raise Rejected(400, "Transfer encoding unsupported")
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) != 1 or not lengths[0].isdigit():
            raise Rejected(411, "One Content-Length is required")
        size = int(lengths[0])
        if size > MAX_BODY:
            raise Rejected(413, "Request body too large")
        if self.headers.get("Content-Type", "").split(";")[0].strip().lower() != "application/json":
            raise Rejected(415, "Send application/json")
        try:
            raw = self.rfile.read(size)
            if len(raw) != size:
                raise ValueError("truncated body")
            value = json.loads(raw.decode("utf-8"), object_pairs_hook=strict_object,
                               parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
        except (ValueError, UnicodeError):
            raise Rejected(400, "Invalid JSON") from None
        if not isinstance(value, dict):
            raise Rejected(400, "Expected a JSON object")
        return value

    def session_token(self):
        try:
            cookies = SimpleCookie()
            cookies.load(self.headers.get("Cookie", ""))
            return cookies["moss_session"].value if "moss_session" in cookies else ""
        except CookieError:
            return ""

    def authenticated(self, db, write=False):
        raw_token = self.session_token()
        if not 32 <= len(raw_token) <= 128:
            raise Rejected(401, "Sign in to continue")
        user = db.execute("""SELECT u.id, u.username, u.name, u.tenant, u.role, s.csrf, s.expires
                           FROM sessions s JOIN users u ON u.id=s.user_id
                           WHERE s.token_hash=? AND s.expires>?""",
                          (token_hash(raw_token), int(time.time()))).fetchone()
        if not user:
            raise Rejected(401, "Sign in to continue")
        if write:
            csrf = self.headers.get("X-CSRF-Token", "")
            if not hmac.compare_digest(csrf.encode(), user["csrf"].encode()):
                raise Rejected(403, "CSRF token required")
            if not self.server.limiter.allow(f"write:{user['id']}", 40):
                raise Rejected(429, "Write limit reached; try again later")
        return user

    @staticmethod
    def permit(db, user, permit_id):
        item = db.execute("SELECT * FROM permits WHERE id=? AND tenant=?", (permit_id, user["tenant"])).fetchone()
        if item is None or (user["role"] != "reviewer" and item["owner_id"] != user["id"]):
            raise Rejected(404, "Permit not found")
        return item

    @staticmethod
    def audit(db, user, action, object_id=None, detail=""):
        db.execute("INSERT INTO audit(created,tenant,actor_id,action,object_id,detail) VALUES(?,?,?,?,?,?)",
                   (utc_now(), user["tenant"], user["id"], action, object_id, detail))

    def do_GET(self):
        try:
            path = self.common()
            if path in STATIC:
                filename, content_type = STATIC[path]
                self.reply(200, (ROOT / "static" / filename).read_bytes(), content_type)
                return
            with closing(connect(self.server.database)) as db:
                user = self.authenticated(db)
                if path == "/api/session":
                    self.reply(200, {"user": {key: user[key] for key in ("id", "username", "name", "tenant", "role")},
                                     "csrf": user["csrf"], "expires": user["expires"]})
                elif path == "/api/permits":
                    sql = "SELECT * FROM permits WHERE tenant=?"
                    params = [user["tenant"]]
                    if user["role"] != "reviewer":
                        sql += " AND owner_id=?"
                        params.append(user["id"])
                    items = [dict(row) for row in db.execute(sql + " ORDER BY id DESC LIMIT 500", params)]
                    self.reply(200, {"permits": items})
                elif re.fullmatch(r"/api/permits/[0-9]{1,9}", path):
                    self.reply(200, {"permit": dict(self.permit(db, user, int(path.split("/")[-1])))})
                elif path == "/api/audit":
                    if user["role"] != "reviewer":
                        raise Rejected(403, "Reviewer role required")
                    items = [dict(row) for row in db.execute("SELECT * FROM audit WHERE tenant=? ORDER BY id DESC LIMIT 100", (user["tenant"],))]
                    self.reply(200, {"events": items})
                else:
                    raise Rejected(404, "Not found")
        except Rejected as error:
            self.reject(error.code, error.message)
        except (sqlite3.Error, OSError):
            self.reject(503, "Service temporarily unavailable")

    def do_POST(self):
        try:
            path = self.common(write=True)
            with closing(connect(self.server.database)) as db:
                if path == "/api/login":
                    if not self.server.limiter.allow(f"login-ip:{self.client_address[0]}", 20):
                        raise Rejected(429, "Sign-in limit reached; try again later")
                    data = fields(self.body(), {"username": (1, 64), "password": (1, 256)})
                    name = data["username"].lower().strip()
                    if not self.server.limiter.allow(f"login-user:{name}", 6):
                        raise Rejected(429, "Sign-in limit reached; try again later")
                    user = db.execute("SELECT * FROM users WHERE username=?", (name,)).fetchone()
                    matched = verify_password(data["password"], user["password_hash"] if user else self.server.dummy_hash)
                    if not user or not matched:
                        raise Rejected(401, "Invalid credentials")
                    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
                    with db:
                        db.execute("DELETE FROM sessions WHERE expires<=? OR token_hash=?", (int(time.time()), token_hash(self.session_token())))
                        # At most five live sessions per account; oldest evicted on a sixth login.
                        existing = db.execute("SELECT token_hash FROM sessions WHERE user_id=? ORDER BY expires DESC", (user["id"],)).fetchall()
                        for old in existing[4:]:
                            db.execute("DELETE FROM sessions WHERE token_hash=?", (old["token_hash"],))
                        db.execute("INSERT INTO sessions VALUES(?,?,?,?)", (token_hash(token), user["id"], csrf, int(time.time()) + SESSION_SECONDS))
                        self.audit(db, user, "signed_in")
                    self.reply(200, {"csrf": csrf}, cookie=f"moss_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_SECONDS}")
                    return
                user = self.authenticated(db, write=True)
                data = self.body()
                if path == "/api/logout":
                    fields(data, {})
                    with db:
                        db.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash(self.session_token()),))
                        self.audit(db, user, "signed_out")
                    self.reply(200, {"ok": True}, cookie="moss_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")
                elif path == "/api/permits":
                    fields(data, {"species": (3, 120), "location": (3, 120), "purpose": (15, 1500)})
                    with db:
                        cursor = db.execute("""INSERT INTO permits(tenant,owner_id,species,location,purpose,status,submitted)
                                             VALUES(?,?,?,?,?,'pending',?)""", (user["tenant"], user["id"], data["species"].strip(), data["location"].strip(), data["purpose"].strip(), utc_now()))
                        self.audit(db, user, "permit_submitted", cursor.lastrowid)
                    self.reply(201, {"id": cursor.lastrowid})
                elif re.fullmatch(r"/api/permits/[0-9]{1,9}/review", path):
                    fields(data, {"decision": (1, 20), "note": (10, 500)})
                    if data["decision"] not in ("approved", "rejected"):
                        raise Rejected(400, "Decision must be approved or rejected")
                    if user["role"] != "reviewer":
                        raise Rejected(403, "Reviewer role required")
                    permit_id = int(path.split("/")[-2])
                    item = self.permit(db, user, permit_id)
                    if item["owner_id"] == user["id"]:
                        raise Rejected(403, "A second reviewer must review your own submission")
                    with db:
                        cursor = db.execute("""UPDATE permits SET status=?,reviewed_by=?,review_note=?,version=version+1
                                              WHERE id=? AND tenant=? AND status='pending'""",
                                            (data["decision"], user["id"], data["note"].strip(), permit_id, user["tenant"]))
                        if cursor.rowcount != 1:
                            raise Rejected(409, "This permit has already been reviewed")
                        self.audit(db, user, "permit_reviewed", permit_id, data["decision"])
                    self.reply(200, {"ok": True})
                else:
                    raise Rejected(404, "Not found")
        except Rejected as error:
            self.reject(error.code, error.message)
        except (sqlite3.Error, OSError):
            self.reject(503, "Service temporarily unavailable")

    def do_OPTIONS(self):
        self.reject(405, "Method not allowed")

    do_PUT = do_OPTIONS
    do_PATCH = do_OPTIONS
    do_DELETE = do_OPTIONS
