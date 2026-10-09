
import os
import re
import json
import hmac
import base64
import hashlib
import secrets
import sqlite3
import smtplib
import urllib.parse
import urllib.request
import urllib.error

from email.message import EmailMessage
from datetime import datetime, timezone, timedelta, date
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field


# =========================================================
# ZIVAN — AUTH V3 + SOCIAL + SECURITY FOUNDATION
# AI CONTROL CENTER: RESERVED FOR THE FINAL PHASE
# =========================================================

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("ZIVAN_DB", str(BASE_DIR / "zivan.db")))

SESSION_DAYS = 30
OTP_MINUTES = 10
MAX_OTP_ATTEMPTS = 5
OWNER_USERNAME = os.getenv("ZIVAN_OWNER_USERNAME", "").strip().lower()
IP_HASH_SECRET = os.getenv("ZIVAN_IP_HASH_SECRET", "")
POLICY_VERSION = os.getenv("ZIVAN_POLICY_VERSION", "2026-10-01")

app = FastAPI(
    title="ZIVAN API",
    version="0.3.0",
    description="ZIVAN social platform API and security foundation"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)


# =========================================================
# DATABASE HELPERS
# =========================================================

def db():
    con = sqlite3.connect(DB_PATH, timeout=20)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    con.execute("PRAGMA busy_timeout = 20000")
    return con


def now():
    return datetime.now(timezone.utc).isoformat()


def utc_after(**kwargs):
    return (datetime.now(timezone.utc) + timedelta(**kwargs)).isoformat()


def ip_digest(ip):
    if not ip:
        return ""
    if IP_HASH_SECRET:
        return hmac.new(
            IP_HASH_SECRET.encode(),
            ip.encode(),
            hashlib.sha256
        ).hexdigest()
    return hashlib.sha256(("zivan-ip:" + ip).encode()).hexdigest()


def request_ip(request: Request):
    # Use the connection peer, not arbitrary client-supplied X-Forwarded-For.
    return request.client.host if request.client else ""


def password_hash(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, 310000
    )
    return salt.hex() + "$" + digest.hex()


def password_ok(password, stored):
    try:
        salt_hex, digest_hex = stored.split("$", 1)
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"),
            bytes.fromhex(salt_hex), 310000
        )
        return hmac.compare_digest(digest.hex(), digest_hex)
    except Exception:
        return False


def code_hash(code):
    return hashlib.sha256(code.encode()).hexdigest()


def make_session(con, user_id):
    token = secrets.token_urlsafe(48)
    con.execute(
        """INSERT INTO sessions(token,user_id,created_at,expires_at)
           VALUES(?,?,?,?)""",
        (token, user_id, now(), utc_after(days=SESSION_DAYS))
    )
    return token


def normalize_email(value):
    return (value or "").strip().lower()


def normalize_username(value):
    username = (value or "").strip().lstrip("@").lower()
    if not re.fullmatch(r"[a-z0-9_]{3,30}", username):
        raise HTTPException(
            400,
            "Username must be 3–30 characters: letters, numbers or underscores."
        )
    return username


def normalize_phone(value):
    phone = re.sub(r"[\s().-]", "", (value or "").strip())
    if not phone:
        return ""
    if phone.startswith("00"):
        phone = "+" + phone[2:]
    if not re.fullmatch(r"\+[1-9]\d{7,14}", phone):
        raise HTTPException(
            400,
            "Use an international phone number, for example +919876543210."
        )
    return phone


def validate_dob(value):
    try:
        dob = date.fromisoformat(value)
    except Exception:
        raise HTTPException(400, "DOB must be in YYYY-MM-DD format.")

    today = datetime.now(timezone.utc).date()
    if dob > today:
        raise HTTPException(400, "DOB cannot be in the future.")

    age = today.year - dob.year - (
        (today.month, today.day) < (dob.month, dob.day)
    )
    if age < 13:
        raise HTTPException(400, "ZIVAN is currently for people aged 13+.")
    if age > 120:
        raise HTTPException(400, "Please enter a valid date of birth.")
    return dob.isoformat()


def rate_limit(con, key, limit, window_seconds):
    """Simple persistent fixed-window limiter. Use Redis for multi-instance scale."""
    current = datetime.now(timezone.utc)
    cutoff = (current - timedelta(seconds=window_seconds)).isoformat()
    con.execute("DELETE FROM rate_events WHERE created_at < ?", (cutoff,))
    count = con.execute(
        "SELECT COUNT(*) c FROM rate_events WHERE bucket_key=? AND created_at>?",
        (key, cutoff)
    ).fetchone()["c"]
    if count >= limit:
        raise HTTPException(
            429,
            "Too many attempts. Please wait before trying again."
        )
    con.execute(
        "INSERT INTO rate_events(bucket_key,created_at) VALUES(?,?)",
        (key, now())
    )


def record_security_event(con, event, ip, user_id=None, details=None):
    con.execute(
        """INSERT INTO security_events
           (event,user_id,ip_hash,details_json,created_at)
           VALUES(?,?,?,?,?)""",
        (
            event, user_id, ip_digest(ip),
            json.dumps(details or {}, ensure_ascii=False)[:3000], now()
        )
    )


# =========================================================
# EMAIL OTP
# =========================================================

def send_email_code(email, code):
    host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    port = int(os.getenv("SMTP_PORT", "587"))
    username = os.getenv("SMTP_USERNAME", "")
    password = os.getenv("SMTP_PASSWORD", "")
    sender = os.getenv("SMTP_FROM", username)

    if not username or not password:
        raise RuntimeError("Email verification is not configured.")

    message = EmailMessage()
    message["Subject"] = "Your ZIVAN verification code"
    message["From"] = sender
    message["To"] = email
    message.set_content(
        f"""Your ZIVAN verification code is: {code}

This code expires in {OTP_MINUTES} minutes.
If you did not request this code, ignore this email."""
    )

    with smtplib.SMTP(host, port, timeout=20) as server:
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(username, password)
        server.send_message(message)


# =========================================================
# TWILIO VERIFY
# =========================================================

def twilio_request(path, form):
    api_key = os.getenv("TWILIO_API_KEY", "")
    api_secret = os.getenv("TWILIO_API_SECRET", "")
    if not api_key or not api_secret:
        raise RuntimeError("Phone verification is not configured.")

    request = urllib.request.Request(
        "https://verify.twilio.com/v2/" + path.lstrip("/"),
        data=urllib.parse.urlencode(form).encode(),
        method="POST"
    )
    auth = base64.b64encode(
        f"{api_key}:{api_secret}".encode()
    ).decode()
    request.add_header("Authorization", "Basic " + auth)
    request.add_header("Content-Type", "application/x-www-form-urlencoded")

    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError:
        # Never leak provider response bodies or credentials to users.
        raise RuntimeError("Phone verification provider rejected the request.")
    except Exception:
        raise RuntimeError("Phone verification provider is unavailable.")


def twilio_send(phone):
    service = os.getenv("TWILIO_VERIFY_SERVICE_SID", "")
    if not service:
        raise RuntimeError("Phone verification is not configured.")
    return twilio_request(
        f"Services/{service}/Verifications",
        {"channel": "sms", "to": phone}
    )


def twilio_check(phone, code):
    service = os.getenv("TWILIO_VERIFY_SERVICE_SID", "")
    if not service:
        raise RuntimeError("Phone verification is not configured.")
    return twilio_request(
        f"Services/{service}/VerificationCheck",
        {"to": phone, "code": code}
    )


# =========================================================
# DATABASE SCHEMA + SAFE ADDITIVE MIGRATIONS
# =========================================================

def init_db():
    con = db()
    con.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE COLLATE NOCASE,
        email TEXT UNIQUE COLLATE NOCASE,
        password_hash TEXT NOT NULL,
        display_name TEXT NOT NULL,
        full_name TEXT NOT NULL DEFAULT '',
        dob TEXT,
        phone TEXT UNIQUE,
        email_verified INTEGER NOT NULL DEFAULT 0,
        phone_verified INTEGER NOT NULL DEFAULT 0,
        bio TEXT NOT NULL DEFAULT '',
        avatar TEXT NOT NULL DEFAULT '',
        is_private INTEGER NOT NULL DEFAULT 0,
        account_status TEXT NOT NULL DEFAULT 'active',
        ban_reason TEXT NOT NULL DEFAULT '',
        banned_until TEXT,
        chat_banned_until TEXT,
        golden_tick INTEGER NOT NULL DEFAULT 0,
        verification_status TEXT NOT NULL DEFAULT 'none',
        policy_accepted_at TEXT,
        policy_version TEXT,
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS signup_challenges (
        id TEXT PRIMARY KEY,
        channel TEXT NOT NULL,
        destination TEXT NOT NULL,
        code_hash TEXT,
        expires_at TEXT NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        full_name TEXT NOT NULL,
        username TEXT NOT NULL,
        dob TEXT NOT NULL,
        email TEXT,
        phone TEXT,
        password_hash TEXT NOT NULL,
        ip_hash TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS follows (
        follower_id INTEGER NOT NULL,
        following_id INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY(follower_id, following_id),
        CHECK(follower_id != following_id),
        FOREIGN KEY(follower_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(following_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        body TEXT NOT NULL,
        media_url TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS likes (
        user_id INTEGER NOT NULL,
        post_id INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY(user_id, post_id),
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        post_id INTEGER NOT NULL,
        body TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        actor_id INTEGER,
        kind TEXT NOT NULL,
        post_id INTEGER,
        read_at TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(actor_id) REFERENCES users(id) ON DELETE SET NULL,
        FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS rate_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        bucket_key TEXT NOT NULL,
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS security_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event TEXT NOT NULL,
        user_id INTEGER,
        ip_hash TEXT NOT NULL DEFAULT '',
        details_json TEXT NOT NULL DEFAULT '{}',
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
    );

    CREATE TABLE IF NOT EXISTS ip_blocks (
        ip_hash TEXT PRIMARY KEY,
        reason TEXT NOT NULL DEFAULT '',
        expires_at TEXT,
        created_by INTEGER,
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS admin_roles (
        user_id INTEGER PRIMARY KEY,
        permissions_json TEXT NOT NULL DEFAULT '[]',
        granted_by INTEGER,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS moderation_reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        reporter_id INTEGER NOT NULL,
        target_user_id INTEGER NOT NULL,
        post_id INTEGER,
        reason TEXT NOT NULL,
        details TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'pending',
        reporter_score INTEGER NOT NULL DEFAULT 0,
        priority_score INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        FOREIGN KEY(reporter_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(target_user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE SET NULL
    );

    CREATE TABLE IF NOT EXISTS moderation_actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_user_id INTEGER NOT NULL,
        actor_id INTEGER,
        action TEXT NOT NULL,
        reason TEXT NOT NULL DEFAULT '',
        source TEXT NOT NULL DEFAULT 'manual',
        expires_at TEXT,
        metadata_json TEXT NOT NULL DEFAULT '{}',
        created_at TEXT NOT NULL,
        FOREIGN KEY(target_user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(actor_id) REFERENCES users(id) ON DELETE SET NULL
    );

    CREATE TABLE IF NOT EXISTS moderation_appeals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        action_id INTEGER,
        message TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        reviewed_by INTEGER,
        reviewed_at TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(action_id) REFERENCES moderation_actions(id) ON DELETE SET NULL,
        FOREIGN KEY(reviewed_by) REFERENCES users(id) ON DELETE SET NULL
    );

    CREATE TABLE IF NOT EXISTS admin_audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        actor_id INTEGER,
        action TEXT NOT NULL,
        target_user_id INTEGER,
        details_json TEXT NOT NULL DEFAULT '{}',
        created_at TEXT NOT NULL,
        FOREIGN KEY(actor_id) REFERENCES users(id) ON DELETE SET NULL,
        FOREIGN KEY(target_user_id) REFERENCES users(id) ON DELETE SET NULL
    );

    CREATE TABLE IF NOT EXISTS app_settings (
        setting_key TEXT PRIMARY KEY,
        setting_value TEXT NOT NULL,
        updated_by INTEGER,
        updated_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_rate_bucket ON rate_events(bucket_key, created_at);
    CREATE INDEX IF NOT EXISTS idx_report_status ON moderation_reports(status, created_at);
    CREATE INDEX IF NOT EXISTS idx_report_target ON moderation_reports(target_user_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_appeal_status ON moderation_appeals(status, created_at);
    CREATE INDEX IF NOT EXISTS idx_security_event ON security_events(event, created_at);
    """)

    # Existing Phase-1 database migration: only add missing columns.
    migrations = {
        "users": {
            "full_name": "TEXT NOT NULL DEFAULT ''",
            "dob": "TEXT",
            "phone": "TEXT",
            "email_verified": "INTEGER NOT NULL DEFAULT 0",
            "phone_verified": "INTEGER NOT NULL DEFAULT 0",
            "account_status": "TEXT NOT NULL DEFAULT 'active'",
            "ban_reason": "TEXT NOT NULL DEFAULT ''",
            "banned_until": "TEXT",
            "chat_banned_until": "TEXT",
            "golden_tick": "INTEGER NOT NULL DEFAULT 0",
            "verification_status": "TEXT NOT NULL DEFAULT 'none'",
            "policy_accepted_at": "TEXT",
            "policy_version": "TEXT"
        },
        "sessions": {"expires_at": "TEXT"},
        "signup_challenges": {"ip_hash": "TEXT NOT NULL DEFAULT ''"},
        "moderation_reports": {
            "reporter_score": "INTEGER NOT NULL DEFAULT 0",
            "priority_score": "INTEGER NOT NULL DEFAULT 0"
        }
    }

    for table, columns in migrations.items():
        existing = {
            row["name"]
            for row in con.execute(f"PRAGMA table_info({table})").fetchall()
        }
        for column, definition in columns.items():
            if column not in existing:
                con.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    con.execute(
        """UPDATE users SET full_name=display_name
           WHERE full_name IS NULL OR full_name=''"""
    )
    con.execute(
        """UPDATE sessions SET expires_at=?
           WHERE expires_at IS NULL OR expires_at=''""",
        (utc_after(days=SESSION_DAYS),)
    )
    con.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_users_phone_unique
        ON users(phone) WHERE phone IS NOT NULL AND phone <> ''
    """)
    con.commit()
    con.close()


init_db()


# =========================================================
# REQUEST MODELS
# =========================================================

class SignupStart(BaseModel):
    full_name: str = Field(min_length=1, max_length=80)
    username: str = Field(min_length=3, max_length=30)
    dob: str
    email: Optional[str] = Field(default=None, max_length=254)
    phone: Optional[str] = Field(default=None, max_length=30)
    password: str = Field(min_length=8, max_length=128)
    channel: Optional[str] = None


class VerifyCode(BaseModel):
    challenge_id: str = Field(min_length=20, max_length=200)
    code: str = Field(min_length=4, max_length=10)


class LoginV2(BaseModel):
    identifier: str = Field(min_length=1, max_length=254)
    password: str = Field(min_length=8, max_length=128)


class LegacyAuth(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None
    identifier: Optional[str] = None
    password: str = Field(min_length=8, max_length=128)


class ProfileUpdate(BaseModel):
    display_name: Optional[str] = Field(default=None, max_length=80)
    bio: Optional[str] = Field(default=None, max_length=500)
    avatar: Optional[str] = Field(default=None, max_length=500)
    is_private: Optional[bool] = None


class PostIn(BaseModel):
    body: str = Field(min_length=1, max_length=5000)
    media_url: Optional[str] = Field(default="", max_length=2000)


class CommentIn(BaseModel):
    body: str = Field(min_length=1, max_length=1000)


class ReportIn(BaseModel):
    username: str = Field(min_length=3, max_length=30)
    reason: str = Field(min_length=3, max_length=80)
    details: str = Field(default="", max_length=2000)
    post_id: Optional[int] = None


class BanIn(BaseModel):
    reason: str = Field(min_length=3, max_length=1000)
    duration_hours: Optional[int] = Field(default=24, ge=1, le=8760)
    permanent: bool = False


class AppealIn(BaseModel):
    message: str = Field(min_length=10, max_length=3000)


class AppealReviewIn(BaseModel):
    decision: str = Field(min_length=3, max_length=30)
    note: str = Field(default="", max_length=1000)


class AdminGrantIn(BaseModel):
    username: str = Field(min_length=3, max_length=30)
    permissions: list[str] = Field(default_factory=list)


class GoldenTickIn(BaseModel):
    enabled: bool
    note: str = Field(default="", max_length=1000)


class ChatBanIn(BaseModel):
    hours: int = Field(ge=1, le=8760)
    reason: str = Field(min_length=3, max_length=1000)


class SettingIn(BaseModel):
    value: str = Field(max_length=2000)


# =========================================================
# SERIALIZATION + AUTHORIZATION
# =========================================================

def public_user(row, private=False):
    keys = set(row.keys())
    result = {
        "id": row["id"],
        "username": row["username"],
        "display_name": row["display_name"],
        "full_name": row["full_name"] if "full_name" in keys else row["display_name"],
        "email_verified": bool(row["email_verified"]),
        "phone_verified": bool(row["phone_verified"]),
        "bio": row["bio"],
        "avatar": row["avatar"],
        "is_private": bool(row["is_private"]),
        "golden_tick": bool(row["golden_tick"]) if "golden_tick" in keys else False,
        "verification_status": row["verification_status"] if "verification_status" in keys else "none",
        "created_at": row["created_at"]
    }
    # Contact details and DOB are only returned to the authenticated account owner.
    if private:
        result.update({
            "email": row["email"],
            "phone": row["phone"],
            "dob": row["dob"],
            "account_status": row["account_status"] if "account_status" in keys else "active"
        })
    return result


CONTROL_PERMISSIONS = {
    "dashboard", "users_read", "reports_review", "appeals_review",
    "ban_users", "chat_restrictions", "verification_manage",
    "security_events", "settings_manage"
}


def role_for(user):
    if OWNER_USERNAME and user["username"].lower() == OWNER_USERNAME:
        return "owner"
    con = db()
    found = con.execute(
        "SELECT permissions_json FROM admin_roles WHERE user_id=?",
        (user["id"],)
    ).fetchone()
    con.close()
    if not found:
        return None
    try:
        permissions = json.loads(found["permissions_json"] or "[]")
    except Exception:
        permissions = []
    return {"role": "admin", "permissions": sorted(set(permissions) & CONTROL_PERMISSIONS)}


def require_control(authorization, permission=None, owner_only=False):
    user, token = current_user(authorization)
    role = role_for(user)
    if role == "owner":
        return user, role
    if owner_only:
        raise HTTPException(403, "Only the configured ZIVAN owner can do this.")
    if not role:
        raise HTTPException(403, "Control Center access is not authorized.")
    if permission and permission not in role["permissions"]:
        raise HTTPException(403, "Your admin role does not have this permission.")
    return user, role


def audit(con, actor_id, action, target_user_id=None, details=None):
    con.execute(
        """INSERT INTO admin_audit_logs
           (actor_id,action,target_user_id,details_json,created_at)
           VALUES(?,?,?,?,?)""",
        (
            actor_id, action, target_user_id,
            json.dumps(details or {}, ensure_ascii=False)[:4000], now()
        )
    )


def current_user(authorization: Optional[str]):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Authentication required.")
    token = authorization.split(" ", 1)[1].strip()
    con = db()
    row = con.execute(
        """SELECT u.* FROM users u JOIN sessions s ON s.user_id=u.id
           WHERE s.token=? AND s.expires_at>?""",
        (token, now())
    ).fetchone()

    if row and row["account_status"] == "suspended":
        expiry = row["banned_until"]
        if expiry and expiry <= now():
            con.execute(
                """UPDATE users SET account_status='active',
                   ban_reason='',banned_until=NULL WHERE id=?""",
                (row["id"],)
            )
            con.commit()
            row = con.execute("SELECT * FROM users WHERE id=?", (row["id"],)).fetchone()

    if row and row["account_status"] in ("banned", "suspended"):
        con.close()
        raise HTTPException(
            403,
            "This account is restricted. If you believe this is a mistake, submit an appeal."
        )
    con.close()
    if not row:
        raise HTTPException(401, "Invalid or expired session.")
    return row, token


def appeal_user(authorization):
    """Valid session lookup that allows a banned user to file an appeal."""
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Authentication required.")
    token = authorization.split(" ", 1)[1].strip()
    con = db()
    row = con.execute(
        """SELECT u.* FROM users u JOIN sessions s ON s.user_id=u.id
           WHERE s.token=? AND s.expires_at>?""",
        (token, now())
    ).fetchone()
    con.close()
    if not row:
        raise HTTPException(401, "Invalid or expired session.")
    return row


def enforce_ip_not_blocked(con, ip):
    digest = ip_digest(ip)
    if not digest:
        return
    block = con.execute(
        "SELECT expires_at FROM ip_blocks WHERE ip_hash=?",
        (digest,)
    ).fetchone()
    if block:
        if not block["expires_at"] or block["expires_at"] > now():
            raise HTTPException(403, "Access from this network is temporarily restricted.")
        con.execute("DELETE FROM ip_blocks WHERE ip_hash=?", (digest,))


# =========================================================
# BASIC + HEALTH
# =========================================================

@app.get("/")
def home():
    return FileResponse(BASE_DIR / "index.html")


@app.get("/api/health")
def health():
    return {"ok": True, "service": "ZIVAN", "version": "0.3.0"}


@app.get("/api/init-app")
def init_app():
    return {
        "app": "ZIVAN",
        "version": "0.3.0",
        "features": [
            "auth", "email_verification", "phone_verification",
            "profiles", "follow", "posts", "likes", "comments",
            "notifications", "security_events", "moderation_reports",
            "appeals", "admin_roles", "golden_verification",
            "ai_control_center_reserved"
        ]
    }


# =========================================================
# AUTH V2 — REQUEST OTP
# =========================================================

@app.post("/api/auth/request-code")
def request_code(data: SignupStart, request: Request):
    full_name = data.full_name.strip()
    if len(full_name) < 1:
        raise HTTPException(400, "Enter your full name.")
    username = normalize_username(data.username)
    dob = validate_dob(data.dob)
    email = normalize_email(data.email)
    phone = normalize_phone(data.phone)
    ip = request_ip(request)

    if bool(email) == bool(phone):
        raise HTTPException(400, "Choose exactly one: email or phone.")

    if email:
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            raise HTTPException(400, "Invalid email address.")
        channel = "email"
    else:
        channel = "phone"

    con = db()
    try:
        enforce_ip_not_blocked(con, ip)
        rate_limit(con, "signup-ip:" + ip_digest(ip), 5, 3600)
        rate_limit(con, "signup-dest:" + hashlib.sha256((email or phone).encode()).hexdigest(), 3, 3600)

        existing = con.execute(
            """SELECT id FROM users
               WHERE username=? OR email=? OR phone=? LIMIT 1""",
            (username, email or None, phone or None)
        ).fetchone()
        if existing:
            raise HTTPException(409, "Username, email or phone is already registered.")

        challenge_id = secrets.token_urlsafe(32)
        email_code = f"{secrets.randbelow(1000000):06d}" if channel == "email" else None
        con.execute(
            """INSERT INTO signup_challenges
               (id,channel,destination,code_hash,expires_at,attempts,
                full_name,username,dob,email,phone,password_hash,ip_hash,created_at)
               VALUES(?,?,?,?,?,0,?,?,?,?,?,?,?,?)""",
            (
                challenge_id, channel, email or phone,
                code_hash(email_code) if email_code else None,
                utc_after(minutes=OTP_MINUTES), full_name, username, dob,
                email or None, phone or None, password_hash(data.password),
                ip_digest(ip), now()
            )
        )
        con.commit()
    except Exception:
        con.rollback()
        con.close()
        raise
    con.close()

    try:
        if channel == "email":
            send_email_code(email, email_code)
        else:
            twilio_send(phone)
    except Exception:
        con = db()
        con.execute("DELETE FROM signup_challenges WHERE id=?", (challenge_id,))
        con.commit()
        con.close()
        raise HTTPException(502, "Verification provider failed. Check the server configuration.")

    return {
        "ok": True,
        "challenge_id": challenge_id,
        "channel": channel,
        "destination": email or phone,
        "expires_in_seconds": OTP_MINUTES * 60
    }


# =========================================================
# AUTH V2 — VERIFY OTP + CREATE ACCOUNT
# =========================================================

@app.post("/api/auth/verify-code")
def verify_code(data: VerifyCode, request: Request):
    con = db()
    challenge = con.execute(
        "SELECT * FROM signup_challenges WHERE id=?",
        (data.challenge_id,)
    ).fetchone()

    if not challenge:
        con.close()
        raise HTTPException(404, "Verification request not found.")

    try:
        expiry = datetime.fromisoformat(challenge["expires_at"])
    except Exception:
        expiry = datetime.now(timezone.utc) - timedelta(seconds=1)

    if expiry <= datetime.now(timezone.utc):
        con.execute("DELETE FROM signup_challenges WHERE id=?", (data.challenge_id,))
        con.commit()
        con.close()
        raise HTTPException(400, "Verification code expired.")

    if challenge["attempts"] >= MAX_OTP_ATTEMPTS:
        con.close()
        raise HTTPException(429, "Too many verification attempts. Start again later.")

    # The signup challenge is bound to the network hash used to request it.
    ip = request_ip(request)
    if challenge["ip_hash"] and challenge["ip_hash"] != ip_digest(ip):
        con.close()
        raise HTTPException(403, "For security, continue verification from the same network.")

    code = data.code.strip()
    con.execute(
        "UPDATE signup_challenges SET attempts=attempts+1 WHERE id=?",
        (data.challenge_id,)
    )
    con.commit()
    con.close()

    approved = False
    if challenge["channel"] == "email":
        approved = hmac.compare_digest(challenge["code_hash"] or "", code_hash(code))
    else:
        try:
            result = twilio_check(challenge["destination"], code)
            approved = result.get("status") == "approved"
        except Exception:
            raise HTTPException(502, "Phone verification provider failed.")

    if not approved:
        raise HTTPException(400, "Invalid verification code.")

    con = db()
    try:
        existing = con.execute(
            "SELECT id FROM users WHERE username=? OR email=? OR phone=? LIMIT 1",
            (challenge["username"], challenge["email"], challenge["phone"])
        ).fetchone()
        if existing:
            con.execute("DELETE FROM signup_challenges WHERE id=?", (data.challenge_id,))
            con.commit()
            raise HTTPException(409, "Account already exists.")

        email_verified = 1 if challenge["channel"] == "email" else 0
        phone_verified = 1 if challenge["channel"] == "phone" else 0
        cur = con.execute(
            """INSERT INTO users
               (username,email,password_hash,display_name,full_name,dob,phone,
                email_verified,phone_verified,policy_accepted_at,policy_version,created_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                challenge["username"], challenge["email"], challenge["password_hash"],
                challenge["full_name"], challenge["full_name"], challenge["dob"],
                challenge["phone"], email_verified, phone_verified,
                now(), POLICY_VERSION, now()
            )
        )
        user_id = cur.lastrowid
        token = make_session(con, user_id)
        row = con.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        con.execute("DELETE FROM signup_challenges WHERE id=?", (data.challenge_id,))
        record_security_event(con, "signup_success", ip, user_id)
        con.commit()
        return {"ok": True, "token": token, "user": public_user(row, private=True)}
    except sqlite3.IntegrityError:
        con.rollback()
        raise HTTPException(409, "Account already exists.")
    finally:
        con.close()


# =========================================================
# AUTH V2 — LOGIN
# =========================================================

@app.post("/api/auth/login")
def auth_login(data: LoginV2, request: Request):
    ip = request_ip(request)
    value = data.identifier.strip()
    bare = value.lstrip("@")
    email = normalize_email(value)

    con = db()
    try:
        enforce_ip_not_blocked(con, ip)
        rate_limit(con, "login-ip:" + ip_digest(ip), 20, 900)
        ident_hash = hashlib.sha256(value.lower().encode()).hexdigest()
        rate_limit(con, "login-ident:" + ident_hash, 10, 900)

        row = con.execute(
            """SELECT * FROM users
               WHERE username=? OR email=? OR phone=? LIMIT 1""",
            (bare, email, value)
        ).fetchone()

        if not row or not password_ok(data.password, row["password_hash"]):
            record_security_event(con, "login_failed", ip, row["id"] if row else None)
            con.commit()
            raise HTTPException(401, "Invalid login details.")

        if not (row["email_verified"] or row["phone_verified"]):
            raise HTTPException(403, "Account verification is required.")

        if row["account_status"] in ("banned", "suspended"):
            raise HTTPException(403, "This account is restricted. You may submit an appeal.")

        token = make_session(con, row["id"])
        record_security_event(con, "login_success", ip, row["id"])
        con.commit()
        return {"ok": True, "token": token, "user": public_user(row, private=True)}
    finally:
        con.close()


# =========================================================
# LEGACY AUTH — NO OTP BYPASS
# =========================================================

@app.post("/api/signup")
def old_signup(data: LegacyAuth):
    # Never allow an old endpoint to create unverified accounts.
    raise HTTPException(
        410,
        "This signup endpoint is retired. Use /api/auth/request-code and /api/auth/verify-code."
    )


@app.post("/api/login")
def old_login(data: LegacyAuth, request: Request):
    identifier = data.identifier or data.username or data.email
    if not identifier:
        raise HTTPException(400, "Username, email or phone is required.")
    return auth_login(
        LoginV2(identifier=identifier, password=data.password),
        request
    )


@app.post("/api/logout")
def logout(authorization: Optional[str] = Header(default=None)):
    _, token = current_user(authorization)
    con = db()
    con.execute("DELETE FROM sessions WHERE token=?", (token,))
    con.commit()
    con.close()
    return {"ok": True}


# =========================================================
# PROFILE
# =========================================================

@app.get("/api/me")
def me(authorization: Optional[str] = Header(default=None)):
    user, _ = current_user(authorization)
    con = db()
    followers = con.execute(
        "SELECT COUNT(*) c FROM follows WHERE following_id=?", (user["id"],)
    ).fetchone()["c"]
    following = con.execute(
        "SELECT COUNT(*) c FROM follows WHERE follower_id=?", (user["id"],)
    ).fetchone()["c"]
    con.close()
    return {
        "user": public_user(user, private=True),
        "followers": followers,
        "following": following
    }


@app.patch("/api/me")
def update_me(data: ProfileUpdate, authorization: Optional[str] = Header(default=None)):
    user, _ = current_user(authorization)
    fields, values = [], []

    for field in ("display_name", "bio", "avatar", "is_private"):
        value = getattr(data, field)
        if value is not None:
            fields.append(field + "=?")
            values.append(int(value) if field == "is_private" else value.strip())

    if not fields:
        return {"user": public_user(user, private=True)}

    values.append(user["id"])
    con = db()
    con.execute("UPDATE users SET " + ",".join(fields) + " WHERE id=?", values)
    updated = con.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
    con.commit()
    con.close()
    return {"user": public_user(updated, private=True)}


@app.get("/api/users/{username}")
def get_user(username: str):
    username = (username or "").lstrip("@").lower()
    con = db()
    row = con.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not row:
        con.close()
        raise HTTPException(404, "User not found.")
    followers = con.execute(
        "SELECT COUNT(*) c FROM follows WHERE following_id=?", (row["id"],)
    ).fetchone()["c"]
    following = con.execute(
        "SELECT COUNT(*) c FROM follows WHERE follower_id=?", (row["id"],)
    ).fetchone()["c"]
    con.close()
    return {
        "user": public_user(row),
        "followers": followers,
        "following": following
    }


# =========================================================
# FOLLOW / UNFOLLOW
# =========================================================

@app.post("/api/users/{username}/follow")
def follow(username: str, authorization: Optional[str] = Header(default=None)):
    user, _ = current_user(authorization)
    con = db()
    target = con.execute(
        "SELECT * FROM users WHERE username=?", ((username or "").lstrip("@").lower(),)
    ).fetchone()
    if not target:
        con.close()
        raise HTTPException(404, "User not found.")
    if target["id"] == user["id"]:
        con.close()
        raise HTTPException(400, "You cannot follow yourself.")
    inserted = con.execute(
        "INSERT OR IGNORE INTO follows(follower_id,following_id,created_at) VALUES(?,?,?)",
        (user["id"], target["id"], now())
    ).rowcount
    if inserted:
        con.execute(
            "INSERT INTO notifications(user_id,actor_id,kind,created_at) VALUES(?,?,?,?)",
            (target["id"], user["id"], "follow", now())
        )
    con.commit()
    con.close()
    return {"ok": True, "following": True}


@app.delete("/api/users/{username}/follow")
def unfollow(username: str, authorization: Optional[str] = Header(default=None)):
    user, _ = current_user(authorization)
    con = db()
    target = con.execute(
        "SELECT id FROM users WHERE username=?", ((username or "").lstrip("@").lower(),)
    ).fetchone()
    if not target:
        con.close()
        raise HTTPException(404, "User not found.")
    con.execute(
        "DELETE FROM follows WHERE follower_id=? AND following_id=?",
        (user["id"], target["id"])
    )
    con.commit()
    con.close()
    return {"ok": True, "following": False}


# =========================================================
# POSTS + FEED
# =========================================================

@app.post("/api/posts")
def create_post(data: PostIn, authorization: Optional[str] = Header(default=None)):
    user, _ = current_user(authorization)
    body = data.body.strip()
    if not body:
        raise HTTPException(400, "Post cannot be empty.")
    media_url = (data.media_url or "").strip()
    con = db()
    cur = con.execute(
        "INSERT INTO posts(user_id,body,media_url,created_at) VALUES(?,?,?,?)",
        (user["id"], body, media_url, now())
    )
    post = con.execute(
        """SELECT p.*,u.username,u.display_name,u.avatar,
           0 AS likes,0 AS comments
           FROM posts p JOIN users u ON u.id=p.user_id WHERE p.id=?""",
        (cur.lastrowid,)
    ).fetchone()
    con.commit()
    con.close()
    return {"post": dict(post)}


@app.get("/api/feed")
def feed(authorization: Optional[str] = Header(default=None)):
    user, _ = current_user(authorization)
    con = db()
    rows = con.execute(
        """SELECT p.*,u.username,u.display_name,u.avatar,
           (SELECT COUNT(*) FROM likes l WHERE l.post_id=p.id) AS likes,
           (SELECT COUNT(*) FROM comments c WHERE c.post_id=p.id) AS comments
           FROM posts p JOIN users u ON u.id=p.user_id
           WHERE p.user_id=? OR p.user_id IN
             (SELECT following_id FROM follows WHERE follower_id=?)
           ORDER BY p.id DESC LIMIT 50""",
        (user["id"], user["id"])
    ).fetchall()
    con.close()
    return {"posts": [dict(row) for row in rows]}


@app.post("/api/posts/{post_id}/like")
def like(post_id: int, authorization: Optional[str] = Header(default=None)):
    user, _ = current_user(authorization)
    con = db()
    post = con.execute("SELECT user_id FROM posts WHERE id=?", (post_id,)).fetchone()
    if not post:
        con.close()
        raise HTTPException(404, "Post not found.")
    inserted = con.execute(
        "INSERT OR IGNORE INTO likes(user_id,post_id,created_at) VALUES(?,?,?)",
        (user["id"], post_id, now())
    ).rowcount
    if inserted and post["user_id"] != user["id"]:
        con.execute(
            "INSERT INTO notifications(user_id,actor_id,kind,post_id,created_at) VALUES(?,?,?,?,?)",
            (post["user_id"], user["id"], "like", post_id, now())
        )
    con.commit()
    con.close()
    return {"ok": True, "liked": True}


@app.delete("/api/posts/{post_id}/like")
def unlike(post_id: int, authorization: Optional[str] = Header(default=None)):
    user, _ = current_user(authorization)
    con = db()
    con.execute("DELETE FROM likes WHERE user_id=? AND post_id=?", (user["id"], post_id))
    con.commit()
    con.close()
    return {"ok": True, "liked": False}


@app.post("/api/posts/{post_id}/comments")
def comment(post_id: int, data: CommentIn, authorization: Optional[str] = Header(default=None)):
    user, _ = current_user(authorization)
    body = data.body.strip()
    if not body:
        raise HTTPException(400, "Comment cannot be empty.")
    con = db()
    post = con.execute("SELECT user_id FROM posts WHERE id=?", (post_id,)).fetchone()
    if not post:
        con.close()
        raise HTTPException(404, "Post not found.")
    cur = con.execute(
        "INSERT INTO comments(user_id,post_id,body,created_at) VALUES(?,?,?,?)",
        (user["id"], post_id, body, now())
    )
    if post["user_id"] != user["id"]:
        con.execute(
            "INSERT INTO notifications(user_id,actor_id,kind,post_id,created_at) VALUES(?,?,?,?,?)",
            (post["user_id"], user["id"], "comment", post_id, now())
        )
    result = con.execute(
        """SELECT c.*,u.username,u.display_name,u.avatar
           FROM comments c JOIN users u ON u.id=c.user_id WHERE c.id=?""",
        (cur.lastrowid,)
    ).fetchone()
    con.commit()
    con.close()
    return {"comment": dict(result)}


@app.get("/api/notifications")
def notifications(authorization: Optional[str] = Header(default=None)):
    user, _ = current_user(authorization)
    con = db()
    rows = con.execute(
        """SELECT n.*,u.username,u.display_name,u.avatar
           FROM notifications n LEFT JOIN users u ON u.id=n.actor_id
           WHERE n.user_id=? ORDER BY n.id DESC LIMIT 50""",
        (user["id"],)
    ).fetchall()
    con.close()
    return {"notifications": [dict(row) for row in rows]}


@app.get("/api/search")
def search(q: str = ""):
    q = (q or "").strip().lstrip("@")
    if not q:
        return {"users": []}
    con = db()
    rows = con.execute(
        """SELECT id,username,display_name,bio,avatar,is_private,golden_tick
           FROM users WHERE username LIKE ? OR display_name LIKE ?
           ORDER BY username LIMIT 20""",
        (f"%{q}%", f"%{q}%")
    ).fetchall()
    con.close()
    return {"users": [dict(row) for row in rows]}


# =========================================================
# REPORTS — TRUST SIGNALS + REVIEW PRIORITY
# Report count alone NEVER causes a permanent ban.
# =========================================================

@app.post("/api/reports")
def create_report(data: ReportIn, authorization: Optional[str] = Header(default=None), request: Request = None):
    reporter, _ = current_user(authorization)
    target_name = normalize_username(data.username)
    if target_name == reporter["username"]:
        raise HTTPException(400, "You cannot report your own account.")

    con = db()
    target = con.execute("SELECT id FROM users WHERE username=?", (target_name,)).fetchone()
    if not target:
        con.close()
        raise HTTPException(404, "User not found.")

    if data.post_id is not None:
        post = con.execute("SELECT user_id FROM posts WHERE id=?", (data.post_id,)).fetchone()
        if not post or post["user_id"] != target["id"]:
            con.close()
            raise HTTPException(400, "The selected post does not belong to this user.")

    recent = con.execute(
        """SELECT id FROM moderation_reports
           WHERE reporter_id=? AND target_user_id=?
             AND COALESCE(post_id,0)=COALESCE(?,0) AND created_at>?
           LIMIT 1""",
        (
            reporter["id"], target["id"], data.post_id,
            (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        )
    ).fetchone()
    if recent:
        con.close()
        raise HTTPException(409, "You already reported this item recently.")

    accurate = con.execute(
        "SELECT COUNT(*) c FROM moderation_reports WHERE reporter_id=? AND status='actioned'",
        (reporter["id"],)
    ).fetchone()["c"]
    dismissed = con.execute(
        "SELECT COUNT(*) c FROM moderation_reports WHERE reporter_id=? AND status='dismissed'",
        (reporter["id"],)
    ).fetchone()["c"]
    account_age_days = max(
        0,
        (datetime.now(timezone.utc) - datetime.fromisoformat(reporter["created_at"])).days
    )
    # Bounded reputation score: history helps triage but never proves a report.
    score = max(0, min(100, 10 + min(accurate * 8, 48) + min(account_age_days // 30, 20) - min(dismissed * 10, 40)))
    pending_unique = con.execute(
        """SELECT COUNT(DISTINCT reporter_id) c FROM moderation_reports
           WHERE target_user_id=? AND status IN ('pending','priority_review')
             AND created_at>?""",
        (target["id"], (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat())
    ).fetchone()["c"]
    priority = min(100, score + (20 if pending_unique >= 5 else 0))

    cur = con.execute(
        """INSERT INTO moderation_reports
           (reporter_id,target_user_id,post_id,reason,details,status,reporter_score,priority_score,created_at)
           VALUES(?,?,?,?,?,'pending',?,?,?)""",
        (
            reporter["id"], target["id"], data.post_id,
            data.reason.strip(), data.details.strip(), score, priority, now()
        )
    )
    if pending_unique >= 5:
        con.execute(
            """UPDATE moderation_reports SET status='priority_review'
               WHERE target_user_id=? AND status='pending'""",
            (target["id"],)
        )
    con.commit()
    con.close()
    return {
        "ok": True,
        "report_id": cur.lastrowid,
        "message": "Report received. Report volume raises review priority only; evidence and context determine action."
    }


@app.post("/api/appeals")
def submit_appeal(data: AppealIn, authorization: Optional[str] = Header(default=None)):
    user = appeal_user(authorization)
    con = db()
    pending = con.execute(
        "SELECT id FROM moderation_appeals WHERE user_id=? AND status='pending' LIMIT 1",
        (user["id"],)
    ).fetchone()
    if pending:
        con.close()
        raise HTTPException(409, "You already have a pending appeal.")
    action = con.execute(
        """SELECT id FROM moderation_actions WHERE target_user_id=?
           AND action IN ('temporary_ban','permanent_ban','chat_ban')
           ORDER BY id DESC LIMIT 1""",
        (user["id"],)
    ).fetchone()
    cur = con.execute(
        """INSERT INTO moderation_appeals(user_id,action_id,message,status,created_at)
           VALUES(?,?,?,'pending',?)""",
        (user["id"], action["id"] if action else None, data.message.strip(), now())
    )
    con.commit()
    con.close()
    return {"ok": True, "appeal_id": cur.lastrowid, "status": "pending"}


# =========================================================
# OWNER / ADMIN CONTROL CENTER FOUNDATION
# =========================================================

@app.get("/api/control/status")
def control_status(authorization: Optional[str] = Header(default=None)):
    user, _ = current_user(authorization)
    role = role_for(user)
    return {
        "enabled": role is not None,
        "role": "owner" if role == "owner" else ("admin" if role else "user"),
        "permissions": sorted(CONTROL_PERMISSIONS) if role == "owner" else (role["permissions"] if role else []),
        "ai_configured": False,
        "ai_phase": "reserved_for_final_phase",
        "policy_version": POLICY_VERSION
    }


@app.get("/api/control/overview")
def control_overview(authorization: Optional[str] = Header(default=None)):
    actor, role = require_control(authorization, "dashboard")
    con = db()
    counts = {
        "users": con.execute("SELECT COUNT(*) c FROM users").fetchone()["c"],
        "active_users": con.execute("SELECT COUNT(*) c FROM users WHERE account_status='active'").fetchone()["c"],
        "suspended_users": con.execute("SELECT COUNT(*) c FROM users WHERE account_status='suspended'").fetchone()["c"],
        "banned_users": con.execute("SELECT COUNT(*) c FROM users WHERE account_status='banned'").fetchone()["c"],
        "pending_reports": con.execute("SELECT COUNT(*) c FROM moderation_reports WHERE status IN ('pending','priority_review')").fetchone()["c"],
        "pending_appeals": con.execute("SELECT COUNT(*) c FROM moderation_appeals WHERE status='pending'").fetchone()["c"],
        "golden_ticks": con.execute("SELECT COUNT(*) c FROM users WHERE golden_tick=1").fetchone()["c"]
    }
    con.close()
    return {"ok": True, "role": "owner" if role == "owner" else "admin", "counts": counts}


@app.get("/api/control/config-status")
def control_config_status(authorization: Optional[str] = Header(default=None)):
    require_control(authorization, "dashboard")
    return {
        "owner_configured": bool(OWNER_USERNAME),
        "ai_configured": False,
        "ai_phase": "reserved_for_final_phase",
        "email_configured": bool(os.getenv("SMTP_USERNAME") and os.getenv("SMTP_PASSWORD")),
        "phone_otp_configured": bool(
            os.getenv("TWILIO_API_KEY") and os.getenv("TWILIO_API_SECRET")
            and os.getenv("TWILIO_VERIFY_SERVICE_SID")
        ),
        "ip_blocking_configured": bool(IP_HASH_SECRET),
        "session_days": SESSION_DAYS,
        "otp_minutes": OTP_MINUTES,
        "max_otp_attempts": MAX_OTP_ATTEMPTS,
        "policy_version": POLICY_VERSION
    }


@app.get("/api/control/users")
def control_users(q: str = "", limit: int = 50, authorization: Optional[str] = Header(default=None)):
    require_control(authorization, "users_read")
    limit = max(1, min(limit, 100))
    con = db()
    if q.strip():
        rows = con.execute(
            """SELECT id,username,display_name,created_at,account_status,
               banned_until,golden_tick,email_verified,phone_verified
               FROM users WHERE username LIKE ? OR display_name LIKE ?
               ORDER BY id DESC LIMIT ?""",
            (f"%{q.strip()}%", f"%{q.strip()}%", limit)
        ).fetchall()
    else:
        rows = con.execute(
            """SELECT id,username,display_name,created_at,account_status,
               banned_until,golden_tick,email_verified,phone_verified
               FROM users ORDER BY id DESC LIMIT ?""",
            (limit,)
        ).fetchall()
    con.close()
    return {"users": [dict(row) for row in rows]}


@app.get("/api/control/reports")
def control_reports(status: str = "pending", limit: int = 50, authorization: Optional[str] = Header(default=None)):
    require_control(authorization, "reports_review")
    allowed = {"pending", "priority_review", "reviewed", "dismissed", "actioned", "all"}
    if status not in allowed:
        raise HTTPException(400, "Invalid report status.")
    limit = max(1, min(limit, 100))
    where = "" if status == "all" else "WHERE r.status=?"
    params = () if status == "all" else (status,)
    con = db()
    rows = con.execute(
        """SELECT r.*,reporter.username reporter_username,target.username target_username,
           p.body post_body FROM moderation_reports r
           JOIN users reporter ON reporter.id=r.reporter_id
           JOIN users target ON target.id=r.target_user_id
           LEFT JOIN posts p ON p.id=r.post_id """ + where +
        " ORDER BY r.priority_score DESC,r.id DESC LIMIT ?",
        (*params, limit)
    ).fetchall()
    con.close()
    return {"reports": [dict(row) for row in rows]}


@app.post("/api/control/reports/{report_id}/review")
def review_report(
    report_id: int,
    decision: str,
    note: str = "",
    authorization: Optional[str] = Header(default=None)
):
    actor, role = require_control(authorization, "reports_review")
    decision = decision.strip().lower()
    if decision not in {"actioned", "dismissed", "reviewed"}:
        raise HTTPException(400, "Decision must be actioned, dismissed or reviewed.")
    con = db()
    report = con.execute("SELECT * FROM moderation_reports WHERE id=?", (report_id,)).fetchone()
    if not report:
        con.close()
        raise HTTPException(404, "Report not found.")
    con.execute("UPDATE moderation_reports SET status=? WHERE id=?", (decision, report_id))
    audit(con, actor["id"], "report_" + decision, report["target_user_id"], {
        "report_id": report_id, "note": note[:1000]
    })
    con.commit()
    con.close()
    return {"ok": True, "status": decision}


@app.post("/api/control/users/{user_id}/ban")
def control_ban(
    user_id: int,
    data: BanIn,
    authorization: Optional[str] = Header(default=None)
):
    actor, role = require_control(authorization, "ban_users")
    con = db()
    target = con.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not target:
        con.close()
        raise HTTPException(404, "User not found.")
    if target["id"] == actor["id"] or (
        OWNER_USERNAME and target["username"].lower() == OWNER_USERNAME
    ):
        con.close()
        raise HTTPException(400, "The owner or acting account cannot be banned here.")
    if role != "owner" and data.permanent:
        con.close()
        raise HTTPException(403, "Only the owner can issue permanent bans.")
    if role_for(target):
        con.close()
        raise HTTPException(403, "Remove admin access before moderating an admin account.")

    expiry = None if data.permanent else utc_after(hours=data.duration_hours or 24)
    status = "banned" if data.permanent else "suspended"
    con.execute(
        "UPDATE users SET account_status=?,ban_reason=?,banned_until=? WHERE id=?",
        (status, data.reason.strip(), expiry, user_id)
    )
    cur = con.execute(
        """INSERT INTO moderation_actions
           (target_user_id,actor_id,action,reason,source,expires_at,metadata_json,created_at)
           VALUES(?,?,?,?,?,?,?,?)""",
        (
            user_id, actor["id"],
            "permanent_ban" if data.permanent else "temporary_ban",
            data.reason.strip(), "manual", expiry,
            json.dumps({"duration_hours": data.duration_hours}), now()
        )
    )
    audit(con, actor["id"], "ban", user_id, {
        "permanent": data.permanent, "reason": data.reason[:1000], "expires_at": expiry
    })
    con.commit()
    con.close()
    return {"ok": True, "action_id": cur.lastrowid, "status": status, "banned_until": expiry}


@app.post("/api/control/users/{user_id}/unban")
def control_unban(
    user_id: int,
    note: str = "",
    authorization: Optional[str] = Header(default=None)
):
    actor, role = require_control(authorization, "ban_users")
    con = db()
    target = con.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not target:
        con.close()
        raise HTTPException(404, "User not found.")
    if OWNER_USERNAME and target["username"].lower() == OWNER_USERNAME:
        con.close()
        raise HTTPException(400, "Owner account is protected.")
    con.execute(
        "UPDATE users SET account_status='active',ban_reason='',banned_until=NULL WHERE id=?",
        (user_id,)
    )
    con.execute(
        """INSERT INTO moderation_actions
           (target_user_id,actor_id,action,reason,source,created_at)
           VALUES(?,?, 'unban',?,'manual',?)""",
        (user_id, actor["id"], (note or "Ban removed")[:1000], now())
    )
    audit(con, actor["id"], "unban", user_id, {"note": note[:1000]})
    con.commit()
    con.close()
    return {"ok": True, "status": "active"}


@app.get("/api/control/appeals")
def control_appeals(status: str = "pending", limit: int = 50, authorization: Optional[str] = Header(default=None)):
    require_control(authorization, "appeals_review")
    if status not in {"pending", "approved", "rejected", "all"}:
        raise HTTPException(400, "Invalid appeal status.")
    limit = max(1, min(limit, 100))
    where = "" if status == "all" else "WHERE a.status=?"
    params = () if status == "all" else (status,)
    con = db()
    rows = con.execute(
        """SELECT a.*,u.username,u.account_status,u.banned_until
           FROM moderation_appeals a JOIN users u ON u.id=a.user_id """ +
        where + " ORDER BY a.id DESC LIMIT ?",
        (*params, limit)
    ).fetchall()
    con.close()
    return {"appeals": [dict(row) for row in rows]}


@app.post("/api/control/appeals/{appeal_id}/review")
def review_appeal(
    appeal_id: int,
    data: AppealReviewIn,
    authorization: Optional[str] = Header(default=None)
):
    actor, role = require_control(authorization, "appeals_review")
    decision = data.decision.strip().lower()
    if decision not in {"approve", "reject"}:
        raise HTTPException(400, "Decision must be approve or reject.")
    con = db()
    appeal = con.execute("SELECT * FROM moderation_appeals WHERE id=?", (appeal_id,)).fetchone()
    if not appeal:
        con.close()
        raise HTTPException(404, "Appeal not found.")
    if appeal["status"] != "pending":
        con.close()
        raise HTTPException(409, "Appeal already reviewed.")
    status = "approved" if decision == "approve" else "rejected"
    con.execute(
        "UPDATE moderation_appeals SET status=?,reviewed_by=?,reviewed_at=? WHERE id=?",
        (status, actor["id"], now(), appeal_id)
    )
    if decision == "approve":
        con.execute(
            "UPDATE users SET account_status='active',ban_reason='',banned_until=NULL WHERE id=?",
            (appeal["user_id"],)
        )
        con.execute(
            """INSERT INTO moderation_actions
               (target_user_id,actor_id,action,reason,source,created_at)
               VALUES(?,?, 'appeal_unban',?,'appeal',?)""",
            (appeal["user_id"], actor["id"], data.note[:1000] or "Appeal approved", now())
        )
    audit(con, actor["id"], "appeal_" + decision, appeal["user_id"], {
        "appeal_id": appeal_id, "note": data.note[:1000]
    })
    con.commit()
    con.close()
    return {"ok": True, "status": status}


@app.put("/api/control/admins")
def grant_admin(data: AdminGrantIn, authorization: Optional[str] = Header(default=None)):
    actor, role = require_control(authorization, owner_only=True)
    username = normalize_username(data.username)
    permissions = sorted(set(data.permissions) & CONTROL_PERMISSIONS)
    if not permissions:
        raise HTTPException(400, "Choose at least one valid permission.")
    con = db()
    target = con.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not target:
        con.close()
        raise HTTPException(404, "User not found.")
    if OWNER_USERNAME and username == OWNER_USERNAME:
        con.close()
        raise HTTPException(400, "Owner does not need an admin role.")
    con.execute(
        """INSERT INTO admin_roles(user_id,permissions_json,granted_by,created_at)
           VALUES(?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET
           permissions_json=excluded.permissions_json,
           granted_by=excluded.granted_by,created_at=excluded.created_at""",
        (target["id"], json.dumps(permissions), actor["id"], now())
    )
    audit(con, actor["id"], "grant_admin", target["id"], {"permissions": permissions})
    con.commit()
    con.close()
    return {"ok": True, "username": username, "permissions": permissions}


@app.delete("/api/control/admins/{username}")
def revoke_admin(username: str, authorization: Optional[str] = Header(default=None)):
    actor, role = require_control(authorization, owner_only=True)
    username = normalize_username(username)
    con = db()
    target = con.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    if not target:
        con.close()
        raise HTTPException(404, "User not found.")
    con.execute("DELETE FROM admin_roles WHERE user_id=?", (target["id"],))
    audit(con, actor["id"], "revoke_admin", target["id"], {})
    con.commit()
    con.close()
    return {"ok": True, "username": username, "admin_access": False}


@app.put("/api/control/users/{user_id}/golden-tick")
def set_golden_tick(
    user_id: int,
    data: GoldenTickIn,
    authorization: Optional[str] = Header(default=None)
):
    actor, role = require_control(authorization, "verification_manage", owner_only=True)
    con = db()
    target = con.execute("SELECT id,username FROM users WHERE id=?", (user_id,)).fetchone()
    if not target:
        con.close()
        raise HTTPException(404, "User not found.")
    con.execute(
        "UPDATE users SET golden_tick=?,verification_status=? WHERE id=?",
        (int(data.enabled), "verified" if data.enabled else "revoked", user_id)
    )
    audit(con, actor["id"], "golden_tick", user_id, {"enabled": data.enabled, "note": data.note[:1000]})
    con.commit()
    con.close()
    return {"ok": True, "username": target["username"], "golden_tick": data.enabled}


@app.post("/api/control/users/{user_id}/chat-ban")
def set_chat_ban(
    user_id: int,
    data: ChatBanIn,
    authorization: Optional[str] = Header(default=None)
):
    actor, role = require_control(authorization, "chat_restrictions")
    con = db()
    target = con.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not target:
        con.close()
        raise HTTPException(404, "User not found.")
    if role != "owner" and role_for(target):
        con.close()
        raise HTTPException(403, "Admins cannot be moderated through this endpoint.")
    expiry = utc_after(hours=data.hours)
    con.execute("UPDATE users SET chat_banned_until=? WHERE id=?", (expiry, user_id))
    cur = con.execute(
        """INSERT INTO moderation_actions
           (target_user_id,actor_id,action,reason,source,expires_at,created_at)
           VALUES(?,?, 'chat_ban',?,'manual',?,?)""",
        (user_id, actor["id"], data.reason[:1000], expiry, now())
    )
    audit(con, actor["id"], "chat_ban", user_id, {"expires_at": expiry, "reason": data.reason})
    con.commit()
    con.close()
    return {"ok": True, "action_id": cur.lastrowid, "chat_banned_until": expiry}


@app.post("/api/control/ip-blocks")
def block_ip(
    ip: str,
    reason: str = "Suspicious activity",
    hours: int = 24,
    authorization: Optional[str] = Header(default=None)
):
    actor, role = require_control(authorization, "security_events", owner_only=True)
    if not IP_HASH_SECRET:
        raise HTTPException(503, "Set ZIVAN_IP_HASH_SECRET in Render before enabling IP blocks.")
    if hours < 1 or hours > 8760:
        raise HTTPException(400, "Hours must be between 1 and 8760.")
    digest = ip_digest(ip.strip())
    con = db()
    con.execute(
        """INSERT INTO ip_blocks(ip_hash,reason,expires_at,created_by,created_at)
           VALUES(?,?,?,?,?) ON CONFLICT(ip_hash) DO UPDATE SET
           reason=excluded.reason,expires_at=excluded.expires_at,
           created_by=excluded.created_by,created_at=excluded.created_at""",
        (digest, reason[:1000], utc_after(hours=hours), actor["id"], now())
    )
    audit(con, actor["id"], "ip_block", None, {"ip_hash": digest, "hours": hours, "reason": reason[:1000]})
    con.commit()
    con.close()
    return {"ok": True, "expires_at": utc_after(hours=hours)}


@app.delete("/api/control/ip-blocks")
def unblock_ip(
    ip: str,
    authorization: Optional[str] = Header(default=None)
):
    actor, role = require_control(authorization, "security_events", owner_only=True)
    if not IP_HASH_SECRET:
        raise HTTPException(503, "Set ZIVAN_IP_HASH_SECRET in Render first.")
    digest = ip_digest(ip.strip())
    con = db()
    con.execute("DELETE FROM ip_blocks WHERE ip_hash=?", (digest,))
    audit(con, actor["id"], "ip_unblock", None, {"ip_hash": digest})
    con.commit()
    con.close()
    return {"ok": True}


@app.get("/api/control/security-events")
def security_events(
    limit: int = 100,
    authorization: Optional[str] = Header(default=None)
):
    require_control(authorization, "security_events")
    limit = max(1, min(limit, 200))
    con = db()
    rows = con.execute(
        """SELECT id,event,user_id,ip_hash,details_json,created_at
           FROM security_events ORDER BY id DESC LIMIT ?""",
        (limit,)
    ).fetchall()
    con.close()
    return {"events": [dict(row) for row in rows]}


@app.get("/api/control/audit")
def audit_logs(limit: int = 100, authorization: Optional[str] = Header(default=None)):
    require_control(authorization, "dashboard")
    limit = max(1, min(limit, 200))
    con = db()
    rows = con.execute(
        """SELECT a.*,actor.username actor_username,target.username target_username
           FROM admin_audit_logs a
           LEFT JOIN users actor ON actor.id=a.actor_id
           LEFT JOIN users target ON target.id=a.target_user_id
           ORDER BY a.id DESC LIMIT ?""",
        (limit,)
    ).fetchall()
    con.close()
    return {"events": [dict(row) for row in rows]}


@app.get("/api/control/settings")
def list_settings(authorization: Optional[str] = Header(default=None)):
    require_control(authorization, "settings_manage")
    con = db()
    rows = con.execute("SELECT setting_key,setting_value,updated_at FROM app_settings ORDER BY setting_key").fetchall()
    con.close()
    return {"settings": [dict(row) for row in rows]}


@app.put("/api/control/settings/{key}")
def update_setting(
    key: str,
    data: SettingIn,
    authorization: Optional[str] = Header(default=None)
):
    actor, role = require_control(authorization, "settings_manage")
    if not re.fullmatch(r"[a-z][a-z0-9_.-]{1,80}", key):
        raise HTTPException(400, "Invalid setting key.")
    # Sensitive security settings are owner-only.
    if key.startswith(("security.", "auth.", "owner.", "moderation.permanent_ban")) and role != "owner":
        raise HTTPException(403, "Only the owner can change this setting.")
    con = db()
    con.execute(
        """INSERT INTO app_settings(setting_key,setting_value,updated_by,updated_at)
           VALUES(?,?,?,?) ON CONFLICT(setting_key) DO UPDATE SET
           setting_value=excluded.setting_value,updated_by=excluded.updated_by,
           updated_at=excluded.updated_at""",
        (key, data.value, actor["id"], now())
    )
    audit(con, actor["id"], "setting_update", None, {"key": key})
    con.commit()
    con.close()
    return {"ok": True, "key": key, "updated": True}


# =========================================================
# FUTURE AI EXTENSION POINT
# =========================================================
# No AI agent is activated in this phase.
# Final phase will add an authenticated owner chat, a safe tool registry,
# per-action confirmation, scoped permissions, tests, audit events and rollback.
# Do not give an AI provider raw passwords, OTPs, tokens or unrestricted DB access.
