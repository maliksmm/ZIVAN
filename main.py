import os
import re
import json
import hmac
import base64
import smtplib
import sqlite3
import hashlib
import secrets
import urllib.parse
import urllib.request
import urllib.error
from email.message import EmailMessage
from datetime import datetime, timezone, timedelta, date
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field


# =========================================================
# ZIVAN
# AUTH V2 + SOCIAL FOUNDATION
# =========================================================

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("ZIVAN_DB", BASE_DIR / "zivan.db"))

SESSION_DAYS = 30
OTP_MINUTES = 10
MAX_OTP_ATTEMPTS = 5


app = FastAPI(
    title="ZIVAN API",
    version="0.2.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================================================
# DATABASE
# =========================================================

def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def now():
    return datetime.now(timezone.utc).isoformat()


def session_expiry():
    return (
        datetime.now(timezone.utc)
        + timedelta(days=SESSION_DAYS)
    ).isoformat()


# =========================================================
# SECURITY
# =========================================================

def password_hash(password: str, salt=None):
    salt = salt or secrets.token_bytes(16)

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        310000
    )

    return salt.hex() + "$" + digest.hex()


def password_ok(password: str, stored: str):
    try:
        salt_hex, digest_hex = stored.split("$", 1)

        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            bytes.fromhex(salt_hex),
            310000
        )

        return hmac.compare_digest(
            digest.hex(),
            digest_hex
        )

    except Exception:
        return False


def code_hash(code: str):
    return hashlib.sha256(
        code.encode("utf-8")
    ).hexdigest()


def make_session(con, user_id):
    token = secrets.token_urlsafe(48)

    con.execute(
        """
        INSERT INTO sessions
        (token, user_id, created_at, expires_at)
        VALUES (?, ?, ?, ?)
        """,
        (
            token,
            user_id,
            now(),
            session_expiry()
        )
    )

    return token


# =========================================================
# NORMALIZATION / VALIDATION
# =========================================================

def normalize_email(value):
    return (value or "").strip().lower()


def normalize_username(value):
    username = value.strip().lstrip("@").lower()

    if not re.fullmatch(
        r"[a-z0-9_]{3,30}",
        username
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                "Username must be 3-30 characters "
                "using letters, numbers and underscores."
            )
        )

    return username


def normalize_phone(value):
    phone = (value or "").strip()

    if not phone:
        return ""

    phone = re.sub(
        r"[\s().-]",
        "",
        phone
    )

    if phone.startswith("00"):
        phone = "+" + phone[2:]

    if not phone.startswith("+"):
        raise HTTPException(
            status_code=400,
            detail=(
                "Phone number must include country code, "
                "for example +919876543210."
            )
        )

    if not re.fullmatch(
        r"\+[1-9]\d{7,14}",
        phone
    ):
        raise HTTPException(
            status_code=400,
            detail="Invalid phone number."
        )

    return phone


def validate_dob(value):
    try:
        dob = date.fromisoformat(value)
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="DOB must be in YYYY-MM-DD format."
        )

    today = datetime.now(timezone.utc).date()

    if dob > today:
        raise HTTPException(
            status_code=400,
            detail="DOB cannot be in the future."
        )

    age = (
        today.year
        - dob.year
        - ((today.month, today.day) < (dob.month, dob.day))
    )

    if age < 13:
        raise HTTPException(
            status_code=400,
            detail="ZIVAN is currently 13+."
        )

    if age > 120:
        raise HTTPException(
            status_code=400,
            detail="Please enter a valid DOB."
        )

    return dob.isoformat()


# =========================================================
# EMAIL OTP
# =========================================================

def send_email_code(email, code):

    host = os.getenv(
        "SMTP_HOST",
        "smtp.gmail.com"
    )

    port = int(
        os.getenv(
            "SMTP_PORT",
            "587"
        )
    )

    username = os.getenv(
        "SMTP_USERNAME",
        ""
    )

    password = os.getenv(
        "SMTP_PASSWORD",
        ""
    )

    sender = os.getenv(
        "SMTP_FROM",
        username
    )

    if not username or not password:
        raise RuntimeError(
            "Email verification is not configured."
        )

    message = EmailMessage()

    message["Subject"] = (
        "Your ZIVAN verification code"
    )

    message["From"] = sender
    message["To"] = email

    message.set_content(
        f"""
Your ZIVAN verification code is:

{code}

This code expires in {OTP_MINUTES} minutes.

If you did not request this code,
you can safely ignore this email.
"""
    )

    with smtplib.SMTP(
        host,
        port,
        timeout=20
    ) as server:

        server.ehlo()
        server.starttls()
        server.ehlo()

        server.login(
            username,
            password
        )

        server.send_message(message)


# =========================================================
# TWILIO VERIFY
# =========================================================

def twilio_request(path, form):

    api_key = os.getenv(
        "TWILIO_API_KEY",
        ""
    )

    api_secret = os.getenv(
        "TWILIO_API_SECRET",
        ""
    )

    if not api_key or not api_secret:
        raise RuntimeError(
            "Phone verification is not configured."
        )

    data = urllib.parse.urlencode(
        form
    ).encode("utf-8")

    request = urllib.request.Request(
        "https://verify.twilio.com/v2/"
        + path.lstrip("/"),
        data=data,
        method="POST"
    )

    auth = base64.b64encode(
        f"{api_key}:{api_secret}".encode()
    ).decode()

    request.add_header(
        "Authorization",
        "Basic " + auth
    )

    request.add_header(
        "Content-Type",
        "application/x-www-form-urlencoded"
    )

    try:

        with urllib.request.urlopen(
            request,
            timeout=20
        ) as response:

            return json.loads(
                response.read().decode()
            )

    except urllib.error.HTTPError as exc:

        body = exc.read().decode(
            errors="ignore"
        )

        try:
            data = json.loads(body)
            message = data.get(
                "message",
                "Phone verification failed."
            )
        except Exception:
            message = "Phone verification failed."

        raise RuntimeError(message)

    except Exception as exc:
        raise RuntimeError(str(exc))


def twilio_send(phone):

    service = os.getenv(
        "TWILIO_VERIFY_SERVICE_SID",
        ""
    )

    if not service:
        raise RuntimeError(
            "TWILIO_VERIFY_SERVICE_SID is not configured."
        )

    return twilio_request(
        f"Services/{service}/Verifications",
        {
            "channel": "sms",
            "to": phone
        }
    )


def twilio_check(phone, code):

    service = os.getenv(
        "TWILIO_VERIFY_SERVICE_SID",
        ""
    )

    if not service:
        raise RuntimeError(
            "TWILIO_VERIFY_SERVICE_SID is not configured."
        )

    return twilio_request(
        f"Services/{service}/VerificationCheck",
        {
            "to": phone,
            "code": code
        }
    )


# =========================================================
# DATABASE INITIALIZATION + MIGRATION
# =========================================================

def init_db():

    con = db()

    con.executescript(
        """
        PRAGMA foreign_keys = ON;

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            username TEXT NOT NULL
                UNIQUE COLLATE NOCASE,

            email TEXT
                UNIQUE COLLATE NOCASE,

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

            created_at TEXT NOT NULL
        );


        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,

            user_id INTEGER NOT NULL,

            created_at TEXT NOT NULL,

            expires_at TEXT,

            FOREIGN KEY(user_id)
            REFERENCES users(id)
            ON DELETE CASCADE
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

            created_at TEXT NOT NULL
        );


        CREATE TABLE IF NOT EXISTS follows (

            follower_id INTEGER NOT NULL,

            following_id INTEGER NOT NULL,

            created_at TEXT NOT NULL,

            PRIMARY KEY (
                follower_id,
                following_id
            ),

            CHECK (
                follower_id != following_id
            ),

            FOREIGN KEY(follower_id)
            REFERENCES users(id)
            ON DELETE CASCADE,

            FOREIGN KEY(following_id)
            REFERENCES users(id)
            ON DELETE CASCADE
        );


        CREATE TABLE IF NOT EXISTS posts (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            user_id INTEGER NOT NULL,

            body TEXT NOT NULL,

            media_url TEXT NOT NULL DEFAULT '',

            created_at TEXT NOT NULL,

            FOREIGN KEY(user_id)
            REFERENCES users(id)
            ON DELETE CASCADE
        );


        CREATE TABLE IF NOT EXISTS likes (

            user_id INTEGER NOT NULL,

            post_id INTEGER NOT NULL,

            created_at TEXT NOT NULL,

            PRIMARY KEY (
                user_id,
                post_id
            ),

            FOREIGN KEY(user_id)
            REFERENCES users(id)
            ON DELETE CASCADE,

            FOREIGN KEY(post_id)
            REFERENCES posts(id)
            ON DELETE CASCADE
        );


        CREATE TABLE IF NOT EXISTS comments (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            user_id INTEGER NOT NULL,

            post_id INTEGER NOT NULL,

            body TEXT NOT NULL,

            created_at TEXT NOT NULL,

            FOREIGN KEY(user_id)
            REFERENCES users(id)
            ON DELETE CASCADE,

            FOREIGN KEY(post_id)
            REFERENCES posts(id)
            ON DELETE CASCADE
        );


        CREATE TABLE IF NOT EXISTS notifications (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            user_id INTEGER NOT NULL,

            actor_id INTEGER,

            kind TEXT NOT NULL,

            post_id INTEGER,

            read_at TEXT,

            created_at TEXT NOT NULL,

            FOREIGN KEY(user_id)
            REFERENCES users(id)
            ON DELETE CASCADE,

            FOREIGN KEY(actor_id)
            REFERENCES users(id)
            ON DELETE SET NULL,

            FOREIGN KEY(post_id)
            REFERENCES posts(id)
            ON DELETE CASCADE
        );
        """
    )


    # -----------------------------------------------------
    # MIGRATE EXISTING PHASE-1 USERS
    # -----------------------------------------------------

    user_columns = {
        row["name"]
        for row in con.execute(
            "PRAGMA table_info(users)"
        ).fetchall()
    }

    migrations = {

        "full_name":
            "TEXT NOT NULL DEFAULT ''",

        "dob":
            "TEXT",

        "phone":
            "TEXT",

        "email_verified":
            "INTEGER NOT NULL DEFAULT 0",

        "phone_verified":
            "INTEGER NOT NULL DEFAULT 0",
    }

    for name, definition in migrations.items():

        if name not in user_columns:

            con.execute(
                f"ALTER TABLE users "
                f"ADD COLUMN {name} {definition}"
            )


    session_columns = {
        row["name"]
        for row in con.execute(
            "PRAGMA table_info(sessions)"
        ).fetchall()
    }

    if "expires_at" not in session_columns:

        con.execute(
            "ALTER TABLE sessions "
            "ADD COLUMN expires_at TEXT"
        )


    # Existing Phase-1 email accounts
    # are treated as verified.
    con.execute(
        """
        UPDATE users

        SET full_name =
            CASE
                WHEN full_name IS NULL
                  OR full_name = ''
                THEN display_name
                ELSE full_name
            END

        WHERE full_name IS NULL
           OR full_name = ''
        """
    )

    con.execute(
        """
        UPDATE users

        SET email_verified = 1

        WHERE email IS NOT NULL
          AND email <> ''
          AND email_verified = 0
        """
    )


    # Existing sessions get 30 days.
    con.execute(
        """
        UPDATE sessions

        SET expires_at = ?

        WHERE expires_at IS NULL
           OR expires_at = ''
        """,
        (session_expiry(),)
    )


    con.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS
        idx_users_phone_unique

        ON users(phone)

        WHERE phone IS NOT NULL
          AND phone <> ''
        """
    )

    con.commit()
    con.close()


init_db()


# =========================================================
# REQUEST MODELS
# =========================================================

class SignupStart(BaseModel):

    full_name: str = Field(
        min_length=1,
        max_length=80
    )

    username: str = Field(
        min_length=3,
        max_length=30
    )

    dob: str

    email: Optional[str] = Field(
        default=None,
        max_length=254
    )

    phone: Optional[str] = Field(
        default=None,
        max_length=30
    )

    password: str = Field(
        min_length=8,
        max_length=128
    )

    channel: Optional[str] = None


class VerifyCode(BaseModel):

    challenge_id: str = Field(
        min_length=20,
        max_length=200
    )

    code: str = Field(
        min_length=4,
        max_length=10
    )


class LoginV2(BaseModel):

    identifier: str = Field(
        min_length=1,
        max_length=254
    )

    password: str = Field(
        min_length=8,
        max_length=128
    )


class LegacyAuth(BaseModel):

    username: Optional[str] = None

    email: Optional[str] = None

    identifier: Optional[str] = None

    password: str = Field(
        min_length=8,
        max_length=128
    )


class ProfileUpdate(BaseModel):

    display_name: Optional[str] = Field(
        default=None,
        max_length=80
    )

    bio: Optional[str] = Field(
        default=None,
        max_length=500
    )

    avatar: Optional[str] = Field(
        default=None,
        max_length=500
    )

    is_private: Optional[bool] = None


class PostIn(BaseModel):

    body: str = Field(
        min_length=1,
        max_length=5000
    )

    media_url: Optional[str] = Field(
        default="",
        max_length=2000
    )


class CommentIn(BaseModel):

    body: str = Field(
        min_length=1,
        max_length=1000
    )


# =========================================================
# USER HELPERS
# =========================================================

def public_user(row):

    return {
        "id": row["id"],
        "username": row["username"],
        "display_name": row["display_name"],
        "full_name": row["full_name"],
        "email": row["email"],
        "phone": row["phone"],
        "dob": row["dob"],
        "email_verified": bool(
            row["email_verified"]
        ),
        "phone_verified": bool(
            row["phone_verified"]
        ),
        "bio": row["bio"],
        "avatar": row["avatar"],
        "is_private": bool(
            row["is_private"]
        ),
        "created_at": row["created_at"]
    }


def current_user(
    authorization: Optional[str]
):

    if (
        not authorization
        or not authorization.lower().startswith("bearer ")
    ):
        raise HTTPException(
            status_code=401,
            detail="Authentication required."
        )

    token = authorization.split(
        " ",
        1
    )[1].strip()

    con = db()

    row = con.execute(
        """
        SELECT u.*

        FROM users u

        JOIN sessions s
          ON s.user_id = u.id

        WHERE s.token = ?

        AND (
            s.expires_at IS NULL
            OR s.expires_at > ?
        )
        """,
        (
            token,
            now()
        )
    ).fetchone()

    con.close()

    if not row:

        raise HTTPException(
            status_code=401,
            detail="Invalid or expired session."
        )

    return row, token


# =========================================================
# BASIC
# =========================================================

@app.get("/")
def home():

    return FileResponse(
        BASE_DIR / "index.html"
    )


@app.get("/api/health")
def health():

    return {
        "ok": True,
        "service": "ZIVAN",
        "version": "0.2.0"
    }


@app.get("/api/init-app")
def init_app():

    return {

        "app": "ZIVAN",

        "version": "0.2.0",

        "features": [
            "auth",
            "email_verification",
            "phone_verification",
            "profiles",
            "follow",
            "posts",
            "likes",
            "comments",
            "notifications"
        ]
    }


# =========================================================
# AUTH V2 — REQUEST OTP
# =========================================================

@app.post("/api/auth/request-code")
def request_code(data: SignupStart):

    full_name = data.full_name.strip()

    username = normalize_username(
        data.username
    )

    dob = validate_dob(
        data.dob
    )

    email = normalize_email(
        data.email
    )

    phone = normalize_phone(
        data.phone
    )


    # Email OR phone — exactly one.
    if bool(email) == bool(phone):

        raise HTTPException(
            status_code=400,
            detail="Choose exactly one: email or phone."
        )


    if email:

        if not re.fullmatch(
            r"[^@\s]+@[^@\s]+\.[^@\s]+",
            email
        ):
            raise HTTPException(
                status_code=400,
                detail="Invalid email address."
            )

        channel = "email"

    else:

        channel = "phone"


    con = db()

    existing = con.execute(
        """
        SELECT id

        FROM users

        WHERE username = ?

        OR (
            email IS NOT NULL
            AND email = ?
        )

        OR (
            phone IS NOT NULL
            AND phone = ?
        )
        """,
        (
            username,
            email or None,
            phone or None
        )
    ).fetchone()


    if existing:

        con.close()

        raise HTTPException(
            status_code=409,
            detail=(
                "Username, email or phone "
                "is already registered."
            )
        )


    challenge_id = secrets.token_urlsafe(
        32
    )

    expires_at = (
        datetime.now(timezone.utc)
        + timedelta(minutes=OTP_MINUTES)
    ).isoformat()


    # Email OTP is generated by ZIVAN.
    # Phone OTP is generated by Twilio Verify.
    email_code = None

    if channel == "email":

        email_code = (
            f"{secrets.randbelow(1000000):06d}"
        )


    con.execute(
        """
        INSERT INTO signup_challenges

        (
            id,
            channel,
            destination,
            code_hash,
            expires_at,
            attempts,
            full_name,
            username,
            dob,
            email,
            phone,
            password_hash,
            created_at
        )

        VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            challenge_id,
            channel,
            email or phone,
            code_hash(email_code)
            if email_code else None,
            expires_at,
            full_name,
            username,
            dob,
            email or None,
            phone or None,
            password_hash(
                data.password
            ),
            now()
        )
    )

    con.commit()
    con.close()


    try:

        if channel == "email":

            send_email_code(
                email,
                email_code
            )

        else:

            twilio_send(
                phone
            )

    except Exception as exc:

        con = db()

        con.execute(
            """
            DELETE FROM signup_challenges
            WHERE id = ?
            """,
            (challenge_id,)
        )

        con.commit()
        con.close()

        raise HTTPException(
            status_code=502,
            detail=str(exc)
        )


    return {

        "ok": True,

        "challenge_id":
            challenge_id,

        "channel":
            channel,

        "destination":
            email or phone,

        "expires_in_seconds":
            OTP_MINUTES * 60
    }


# =========================================================
# AUTH V2 — VERIFY OTP + CREATE ACCOUNT
# =========================================================

@app.post("/api/auth/verify-code")
def verify_code(data: VerifyCode):

    con = db()

    challenge = con.execute(
        """
        SELECT *

        FROM signup_challenges

        WHERE id = ?
        """,
        (
            data.challenge_id,
        )
    ).fetchone()


    if not challenge:

        con.close()

        raise HTTPException(
            status_code=404,
            detail="Verification request not found."
        )


    try:

        expires = datetime.fromisoformat(
            challenge["expires_at"]
        )

    except Exception:

        expires = (
            datetime.now(timezone.utc)
            - timedelta(seconds=1)
        )


    if expires <= datetime.now(
        timezone.utc
    ):

        con.execute(
            """
            DELETE FROM signup_challenges
            WHERE id = ?
            """,
            (data.challenge_id,)
        )

        con.commit()
        con.close()

        raise HTTPException(
            status_code=400,
            detail="Verification code expired."
        )


    if challenge["attempts"] >= MAX_OTP_ATTEMPTS:

        con.close()

        raise HTTPException(
            status_code=429,
            detail="Too many verification attempts."
        )


    approved = False

    code = data.code.strip()


    if challenge["channel"] == "email":

        approved = hmac.compare_digest(
            challenge["code_hash"] or "",
            code_hash(code)
        )

    else:

        con.close()

        try:

            result = twilio_check(
                challenge["destination"],
                code
            )

            approved = (
                result.get("status")
                == "approved"
            )

        except Exception as exc:

            raise HTTPException(
                status_code=502,
                detail=str(exc)
            )

        con = db()


    if not approved:

        con.execute(
            """
            UPDATE signup_challenges

            SET attempts = attempts + 1

            WHERE id = ?
            """,
            (
                data.challenge_id,
            )
        )

        con.commit()
        con.close()

        raise HTTPException(
            status_code=400,
            detail="Invalid verification code."
        )


    # Double-check uniqueness.
    existing = con.execute(
        """
        SELECT id

        FROM users

        WHERE username = ?

        OR (
            email IS NOT NULL
            AND email = ?
        )

        OR (
            phone IS NOT NULL
            AND phone = ?
        )
        """,
        (
            challenge["username"],
            challenge["email"],
            challenge["phone"]
        )
    ).fetchone()


    if existing:

        con.execute(
            """
            DELETE FROM signup_challenges
            WHERE id = ?
            """,
            (
                data.challenge_id,
            )
        )

        con.commit()
        con.close()

        raise HTTPException(
            status_code=409,
            detail="Account already exists."
        )


    email_verified = (
        1
        if challenge["channel"] == "email"
        else 0
    )

    phone_verified = (
        1
        if challenge["channel"] == "phone"
        else 0
    )


    cur = con.execute(
        """
        INSERT INTO users

        (
            username,
            email,
            password_hash,
            display_name,
            full_name,
            dob,
            phone,
            email_verified,
            phone_verified,
            created_at
        )

        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            challenge["username"],
            challenge["email"],
            challenge["password_hash"],
            challenge["full_name"],
            challenge["full_name"],
            challenge["dob"],
            challenge["phone"],
            email_verified,
            phone_verified,
            now()
        )
    )


    user_id = cur.lastrowid

    token = make_session(
        con,
        user_id
    )


    row = con.execute(
        """
        SELECT *

        FROM users

        WHERE id = ?
        """,
        (user_id,)
    ).fetchone()


    con.execute(
        """
        DELETE FROM signup_challenges
        WHERE id = ?
        """,
        (
            data.challenge_id,
        )
    )


    con.commit()
    con.close()


    return {

        "ok": True,

        "token": token,

        "user":
            public_user(row)
    }


# =========================================================
# AUTH V2 — LOGIN
# =========================================================

@app.post("/api/auth/login")
def auth_login(data: LoginV2):

    value = data.identifier.strip()

    bare = value.lstrip("@")

    email = normalize_email(
        value
    )


    con = db()

    row = con.execute(
        """
        SELECT *

        FROM users

        WHERE username = ?
           OR email = ?
           OR phone = ?

        LIMIT 1
        """,
        (
            bare,
            email,
            value
        )
    ).fetchone()


    if (
        not row
        or not password_ok(
            data.password,
            row["password_hash"]
        )
    ):

        con.close()

        raise HTTPException(
            status_code=401,
            detail="Invalid login details."
        )


    if not (
        bool(row["email_verified"])
        or bool(row["phone_verified"])
    ):

        con.close()

        raise HTTPException(
            status_code=403,
            detail="Account verification is required."
        )


    token = make_session(
        con,
        row["id"]
    )

    con.commit()
    con.close()


    return {

        "ok": True,

        "token": token,

        "user":
            public_user(row)
    }


# =========================================================
# BACKWARD COMPATIBILITY
# =========================================================

@app.post("/api/signup")
def old_signup(data: LegacyAuth):

    username = normalize_username(
        data.username or ""
    )

    email = normalize_email(
        data.email
    )

    if not email:

        raise HTTPException(
            status_code=400,
            detail="Email is required."
        )


    con = db()

    exists = con.execute(
        """
        SELECT id

        FROM users

        WHERE username = ?
           OR email = ?
        """,
        (
            username,
            email
        )
    ).fetchone()


    if exists:

        con.close()

        raise HTTPException(
            status_code=409,
            detail="Username or email already exists."
        )


    cur = con.execute(
        """
        INSERT INTO users

        (
            username,
            email,
            password_hash,
            display_name,
            full_name,
            email_verified,
            created_at
        )

        VALUES (?, ?, ?, ?, ?, 1, ?)
        """,
        (
            username,
            email,
            password_hash(
                data.password
            ),
            username,
            username,
            now()
        )
    )


    token = make_session(
        con,
        cur.lastrowid
    )


    row = con.execute(
        """
        SELECT *

        FROM users

        WHERE id = ?
        """,
        (cur.lastrowid,)
    ).fetchone()


    con.commit()
    con.close()


    return {
        "token": token,
        "user": public_user(row)
    }


@app.post("/api/login")
def old_login(data: LegacyAuth):

    identifier = (
        data.identifier
        or data.username
        or data.email
    )

    if not identifier:

        raise HTTPException(
            status_code=400,
            detail=(
                "Username, email or phone "
                "is required."
            )
        )

    return auth_login(
        LoginV2(
            identifier=identifier,
            password=data.password
        )
    )


# =========================================================
# LOGOUT
# =========================================================

@app.post("/api/logout")
def logout(
    authorization: Optional[str] =
    Header(default=None)
):

    _, token = current_user(
        authorization
    )

    con = db()

    con.execute(
        """
        DELETE FROM sessions
        WHERE token = ?
        """,
        (token,)
    )

    con.commit()
    con.close()

    return {
        "ok": True
    }


# =========================================================
# PROFILE
# =========================================================

@app.get("/api/me")
def me(
    authorization: Optional[str] =
    Header(default=None)
):

    row, _ = current_user(
        authorization
    )

    con = db()

    followers = con.execute(
        """
        SELECT COUNT(*) c

        FROM follows

        WHERE following_id = ?
        """,
        (row["id"],)
    ).fetchone()["c"]


    following = con.execute(
        """
        SELECT COUNT(*) c

        FROM follows

        WHERE follower_id = ?
        """,
        (row["id"],)
    ).fetchone()["c"]


    con.close()


    return {

        "user":
            public_user(row),

        "followers":
            followers,

        "following":
            following
    }


@app.patch("/api/me")
def update_me(
    data: ProfileUpdate,
    authorization: Optional[str] =
    Header(default=None)
):

    row, _ = current_user(
        authorization
    )

    fields = []
    values = []


    if data.display_name is not None:

        fields.append(
            "display_name = ?"
        )

        values.append(
            data.display_name.strip()
        )


    if data.bio is not None:

        fields.append(
            "bio = ?"
        )

        values.append(
            data.bio.strip()
        )


    if data.avatar is not None:

        fields.append(
            "avatar = ?"
        )

        values.append(
            data.avatar.strip()
        )


    if data.is_private is not None:

        fields.append(
            "is_private = ?"
        )

        values.append(
            int(data.is_private)
        )


    if not fields:

        return {
            "user":
                public_user(row)
        }


    values.append(
        row["id"]
    )

    con = db()

    con.execute(
        "UPDATE users SET "
        + ", ".join(fields)
        + " WHERE id = ?",
        values
    )


    updated = con.execute(
        """
        SELECT *

        FROM users

        WHERE id = ?
        """,
        (row["id"],)
    ).fetchone()


    con.commit()
    con.close()


    return {
        "user":
            public_user(updated)
    }


# =========================================================
# USER / FOLLOW
# =========================================================

@app.get("/api/users/{username}")
def get_user(username: str):

    con = db()

    row = con.execute(
        """
        SELECT *

        FROM users

        WHERE username = ?
        """,
        (username.lstrip("@"),)
    ).fetchone()


    if not row:

        con.close()

        raise HTTPException(
            status_code=404,
            detail="User not found."
        )


    followers = con.execute(
        """
        SELECT COUNT(*) c

        FROM follows

        WHERE following_id = ?
        """,
        (row["id"],)
    ).fetchone()["c"]


    following = con.execute(
        """
        SELECT COUNT(*) c

        FROM follows

        WHERE follower_id = ?
        """,
        (row["id"],)
    ).fetchone()["c"]


    con.close()


    return {

        "user":
            public_user(row),

        "followers":
            followers,

        "following":
            following
    }


@app.post("/api/users/{username}/follow")
def follow(
    username: str,
    authorization: Optional[str] =
    Header(default=None)
):

    me_row, _ = current_user(
        authorization
    )

    con = db()

    target = con.execute(
        """
        SELECT *

        FROM users

        WHERE username = ?
        """,
        (username.lstrip("@"),)
    ).fetchone()


    if not target:

        con.close()

        raise HTTPException(
            status_code=404,
            detail="User not found."
        )


    if target["id"] == me_row["id"]:

        con.close()

        raise HTTPException(
            status_code=400,
            detail="You cannot follow yourself."
        )


    inserted = con.execute(
        """
        INSERT OR IGNORE INTO follows

        (
            follower_id,
            following_id,
            created_at
        )

        VALUES (?, ?, ?)
        """,
        (
            me_row["id"],
            target["id"],
            now()
        )
    ).rowcount


    if inserted:

        con.execute(
            """
            INSERT INTO notifications

            (
                user_id,
                actor_id,
                kind,
                created_at
            )

            VALUES (?, ?, ?, ?)
            """,
            (
                target["id"],
                me_row["id"],
                "follow",
                now()
            )
        )


    con.commit()
    con.close()


    return {
        "ok": True,
        "following": True
    }


@app.delete("/api/users/{username}/follow")
def unfollow(
    username: str,
    authorization: Optional[str] =
    Header(default=None)
):

    me_row, _ = current_user(
        authorization
    )

    con = db()

    target = con.execute(
        """
        SELECT id

        FROM users

        WHERE username = ?
        """,
        (username.lstrip("@"),)
    ).fetchone()


    if not target:

        con.close()

        raise HTTPException(
            status_code=404,
            detail="User not found."
        )


    con.execute(
        """
        DELETE FROM follows

        WHERE follower_id = ?

        AND following_id = ?
        """,
        (
            me_row["id"],
            target["id"]
        )
    )


    con.commit()
    con.close()


    return {
        "ok": True,
        "following": False
    }


# =========================================================
# POSTS
# =========================================================

@app.post("/api/posts")
def create_post(
    data: PostIn,
    authorization: Optional[str] =
    Header(default=None)
):

    row, _ = current_user(
        authorization
    )

    con = db()

    cur = con.execute(
        """
        INSERT INTO posts

        (
            user_id,
            body,
            media_url,
            created_at
        )

        VALUES (?, ?, ?, ?)
        """,
        (
            row["id"],
            data.body.strip(),
            (data.media_url or "").strip(),
            now()
        )
    )


    post = con.execute(
        """
        SELECT
            p.*,
            u.username,
            u.display_name,
            u.avatar

        FROM posts p

        JOIN users u
          ON u.id = p.user_id

        WHERE p.id = ?
        """,
        (cur.lastrowid,)
    ).fetchone()


    con.commit()
    con.close()


    return {
        "post":
            dict(post)
    }


@app.get("/api/feed")
def feed(
    authorization: Optional[str] =
    Header(default=None)
):

    row, _ = current_user(
        authorization
    )

    con = db()

    posts = con.execute(
        """
        SELECT

            p.*,

            u.username,
            u.display_name,
            u.avatar,

            (
                SELECT COUNT(*)

                FROM likes l

                WHERE l.post_id = p.id
            ) AS likes,

            (
                SELECT COUNT(*)

                FROM comments c

                WHERE c.post_id = p.id
            ) AS comments

        FROM posts p

        JOIN users u
          ON u.id = p.user_id

        WHERE

            p.user_id = ?

            OR p.user_id IN (

                SELECT following_id

                FROM follows

                WHERE follower_id = ?
            )

        ORDER BY p.id DESC

        LIMIT 50
        """,
        (
            row["id"],
            row["id"]
        )
    ).fetchall()


    con.close()


    return {
        "posts":
            [dict(x) for x in posts]
    }


# =========================================================
# LIKE
# =========================================================

@app.post("/api/posts/{post_id}/like")
def like(
    post_id: int,
    authorization: Optional[str] =
    Header(default=None)
):

    row, _ = current_user(
        authorization
    )

    con = db()

    post = con.execute(
        """
        SELECT user_id

        FROM posts

        WHERE id = ?
        """,
        (post_id,)
    ).fetchone()


    if not post:

        con.close()

        raise HTTPException(
            status_code=404,
            detail="Post not found."
        )


    inserted = con.execute(
        """
        INSERT OR IGNORE INTO likes

        (
            user_id,
            post_id,
            created_at
        )

        VALUES (?, ?, ?)
        """,
        (
            row["id"],
            post_id,
            now()
        )
    ).rowcount


    if (
        inserted
        and post["user_id"] != row["id"]
    ):

        con.execute(
            """
            INSERT INTO notifications

            (
                user_id,
                actor_id,
                kind,
                post_id,
                created_at
            )

            VALUES (?, ?, ?, ?, ?)
            """,
            (
                post["user_id"],
                row["id"],
                "like",
                post_id,
                now()
            )
        )


    con.commit()
    con.close()


    return {
        "ok": True,
        "liked": True
    }


@app.delete("/api/posts/{post_id}/like")
def unlike(
    post_id: int,
    authorization: Optional[str] =
    Header(default=None)
):

    row, _ = current_user(
        authorization
    )

    con = db()

    con.execute(
        """
        DELETE FROM likes

        WHERE user_id = ?

        AND post_id = ?
        """,
        (
            row["id"],
            post_id
        )
    )

    con.commit()
    con.close()


    return {
        "ok": True,
        "liked": False
    }


# =========================================================
# COMMENTS
# =========================================================

@app.post("/api/posts/{post_id}/comments")
def comment(
    post_id: int,
    data: CommentIn,
    authorization: Optional[str] =
    Header(default=None)
):

    row, _ = current_user(
        authorization
    )

    con = db()

    post = con.execute(
        """
        SELECT user_id

        FROM posts

        WHERE id = ?
        """,
        (post_id,)
    ).fetchone()


    if not post:

        con.close()

        raise HTTPException(
            status_code=404,
            detail="Post not found."
        )


    cur = con.execute(
        """
        INSERT INTO comments

        (
            user_id,
            post_id,
            body,
            created_at
        )

        VALUES (?, ?, ?, ?)
        """,
        (
            row["id"],
            post_id,
            data.body.strip(),
            now()
        )
    )


    if post["user_id"] != row["id"]:

        con.execute(
            """
            INSERT INTO notifications

            (
                user_id,
                actor_id,
                kind,
                post_id,
                created_at
            )

            VALUES (?, ?, ?, ?, ?)
            """,
            (
                post["user_id"],
                row["id"],
                "comment",
                post_id,
                now()
            )
        )


    result = con.execute(
        """
        SELECT

            c.*,

            u.username,
            u.display_name,
            u.avatar

        FROM comments c

        JOIN users u
          ON u.id = c.user_id

        WHERE c.id = ?
        """,
        (cur.lastrowid,)
    ).fetchone()


    con.commit()
    con.close()


    return {
        "comment":
            dict(result)
    }


# =========================================================
# NOTIFICATIONS
# =========================================================

@app.get("/api/notifications")
def notifications(
    authorization: Optional[str] =
    Header(default=None)
):

    row, _ = current_user(
        authorization
    )

    con = db()

    items = con.execute(
        """
        SELECT

            n.*,

            u.username,
            u.display_name,
            u.avatar

        FROM notifications n

        LEFT JOIN users u
          ON u.id = n.actor_id

        WHERE n.user_id = ?

        ORDER BY n.id DESC

        LIMIT 50
        """,
        (row["id"],)
    ).fetchall()


    con.close()


    return {
        "notifications":
            [dict(x) for x in items]
    }


# =========================================================
# SEARCH
# =========================================================

@app.get("/api/search")
def search(q: str = ""):

    q = q.strip().lstrip("@")

    if not q:

        return {
            "users": []
        }


    con = db()

    rows = con.execute(
        """
        SELECT

            id,
            username,
            display_name,
            bio,
            avatar,
            is_private

        FROM users

        WHERE

            username LIKE ?

            OR display_name LIKE ?

        ORDER BY username

        LIMIT 20
        """,
        (
            f"%{q}%",
            f"%{q}%"
        )
    ).fetchall()


    con.close()


    return {
        "users":
            [dict(x) for x in rows]
    }
