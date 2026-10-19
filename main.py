import os
import re
import json
import hmac
import uuid
import hashlib
import secrets
import sqlite3
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import (
FastAPI, Request, HTTPException, Depends,
UploadFile, File, Form
)
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

#=========================================================

#ZIVAN BACKEND CONFIGURATION#

=========================================================

APP_NAME = "ZIVAN"
APP_VERSION = "0.2.0"

BASE_DIR = Path(file).resolve().parent
MEDIA_DIR = Path(os.getenv("ZIVAN_MEDIA_DIR", str(BASE_DIR / "media")))
MEDIA_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = os.getenv("ZIVAN_DB", str(BASE_DIR / "zivan.db"))
SESSION_DAYS = 30
MIN_AGE = 13
MAX_UPLOAD_BYTES = 25 * 1024 * 1024

app = FastAPI(
title="ZIVAN API",
version=APP_VERSION,
description="ZIVAN social platform API",
)

app.mount("/media", StaticFiles(directory=str(MEDIA_DIR)), name="media")

=========================================================

TIME, DATABASE AND SECURITY HELPERS

=========================================================

def utc_now():
return datetime.now(timezone.utc)

def iso_now():
return utc_now().isoformat()

def db():
connection = sqlite3.connect(DB_PATH, timeout=20)
connection.row_factory = sqlite3.Row
connection.execute("PRAGMA foreign_keys = ON")
connection.execute("PRAGMA busy_timeout = 20000")
return connection

def hash_token(token: str) -> str:
return hashlib.sha256(token.encode("utf-8")).hexdigest()

def hash_password(password: str, salt: Optional[bytes] = None) -> str:
salt = salt or secrets.token_bytes(16)
derived = hashlib.scrypt(
password.encode("utf-8"),
salt=salt,
n=2**14,
r=8,
p=1,
dklen=32,
)
return salt.hex() + "$" + derived.hex()

def verify_password(password: str, stored: str) -> bool:
try:
salt_hex, _ = stored.split("$", 1)
candidate = hash_password(password, bytes.fromhex(salt_hex))
return hmac.compare_digest(candidate, stored)
except (ValueError, TypeError):
return False

def clean_username(username: str) -> str:
username = username.strip().lower()
if not re.fullmatch(r"[a-z0-9._]{3,30}", username):
raise HTTPException(
status_code=400,
detail="Username must be 3–30 characters: letters, numbers, dots or underscores.",
)
return username

def clean_text(value: str, maximum: int = 2000) -> str:
value = value.strip()
if not value:
raise HTTPException(status_code=400, detail="This field cannot be empty.")
if len(value) > maximum:
raise HTTPException(status_code=400, detail=f"Maximum length is {maximum} characters.")
return value

def get_dob(value: str) -> datetime:
"""Accept DOB as DD/MM/YYYY; never accept a future birth date."""
try:
dob = datetime.strptime(value.strip(), "%d/%m/%Y")
except (ValueError, AttributeError):
raise HTTPException(status_code=400, detail="Enter date of birth as DD/MM/YYYY.")

today = utc_now().date()  
if dob.date() > today:  
    raise HTTPException(status_code=400, detail="Date of birth cannot be in the future.")  

age = today.year - dob.year - (  
    (today.month, today.day) < (dob.month, dob.day)  
)  
if age < MIN_AGE:  
    raise HTTPException(status_code=403, detail="You must be at least 13 to use ZIVAN.")  

if age > 120:  
    raise HTTPException(status_code=400, detail="Please check your date of birth.")  

return dob

def user_public(row):
if not row:
return None
return {
"id": row["id"],
"full_name": row["full_name"],
"username": row["username"],
"bio": row["bio"],
"avatar_url": row["avatar_url"],
"is_private": bool(row["is_private"]),
"created_at": row["created_at"],
}

=========================================================

DATABASE TABLES

=========================================================

def init_db():
connection = db()
try:
connection.executescript("""
CREATE TABLE IF NOT EXISTS users (
id TEXT PRIMARY KEY,
full_name TEXT NOT NULL,
username TEXT NOT NULL COLLATE NOCASE UNIQUE,
dob TEXT NOT NULL,
email TEXT COLLATE NOCASE UNIQUE,
phone TEXT UNIQUE,
password_hash TEXT NOT NULL,
bio TEXT NOT NULL DEFAULT '',
avatar_url TEXT NOT NULL DEFAULT '',
is_private INTEGER NOT NULL DEFAULT 0,
is_verified INTEGER NOT NULL DEFAULT 0,
is_suspended INTEGER NOT NULL DEFAULT 0,
created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (  
        token_hash TEXT PRIMARY KEY,  
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,  
        expires_at TEXT NOT NULL,  
        created_at TEXT NOT NULL  
    );  

    CREATE TABLE IF NOT EXISTS posts (  
        id TEXT PRIMARY KEY,  
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,  
        caption TEXT NOT NULL DEFAULT '',  
        media_url TEXT NOT NULL DEFAULT '',  
        media_type TEXT NOT NULL DEFAULT 'text',  
        visibility TEXT NOT NULL DEFAULT 'public',  
        created_at TEXT NOT NULL  
    );  

    CREATE TABLE IF NOT EXISTS follows (  
        follower_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,  
        following_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,  
        status TEXT NOT NULL DEFAULT 'accepted',  
        created_at TEXT NOT NULL,  
        PRIMARY KEY (follower_id, following_id),  
        CHECK (follower_id != following_id)  
    );  

    CREATE TABLE IF NOT EXISTS likes (  
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,  
        post_id TEXT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,  
        created_at TEXT NOT NULL,  
        PRIMARY KEY (user_id, post_id)  
    );  

    CREATE TABLE IF NOT EXISTS comments (  
        id TEXT PRIMARY KEY,  
        post_id TEXT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,  
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,  
        body TEXT NOT NULL,  
        created_at TEXT NOT NULL  
    );  

    CREATE TABLE IF NOT EXISTS notifications (  
        id TEXT PRIMARY KEY,  
        recipient_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,  
        actor_id TEXT REFERENCES users(id) ON DELETE SET NULL,  
        kind TEXT NOT NULL,  
        post_id TEXT REFERENCES posts(id) ON DELETE CASCADE,  
        message TEXT NOT NULL,  
        is_read INTEGER NOT NULL DEFAULT 0,  
        created_at TEXT NOT NULL  
    );  

    CREATE TABLE IF NOT EXISTS reports (  
        id TEXT PRIMARY KEY,  
        reporter_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,  
        target_type TEXT NOT NULL,  
        target_id TEXT NOT NULL,  
        reason TEXT NOT NULL,  
        status TEXT NOT NULL DEFAULT 'pending',  
        created_at TEXT NOT NULL  
    );  

    CREATE INDEX IF NOT EXISTS idx_posts_created  
        ON posts(created_at DESC);  
    CREATE INDEX IF NOT EXISTS idx_posts_user  
        ON posts(user_id, created_at DESC);  
    CREATE INDEX IF NOT EXISTS idx_comments_post  
        ON comments(post_id, created_at);  
    CREATE INDEX IF NOT EXISTS idx_notifications_recipient  
        ON notifications(recipient_id, created_at DESC);  
    """)  
    connection.commit()  
finally:  
    connection.close()

init_db()

=========================================================

REQUEST MODELS

=========================================================

class SignupRequest(BaseModel):
full_name: str = Field(min_length=1, max_length=80)
username: str = Field(min_length=3, max_length=30)
dob: str
password: str = Field(min_length=8, max_length=128)
email: Optional[str] = None
phone: Optional[str] = None

class LoginRequest(BaseModel):
identifier: str = Field(min_length=1, max_length=254)
password: str = Field(min_length=8, max_length=128)

class ProfileUpdateRequest(BaseModel):
full_name: Optional[str] = Field(default=None, max_length=80)
bio: Optional[str] = Field(default=None, max_length=300)
avatar_url: Optional[str] = Field(default=None, max_length=1000)
is_private: Optional[bool] = None

class CreatePostRequest(BaseModel):
caption: str = Field(default="", max_length=2200)
media_url: str = Field(default="", max_length=1000)
media_type: str = Field(default="text", max_length=20)
visibility: str = Field(default="public", max_length=20)

class CommentRequest(BaseModel):
body: str = Field(min_length=1, max_length=1000)

class ReportRequest(BaseModel):
target_type: str = Field(min_length=1, max_length=20)
target_id: str = Field(min_length=1, max_length=100)
reason: str = Field(min_length=3, max_length=1000)

=========================================================

AUTHENTICATION HELPERS

=========================================================

def create_session(user_id: str):
raw_token = secrets.token_urlsafe(40)
expires = utc_now() + timedelta(days=SESSION_DAYS)

connection = db()  
try:  
    connection.execute(  
        "INSERT INTO sessions(token_hash, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)",  
        (hash_token(raw_token), user_id, expires.isoformat(), iso_now()),  
    )  
    connection.commit()  
finally:  
    connection.close()  

return raw_token, expires.isoformat()

def get_current_user(request: Request):
authorization = request.headers.get("authorization", "")
token = ""

if authorization.lower().startswith("bearer "):  
    token = authorization[7:].strip()  

if not token:  
    token = request.cookies.get("zivan_session", "")  

if not token:  
    raise HTTPException(status_code=401, detail="Please log in.")  

connection = db()  
try:  
    row = connection.execute("""  
        SELECT users.*  
        FROM sessions  
        JOIN users ON users.id = sessions.user_id  
        WHERE sessions.token_hash = ? AND sessions.expires_at > ?  
    """, (hash_token(token), iso_now())).fetchone()  
finally:  
    connection.close()  

if not row:  
    raise HTTPException(status_code=401, detail="Session expired. Please log in again.")  

if row["is_suspended"]:  
    raise HTTPException(status_code=403, detail="This account is currently restricted.")  

return row

def add_notification(recipient_id, actor_id, kind, message, post_id=None):
if recipient_id == actor_id:
return

connection = db()  
try:  
    connection.execute("""  
        INSERT INTO notifications  
        (id, recipient_id, actor_id, kind, post_id, message, is_read, created_at)  
        VALUES (?, ?, ?, ?, ?, ?, 0, ?)  
    """, (  
        str(uuid.uuid4()), recipient_id, actor_id,  
        kind, post_id, message, iso_now(),  
    ))  
    connection.commit()  
finally:  
    connection.close()

=========================================================

HEALTH CHECK AND BASIC APP ROUTES

=========================================================

@app.get("/")
def home():
index_file = BASE_DIR / "index.html"
if index_file.exists():
return HTMLResponse(index_file.read_text(encoding="utf-8"))
return {
"app": APP_NAME,
"version": APP_VERSION,
"status": "running",
"message": "ZIVAN API is ready",
}

@app.get("/health")
def health():
return {
"ok": True,
"service": APP_NAME,
"version": APP_VERSION,
"time": iso_now(),
}

@app.get("/api/health")
def api_health():
return health()

@app.get("/api")
def api_info():
return {
"name": APP_NAME,
"version": APP_VERSION,
"status": "running",
}

=========================================================

SIGNUP

=========================================================

@app.post("/api/auth/signup")
def signup(data: SignupRequest):
full_name = clean_text(data.full_name, 80)
username = clean_username(data.username)

dob = get_dob(data.dob)  

email = (data.email or "").strip().lower() or None  
phone = (data.phone or "").strip() or None  

# Signup requires exactly one contact method.  
if bool(email) == bool(phone):  
    raise HTTPException(  
        status_code=400,  
        detail="Provide either an email address or a phone number, not both.",  
    )  

if email:  
    if len(email) > 254 or not re.fullmatch(  
        r"[^@\s]+@[^@\s]+\.[^@\s]+", email  
    ):  
        raise HTTPException(status_code=400, detail="Enter a valid email address.")  

if phone:  
    if not re.fullmatch(r"\+?[0-9]{8,15}", phone):  
        raise HTTPException(  
            status_code=400,  
            detail="Enter a valid phone number with country code.",  
        )  

user_id = str(uuid.uuid4())  
password_hash = hash_password(data.password)  

connection = db()  
try:  
    if connection.execute(  
        "SELECT 1 FROM users WHERE username = ? COLLATE NOCASE",  
        (username,),  
    ).fetchone():  
        raise HTTPException(status_code=409, detail="Username is already taken.")  

    if email and connection.execute(  
        "SELECT 1 FROM users WHERE email = ? COLLATE NOCASE",  
        (email,),  
    ).fetchone():  
        raise HTTPException(status_code=409, detail="Email is already registered.")  

    if phone and connection.execute(  
        "SELECT 1 FROM users WHERE phone = ?",  
        (phone,),  
    ).fetchone():  
        raise HTTPException(status_code=409, detail="Phone number is already registered.")  

    connection.execute("""  
        INSERT INTO users (  
            id, full_name, username, dob, email, phone,  
            password_hash, created_at  
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)  
    """, (  
        user_id,  
        full_name,  
        username,  
        dob.strftime("%Y-%m-%d"),  
        email,  
        phone,  
        password_hash,  
        iso_now(),  
    ))  
    connection.commit()  

except sqlite3.IntegrityError:  
    raise HTTPException(status_code=409, detail="Account details are already in use.")  
finally:  
    connection.close()  

token, expires = create_session(user_id)  

return {  
    "ok": True,  
    "message": "Account created.",  
    "token": token,  
    "token_type": "bearer",  
    "expires_at": expires,  
    "user": {  
        "id": user_id,  
        "full_name": full_name,  
        "username": username,  
    },  
}

=========================================================

LOGIN AND LOGOUT

=========================================================

@app.post("/api/auth/login")
def login(data: LoginRequest):
identifier = data.identifier.strip()

connection = db()  
try:  
    user = connection.execute("""  
        SELECT * FROM users  
        WHERE username = ? COLLATE NOCASE  
           OR email = ? COLLATE NOCASE  
           OR phone = ?  
        LIMIT 1  
    """, (identifier, identifier, identifier)).fetchone()  
finally:  
    connection.close()  

if not user or not verify_password(data.password, user["password_hash"]):  
    raise HTTPException(status_code=401, detail="Incorrect login details.")  

if user["is_suspended"]:  
    raise HTTPException(status_code=403, detail="This account is currently restricted.")  

token, expires = create_session(user["id"])  

return {  
    "ok": True,  
    "message": "Logged in successfully.",  
    "token": token,  
    "token_type": "bearer",  
    "expires_at": expires,  
    "user": user_public(user),  
}

@app.post("/api/auth/logout")
def logout(request: Request):
authorization = request.headers.get("authorization", "")
token = ""

if authorization.lower().startswith("bearer "):  
    token = authorization[7:].strip()  

if not token:  
    token = request.cookies.get("zivan_session", "")  

if token:  
    connection = db()  
    try:  
        connection.execute(  
            "DELETE FROM sessions WHERE token_hash = ?",  
            (hash_token(token),),  
        )  
        connection.commit()  
    finally:  
        connection.close()  

response = JSONResponse({"ok": True, "message": "Logged out."})  
response.delete_cookie("zivan_session")  
return response

@app.get("/api/auth/me")
def auth_me(user=Depends(get_current_user)):
return {"ok": True, "user": user_public(user)}

=========================================================

USER PROFILE

=========================================================

@app.get("/api/users/me")
def my_profile(user=Depends(get_current_user)):
connection = db()
try:
followers = connection.execute(
"SELECT COUNT(*) FROM follows WHERE following_id = ? AND status = 'accepted'",
(user["id"],),
).fetchone()[0]

following = connection.execute(  
        "SELECT COUNT(*) FROM follows WHERE follower_id = ? AND status = 'accepted'",  
        (user["id"],),  
    ).fetchone()[0]  

    posts = connection.execute(  
        "SELECT COUNT(*) FROM posts WHERE user_id = ?",  
        (user["id"],),  
    ).fetchone()[0]  
finally:  
    connection.close()  

profile = user_public(user)  
profile.update({  
    "followers_count": followers,  
    "following_count": following,  
    "posts_count": posts,  
    "is_me": True,  
})  
return {"ok": True, "profile": profile}

@app.get("/api/users/{username}")
def get_profile(username: str, request: Request):
username = clean_username(username)
viewer_id = None

authorization = request.headers.get("authorization", "")  
token = authorization[7:].strip() if authorization.lower().startswith("bearer ") else ""  
if not token:  
    token = request.cookies.get("zivan_session", "")  

connection = db()  
try:  
    if token:  
        viewer = connection.execute("""  
            SELECT user_id FROM sessions  
            WHERE token_hash = ? AND expires_at > ?  
        """, (hash_token(token), iso_now())).fetchone()  
        if viewer:  
            viewer_id = viewer["user_id"]  

    profile = connection.execute(  
        "SELECT * FROM users WHERE username = ? COLLATE NOCASE",  
        (username,),  
    ).fetchone()  

    if not profile or profile["is_suspended"]:  
        raise HTTPException(status_code=404, detail="User not found.")  

    user_id = profile["id"]  

    follower_count = connection.execute(  
        "SELECT COUNT(*) FROM follows WHERE following_id = ? AND status = 'accepted'",  
        (user_id,),  
    ).fetchone()[0]  

    following_count = connection.execute(  
        "SELECT COUNT(*) FROM follows WHERE follower_id = ? AND status = 'accepted'",  
        (user_id,),  
    ).fetchone()[0]  

    post_count = connection.execute(  
        "SELECT COUNT(*) FROM posts WHERE user_id = ?",  
        (user_id,),  
    ).fetchone()[0]  

    relation = None  
    if viewer_id and viewer_id != user_id:  
        relation = connection.execute("""  
            SELECT status FROM follows  
            WHERE follower_id = ? AND following_id = ?  
        """, (viewer_id, user_id)).fetchone()  

    follows_status = relation["status"] if relation else None  
    is_me = viewer_id == user_id  

    can_view_posts = (  
        not profile["is_private"]  
        or is_me  
        or follows_status == "accepted"  
    )  

    result = user_public(profile)  
    result.update({  
        "followers_count": follower_count,  
        "following_count": following_count,  
        "posts_count": post_count,  
        "is_me": is_me,  
        "follow_status": follows_status,  
        "can_view_posts": can_view_posts,  
    })  

    return {"ok": True, "profile": result}  

finally:  
    connection.close()

@app.patch("/api/users/me")
def update_profile(data: ProfileUpdateRequest, user=Depends(get_current_user)):
updates = data.model_dump(exclude_unset=True)

if not updates:  
    raise HTTPException(status_code=400, detail="No profile changes supplied.")  

allowed = {"full_name", "bio", "avatar_url", "is_private"}  
if any(key not in allowed for key in updates):  
    raise HTTPException(status_code=400, detail="Invalid profile field.")  

if "full_name" in updates:  
    updates["full_name"] = clean_text(updates["full_name"], 80)  

if "bio" in updates and updates["bio"] is not None:  
    updates["bio"] = updates["bio"].strip()  

if "avatar_url" in updates and updates["avatar_url"] is not None:  
    avatar = updates["avatar_url"].strip()  
    if avatar and not avatar.startswith(("https://", "http://", "/media/")):  
        raise HTTPException(status_code=400, detail="Avatar must use a valid URL.")  
    updates["avatar_url"] = avatar  

if "is_private" in updates:  
    updates["is_private"] = int(bool(updates["is_private"]))  

assignments = ", ".join(f"{key} = ?" for key in updates)  
values = list(updates.values()) + [user["id"]]  

connection = db()  
try:  
    connection.execute(  
        f"UPDATE users SET {assignments} WHERE id = ?",  
        values,  
    )  
    connection.commit()  

    updated = connection.execute(  
        "SELECT * FROM users WHERE id = ?",  
        (user["id"],),  
    ).fetchone()  
finally:  
    connection.close()  

return {"ok": True, "user": user_public(updated)}

=========================================================

FOLLOW AND UNFOLLOW

=========================================================

@app.post("/api/users/{username}/follow")
def follow_user(username: str, user=Depends(get_current_user)):
username = clean_username(username)

connection = db()  
try:  
    target = connection.execute(  
        "SELECT * FROM users WHERE username = ? COLLATE NOCASE",  
        (username,),  
    ).fetchone()  

    if not target or target["is_suspended"]:  
        raise HTTPException(status_code=404, detail="User not found.")  

    if target["id"] == user["id"]:  
        raise HTTPException(status_code=400, detail="You cannot follow yourself.")  

    status = "pending" if target["is_private"] else "accepted"  

    connection.execute("""  
        INSERT INTO follows (follower_id, following_id, status, created_at)  
        VALUES (?, ?, ?, ?)  
        ON CONFLICT(follower_id, following_id)  
        DO UPDATE SET status = excluded.status, created_at = excluded.created_at  
    """, (user["id"], target["id"], status, iso_now()))  
    connection.commit()  

finally:  
    connection.close()  

if status == "accepted":  
    add_notification(  
        target["id"], user["id"], "follow",  
        f"@{user['username']} started following you.",  
    )  
    message = "Now following."  
else:  
    add_notification(  
        target["id"], user["id"], "follow_request",  
        f"@{user['username']} requested to follow you.",  
    )  
    message = "Follow request sent."  

return {"ok": True, "status": status, "message": message}

@app.delete("/api/users/{username}/follow")
def unfollow_user(username: str, user=Depends(get_current_user)):
username = clean_username(username)

connection = db()  
try:  
    target = connection.execute(  
        "SELECT id FROM users WHERE username = ? COLLATE NOCASE",  
        (username,),  
    ).fetchone()  

    if not target:  
        raise HTTPException(status_code=404, detail="User not found.")  

    connection.execute("""  
        DELETE FROM follows  
        WHERE follower_id = ? AND following_id = ?  
    """, (user["id"], target["id"]))  
    connection.commit()  
finally:  
    connection.close()  

return {"ok": True, "message": "Follow removed."}

@app.get("/api/users/{username}/followers")
def list_followers(username: str, user=Depends(get_current_user)):
username = clean_username(username)
connection = db()
try:
target = connection.execute(
"SELECT * FROM users WHERE username = ? COLLATE NOCASE",
(username,),
).fetchone()

if not target:  
        raise HTTPException(status_code=404, detail="User not found.")  

    if target["is_private"] and target["id"] != user["id"]:  
        accepted = connection.execute("""  
            SELECT 1 FROM follows  
            WHERE follower_id = ? AND following_id = ? AND status = 'accepted'  
        """, (user["id"], target["id"])).fetchone()  
        if not accepted:  
            raise HTTPException(status_code=403, detail="This profile is private.")  

    rows = connection.execute("""  
        SELECT users.* FROM follows  
        JOIN users ON users.id = follows.follower_id  
        WHERE follows.following_id = ? AND follows.status = 'accepted'  
        ORDER BY follows.created_at DESC  
    """, (target["id"],)).fetchall()  

    return {"ok": True, "users": [user_public(row) for row in rows]}  
finally:  
    connection.close()

@app.get("/api/users/{username}/following")
def list_following(username: str, user=Depends(get_current_user)):
username = clean_username(username)
connection = db()
try:
target = connection.execute(
"SELECT * FROM users WHERE username = ? COLLATE NOCASE",
(username,),
).fetchone()

if not target:  
        raise HTTPException(status_code=404, detail="User not found.")  

    if target["is_private"] and target["id"] != user["id"]:  
        accepted = connection.execute("""  
            SELECT 1 FROM follows  
            WHERE follower_id = ? AND following_id = ? AND status = 'accepted'  
        """, (user["id"], target["id"])).fetchone()  
        if not accepted:  
            raise HTTPException(status_code=403, detail="This profile is private.")  

    rows = connection.execute("""  
        SELECT users.* FROM follows  
        JOIN users ON users.id = follows.following_id  
        WHERE follows.follower_id = ? AND follows.status = 'accepted'  
        ORDER BY follows.created_at DESC  
    """, (target["id"],)).fetchall()  

    return {"ok": True, "users": [user_public(row) for row in rows]}  
finally:  
    connection.close()

=========================================================

PRIVATE ACCOUNT FOLLOW REQUESTS

=========================================================

@app.get("/api/follow-requests")
def list_follow_requests(user=Depends(get_current_user)):
connection = db()
try:
rows = connection.execute("""
SELECT users.id, users.username, users.full_name, users.avatar_url,
follows.created_at
FROM follows
JOIN users ON users.id = follows.follower_id
WHERE follows.following_id = ? AND follows.status = 'pending'
ORDER BY follows.created_at DESC
""", (user["id"],)).fetchall()

return {"ok": True, "requests": [dict(row) for row in rows]}  
finally:  
    connection.close()

@app.post("/api/follow-requests/{requester_id}/accept")
def accept_follow_request(requester_id: str, user=Depends(get_current_user)):
connection = db()
try:
result = connection.execute("""
UPDATE follows SET status = 'accepted'
WHERE follower_id = ? AND following_id = ? AND status = 'pending'
""", (requester_id, user["id"]))

if result.rowcount == 0:  
        raise HTTPException(status_code=404, detail="Follow request not found.")  

    connection.commit()  
finally:  
    connection.close()  

add_notification(  
    requester_id, user["id"], "follow_accepted",  
    f"@{user['username']} accepted your follow request.",  
)  
return {"ok": True, "message": "Follow request accepted."}

@app.delete("/api/follow-requests/{requester_id}")
def reject_follow_request(requester_id: str, user=Depends(get_current_user)):
connection = db()
try:
result = connection.execute("""
DELETE FROM follows
WHERE follower_id = ? AND following_id = ? AND status = 'pending'
""", (requester_id, user["id"]))

if result.rowcount == 0:  
        raise HTTPException(status_code=404, detail="Follow request not found.")  

    connection.commit()  
finally:  
    connection.close()  

return {"ok": True, "message": "Follow request declined."}

=========================================================

POSTS: CREATE, FEED, VIEW AND DELETE

=========================================================

def serialize_post(connection, post, viewer_id=None):
author = connection.execute(
"SELECT * FROM users WHERE id = ?",
(post["user_id"],),
).fetchone()

if not author:  
    return None  

like_count = connection.execute(  
    "SELECT COUNT(*) FROM likes WHERE post_id = ?",  
    (post["id"],),  
).fetchone()[0]  

comment_count = connection.execute(  
    "SELECT COUNT(*) FROM comments WHERE post_id = ?",  
    (post["id"],),  
).fetchone()[0]  

liked = False  
if viewer_id:  
    liked = bool(connection.execute(  
        "SELECT 1 FROM likes WHERE post_id = ? AND user_id = ?",  
        (post["id"], viewer_id),  
    ).fetchone())  

return {  
    "id": post["id"],  
    "caption": post["caption"],  
    "media_url": post["media_url"],  
    "media_type": post["media_type"],  
    "visibility": post["visibility"],  
    "created_at": post["created_at"],  
    "author": user_public(author),  
    "likes_count": like_count,  
    "comments_count": comment_count,  
    "liked_by_me": liked,  
}

def can_view_post(connection, post, viewer_id=None):
author = connection.execute(
"SELECT is_private, is_suspended FROM users WHERE id = ?",
(post["user_id"],),
).fetchone()

if not author or author["is_suspended"]:  
    return False  

if post["visibility"] == "private":  
    return viewer_id == post["user_id"]  

if not author["is_private"] or viewer_id == post["user_id"]:  
    return True  

if not viewer_id:  
    return False  

relation = connection.execute("""  
    SELECT status FROM follows  
    WHERE follower_id = ? AND following_id = ?  
""", (viewer_id, post["user_id"])).fetchone()  

return bool(relation and relation["status"] == "accepted")

@app.post("/api/posts")
def create_post(data: CreatePostRequest, user=Depends(get_current_user)):
caption = (data.caption or "").strip()
media_url = (data.media_url or "").strip()
media_type = (data.media_type or "text").strip().lower()
visibility = (data.visibility or "public").strip().lower()

if len(caption) > 2200:  
    raise HTTPException(status_code=400, detail="Caption is too long.")  

if media_type not in {"text", "image", "video"}:  
    raise HTTPException(status_code=400, detail="Unsupported media type.")  

if visibility not in {"public", "private"}:  
    raise HTTPException(status_code=400, detail="Invalid post visibility.")  

if media_url and not media_url.startswith(("https://", "http://", "/media/")):  
    raise HTTPException(status_code=400, detail="Invalid media URL.")  

if not caption and not media_url:  
    raise HTTPException(status_code=400, detail="Add a caption or media to your post.")  

post_id = str(uuid.uuid4())  
connection = db()  
try:  
    connection.execute("""  
        INSERT INTO posts (  
            id, user_id, caption, media_url,  
            media_type, visibility, created_at  
        ) VALUES (?, ?, ?, ?, ?, ?, ?)  
    """, (  
        post_id, user["id"], caption, media_url,  
        media_type, visibility, iso_now(),  
    ))  
    connection.commit()  

    post = connection.execute(  
        "SELECT * FROM posts WHERE id = ?",  
        (post_id,),  
    ).fetchone()  

    result = serialize_post(connection, post, user["id"])  
finally:  
    connection.close()  

return {"ok": True, "post": result}

@app.get("/api/feed")
def get_feed(
request: Request,
limit: int = 20,
offset: int = 0,
):
limit = max(1, min(limit, 50))
offset = max(0, offset)

viewer_id = None  
authorization = request.headers.get("authorization", "")  
token = (  
    authorization[7:].strip()  
    if authorization.lower().startswith("bearer ")  
    else request.cookies.get("zivan_session", "")  
)  

connection = db()  
try:  
    if token:  
        session = connection.execute("""  
            SELECT user_id FROM sessions  
            WHERE token_hash = ? AND expires_at > ?  
        """, (hash_token(token), iso_now())).fetchone()  

        if session:  
            viewer_id = session["user_id"]  

    rows = connection.execute("""  
        SELECT posts.* FROM posts  
        JOIN users ON users.id = posts.user_id  
        WHERE users.is_suspended = 0  
        ORDER BY posts.created_at DESC  
        LIMIT ? OFFSET ?  
    """, (limit, offset)).fetchall()  

    posts = []  
    for post in rows:  
        if can_view_post(connection, post, viewer_id):  
            item = serialize_post(connection, post, viewer_id)  
            if item:  
                posts.append(item)  

    return {  
        "ok": True,  
        "posts": posts,  
        "limit": limit,  
        "offset": offset,  
    }  
finally:  
    connection.close()

@app.get("/api/posts/{post_id}")
def get_post(post_id: str, request: Request):
viewer_id = None
authorization = request.headers.get("authorization", "")
token = (
authorization[7:].strip()
if authorization.lower().startswith("bearer ")
else request.cookies.get("zivan_session", "")
)

connection = db()  
try:  
    if token:  
        session = connection.execute("""  
            SELECT user_id FROM sessions  
            WHERE token_hash = ? AND expires_at > ?  
        """, (hash_token(token), iso_now())).fetchone()  
        if session:  
            viewer_id = session["user_id"]  

    post = connection.execute(  
        "SELECT * FROM posts WHERE id = ?",  
        (post_id,),  
    ).fetchone()  

    if not post or not can_view_post(connection, post, viewer_id):  
        raise HTTPException(status_code=404, detail="Post not found.")  

    return {  
        "ok": True,  
        "post": serialize_post(connection, post, viewer_id),  
    }  
finally:  
    connection.close()

@app.delete("/api/posts/{post_id}")
def delete_post(post_id: str, user=Depends(get_current_user)):
connection = db()
try:
post = connection.execute(
"SELECT * FROM posts WHERE id = ?",
(post_id,),
).fetchone()

if not post:  
        raise HTTPException(status_code=404, detail="Post not found.")  

    if post["user_id"] != user["id"]:  
        raise HTTPException(status_code=403, detail="You can only delete your own posts.")  

    connection.execute("DELETE FROM posts WHERE id = ?", (post_id,))  
    connection.commit()  
finally:  
    connection.close()  

return {"ok": True, "message": "Post deleted."}

@app.get("/api/users/{username}/posts")
def user_posts(username: str, request: Request, limit: int = 30, offset: int = 0):
username = clean_username(username)
limit = max(1, min(limit, 50))
offset = max(0, offset)

authorization = request.headers.get("authorization", "")  
token = (  
    authorization[7:].strip()  
    if authorization.lower().startswith("bearer ")  
    else request.cookies.get("zivan_session", "")  
)  

viewer_id = None  
connection = db()  
try:  
    if token:  
        session = connection.execute("""  
            SELECT user_id FROM sessions  
            WHERE token_hash = ? AND expires_at > ?  
        """, (hash_token(token), iso_now())).fetchone()  
        if session:  
            viewer_id = session["user_id"]  

    target = connection.execute(  
        "SELECT * FROM users WHERE username = ? COLLATE NOCASE",  
        (username,),  
    ).fetchone()  

    if not target or target["is_suspended"]:  
        raise HTTPException(status_code=404, detail="User not found.")  

    rows = connection.execute("""  
        SELECT * FROM posts WHERE user_id = ?  
        ORDER BY created_at DESC LIMIT ? OFFSET ?  
    """, (target["id"], limit, offset)).fetchall()  

    visible_posts = []  
    for post in rows:  
        if can_view_post(connection, post, viewer_id):  
            visible_posts.append(serialize_post(connection, post, viewer_id))  

    return {"ok": True, "posts": visible_posts}  
finally:  
    connection.close()

=========================================================

LIKES AND COMMENTS

=========================================================

@app.post("/api/posts/{post_id}/like")
def like_post(post_id: str, user=Depends(get_current_user)):
connection = db()
try:
post = connection.execute(
"SELECT * FROM posts WHERE id = ?",
(post_id,),
).fetchone()

if not post or not can_view_post(connection, post, user["id"]):  
        raise HTTPException(status_code=404, detail="Post not found.")  

    connection.execute("""  
        INSERT OR IGNORE INTO likes (user_id, post_id, created_at)  
        VALUES (?, ?, ?)  
    """, (user["id"], post_id, iso_now()))  
    connection.commit()  

    count = connection.execute(  
        "SELECT COUNT(*) FROM likes WHERE post_id = ?",  
        (post_id,),  
    ).fetchone()[0]  
finally:  
    connection.close()  

add_notification(  
    post["user_id"], user["id"], "like",  
    f"@{user['username']} liked your post.", post_id,  
)  

return {"ok": True, "liked": True, "likes_count": count}

@app.delete("/api/posts/{post_id}/like")
def unlike_post(post_id: str, user=Depends(get_current_user)):
connection = db()
try:
post = connection.execute(
"SELECT * FROM posts WHERE id = ?",
(post_id,),
).fetchone()

if not post:  
        raise HTTPException(status_code=404, detail="Post not found.")  

    connection.execute(  
        "DELETE FROM likes WHERE user_id = ? AND post_id = ?",  
        (user["id"], post_id),  
    )  
    connection.commit()  

    count = connection.execute(  
        "SELECT COUNT(*) FROM likes WHERE post_id = ?",  
        (post_id,),  
    ).fetchone()[0]  
finally:  
    connection.close()  

return {"ok": True, "liked": False, "likes_count": count}

@app.post("/api/posts/{post_id}/comments")
def create_comment(post_id: str, data: CommentRequest, user=Depends(get_current_user)):
body = clean_text(data.body, 1000)
comment_id = str(uuid.uuid4())

connection = db()  
try:  
    post = connection.execute(  
        "SELECT * FROM posts WHERE id = ?",  
        (post_id,),  
    ).fetchone()  

    if not post or not can_view_post(connection, post, user["id"]):  
        raise HTTPException(status_code=404, detail="Post not found.")  

    connection.execute("""  
        INSERT INTO comments (id, post_id, user_id, body, created_at)  
        VALUES (?, ?, ?, ?, ?)  
    """, (comment_id, post_id, user["id"], body, iso_now()))  
    connection.commit()  
finally:  
    connection.close()  

add_notification(  
    post["user_id"], user["id"], "comment",  
    f"@{user['username']} commented on your post.", post_id,  
)  

return {  
    "ok": True,  
    "comment": {  
        "id": comment_id,  
        "post_id": post_id,  
        "body": body,  
        "created_at": iso_now(),  
        "author": user_public(user),  
    },  
}

@app.get("/api/posts/{post_id}/comments")
def get_comments(post_id: str, request: Request, limit: int = 50, offset: int = 0):
limit = max(1, min(limit, 100))
offset = max(0, offset)

authorization = request.headers.get("authorization", "")  
token = (  
    authorization[7:].strip()  
    if authorization.lower().startswith("bearer ")  
    else request.cookies.get("zivan_session", "")  
)  

viewer_id = None  
connection = db()  
try:  
    if token:  
        session = connection.execute("""  
            SELECT user_id FROM sessions  
            WHERE token_hash = ? AND expires_at > ?  
        """, (hash_token(token), iso_now())).fetchone()  
        if session:  
            viewer_id = session["user_id"]  

    post = connection.execute(  
        "SELECT * FROM posts WHERE id = ?",  
        (post_id,),  
    ).fetchone()  

    if not post or not can_view_post(connection, post, viewer_id):  
        raise HTTPException(status_code=404, detail="Post not found.")  

    rows = connection.execute("""  
        SELECT comments.*, users.username, users.full_name, users.avatar_url  
        FROM comments  
        JOIN users ON users.id = comments.user_id  
        WHERE comments.post_id = ?  
        ORDER BY comments.created_at ASC  
        LIMIT ? OFFSET ?  
    """, (post_id, limit, offset)).fetchall()  

    return {  
        "ok": True,  
        "comments": [  
            {  
                "id": row["id"],  
                "post_id": row["post_id"],  
                "body": row["body"],  
                "created_at": row["created_at"],  
                "author": {  
                    "id": row["user_id"],  
                    "username": row["username"],  
                    "full_name": row["full_name"],  
                    "avatar_url": row["avatar_url"],  
                },  
            }  
            for row in rows  
        ],  
    }  
finally:  
    connection.close()

@app.delete("/api/comments/{comment_id}")
def delete_comment(comment_id: str, user=Depends(get_current_user)):
connection = db()
try:
comment = connection.execute(
"SELECT * FROM comments WHERE id = ?",
(comment_id,),
).fetchone()

if not comment:  
        raise HTTPException(status_code=404, detail="Comment not found.")  

    post = connection.execute(  
        "SELECT user_id FROM posts WHERE id = ?",  
        (comment["post_id"],),  
    ).fetchone()  

    if comment["user_id"] != user["id"] and (  
        not post or post["user_id"] != user["id"]  
    ):  
        raise HTTPException(  
            status_code=403,  
            detail="You can only delete your own comment or a comment on your post.",  
        )  

    connection.execute("DELETE FROM comments WHERE id = ?", (comment_id,))  
    connection.commit()  
finally:  
    connection.close()  

return {"ok": True, "message": "Comment deleted."}

=========================================================

MEDIA UPLOADS

=========================================================

@app.post("/api/upload")
async def upload_media(
file: UploadFile = File(...),
user=Depends(get_current_user),
):
allowed_types = {
"image/jpeg": ".jpg",
"image/png": ".png",
"image/webp": ".webp",
"image/gif": ".gif",
"video/mp4": ".mp4",
"video/webm": ".webm",
"video/quicktime": ".mov",
}

content_type = (file.content_type or "").lower()  
if content_type not in allowed_types:  
    raise HTTPException(  
        status_code=415,  
        detail="Unsupported file type. Upload an image or video.",  
    )  

data = await file.read(MAX_UPLOAD_BYTES + 1)  
await file.close()  

if not data:  
    raise HTTPException(status_code=400, detail="The uploaded file is empty.")  

if len(data) > MAX_UPLOAD_BYTES:  
    raise HTTPException(status_code=413, detail="File exceeds the 25 MB limit.")  

# Basic file-signature checks to reject obvious mismatches.  
valid = True  
if content_type == "image/jpeg":  
    valid = data.startswith(b"\xff\xd8\xff")  
elif content_type == "image/png":  
    valid = data.startswith(b"\x89PNG\r\n\x1a\n")  
elif content_type == "image/webp":  
    valid = len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP"  
elif content_type == "image/gif":  
    valid = data.startswith((b"GIF87a", b"GIF89a"))  
elif content_type == "video/mp4":  
    valid = len(data) >= 12 and data[4:8] == b"ftyp"  
elif content_type == "video/quicktime":  
    valid = len(data) >= 12 and data[4:8] == b"ftyp"  
elif content_type == "video/webm":  
    valid = data.startswith(b"\x1a\x45\xdf\xa3")  

if not valid:  
    raise HTTPException(status_code=400, detail="The file does not match its claimed type.")  

extension = allowed_types[content_type]  
filename = f"{uuid.uuid4().hex}{extension}"  
destination = MEDIA_DIR / filename  

try:  
    destination.write_bytes(data)  
except OSError:  
    raise HTTPException(  
        status_code=500,  
        detail="Upload storage is unavailable. Please try again later.",  
    )  

return {  
    "ok": True,  
    "url": f"/media/{filename}",  
    "media_type": "video" if content_type.startswith("video/") else "image",  
    "size": len(data),  
}

=========================================================

NOTIFICATIONS

=========================================================

@app.get("/api/notifications")
def get_notifications(user=Depends(get_current_user), limit: int = 30, offset: int = 0):
limit = max(1, min(limit, 100))
offset = max(0, offset)

connection = db()  
try:  
    rows = connection.execute("""  
        SELECT notifications.*,  
               users.username AS actor_username,  
               users.full_name AS actor_full_name,  
               users.avatar_url AS actor_avatar  
        FROM notifications  
        LEFT JOIN users ON users.id = notifications.actor_id  
        WHERE notifications.recipient_id = ?  
        ORDER BY notifications.created_at DESC  
        LIMIT ? OFFSET ?  
    """, (user["id"], limit, offset)).fetchall()  

    unread = connection.execute(  
        "SELECT COUNT(*) FROM notifications WHERE recipient_id = ? AND is_read = 0",  
        (user["id"],),  
    ).fetchone()[0]  

    return {  
        "ok": True,  
        "unread_count": unread,  
        "notifications": [  
            {  
                "id": row["id"],  
                "kind": row["kind"],  
                "message": row["message"],  
                "post_id": row["post_id"],  
                "is_read": bool(row["is_read"]),  
                "created_at": row["created_at"],  
                "actor": (  
                    {  
                        "username": row["actor_username"],  
                        "full_name": row["actor_full_name"],  
                        "avatar_url": row["actor_avatar"],  
                    }  
                    if row["actor_id"] else None  
                ),  
            }  
            for row in rows  
        ],  
    }  
finally:  
    connection.close()

@app.post("/api/notifications/read")
def mark_notifications_read(user=Depends(get_current_user)):
connection = db()
try:
connection.execute(
"UPDATE notifications SET is_read = 1 WHERE recipient_id = ?",
(user["id"],),
)
connection.commit()
finally:
connection.close()

return {"ok": True, "message": "Notifications marked as read."}

@app.post("/api/notifications/{notification_id}/read")
def mark_notification_read(notification_id: str, user=Depends(get_current_user)):
connection = db()
try:
result = connection.execute("""
UPDATE notifications SET is_read = 1
WHERE id = ? AND recipient_id = ?
""", (notification_id, user["id"]))

if result.rowcount == 0:  
        raise HTTPException(status_code=404, detail="Notification not found.")  

    connection.commit()  
finally:  
    connection.close()  

return {"ok": True}

=========================================================

REPORTS AND COMMUNITY SAFETY

=========================================================

@app.post("/api/reports")
def create_report(data: ReportRequest, user=Depends(get_current_user)):
target_type = data.target_type.strip().lower()
target_id = data.target_id.strip()
reason = clean_text(data.reason, 1000)

if target_type not in {"user", "post", "comment"}:  
    raise HTTPException(status_code=400, detail="Invalid report target.")  

connection = db()  
try:  
    if target_type == "user":  
        exists = connection.execute(  
            "SELECT 1 FROM users WHERE id = ?",  
            (target_id,),  
        ).fetchone()  
    elif target_type == "post":  
        exists = connection.execute(  
            "SELECT 1 FROM posts WHERE id = ?",  
            (target_id,),  
        ).fetchone()  
    else:  
        exists = connection.execute(  
            "SELECT 1 FROM comments WHERE id = ?",  
            (target_id,),  
        ).fetchone()  

    if not exists:  
        raise HTTPException(status_code=404, detail="Reported item not found.")  

    report_id = str(uuid.uuid4())  
    connection.execute("""  
        INSERT INTO reports (  
            id, reporter_id, target_type, target_id,  
            reason, status, created_at  
        ) VALUES (?, ?, ?, ?, ?, 'pending', ?)  
    """, (  
        report_id, user["id"], target_type, target_id,  
        reason, iso_now(),  
    ))  
    connection.commit()  
finally:  
    connection.close()  

return {  
    "ok": True,  
    "message": "Report submitted for review.",  
    "report_id": report_id,  
}

=========================================================

ACCOUNT DELETION AND PRIVACY

=========================================================

@app.delete("/api/users/me")
def delete_my_account(user=Depends(get_current_user)):
connection = db()
try:
connection.execute("DELETE FROM users WHERE id = ?", (user["id"],))
connection.commit()
finally:
connection.close()

return {  
    "ok": True,  
    "message": "Your account and associated app records have been deleted.",  
}

@app.get("/api/privacy")
def privacy_policy():
return {
"app": APP_NAME,
"title": "ZIVAN Privacy Principles",
"items": [
"Your date of birth is used for age eligibility and is not shown on your public profile.",
"Never share your password or one-time verification codes.",
"Profile visibility can be controlled using the private-account setting.",
"Posts, comments, follows and notifications are stored to provide app features.",
"Uploaded media is stored by the configured server storage.",
"Report abuse and security concerns through the app's reporting feature.",
"Account deletion removes associated records from the app database.",
"This summary is not a substitute for a complete, legally reviewed privacy policy.",
],
}

@app.get("/api/community-rules")
def community_rules():
return {
"title": "ZIVAN Community Rules",
"rules": [
"Treat other people respectfully.",
"Do not threaten, harass or impersonate others.",
"Do not post illegal content or private information without permission.",
"Do not spam, scam or share harmful links.",
"Report content that appears to break these rules.",
"Moderation decisions should allow appropriate review and appeals.",
],
}

=========================================================

GLOBAL ERROR HANDLING

=========================================================

@app.exception_handler(HTTPException)
async def http_error_handler(request: Request, exc: HTTPException):
return JSONResponse(
status_code=exc.status_code,
content={
"ok": False,
"error": exc.detail,
},
headers=exc.headers,
)

@app.exception_handler(Exception)
async def unexpected_error_handler(request: Request, exc: Exception):
# Avoid returning internal exception details to clients.
return JSONResponse(
status_code=500,
content={
"ok": False,
"error": "An unexpected server error occurred.",
},
)

=========================================================

STARTUP STATUS

=========================================================

@app.on_event("startup")
def startup_status():
init_db()

if name == "main":
import uvicorn
uvicorn.run(
"main:app",
host="0.0.0.0",
port=int(os.getenv("PORT", "8000")),
)
