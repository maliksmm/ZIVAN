import os
import sqlite3
import hashlib
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("ZIVAN_DB", BASE_DIR / "zivan.db"))

app = FastAPI(title="ZIVAN API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def now():
    return datetime.now(timezone.utc).isoformat()


def init_db():
    con = db()

    con.executescript("""
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE COLLATE NOCASE,
        email TEXT NOT NULL UNIQUE COLLATE NOCASE,
        password_hash TEXT NOT NULL,
        display_name TEXT NOT NULL,
        bio TEXT NOT NULL DEFAULT '',
        avatar TEXT NOT NULL DEFAULT '',
        is_private INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS follows (
        follower_id INTEGER NOT NULL,
        following_id INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY (follower_id, following_id),
        CHECK (follower_id != following_id),
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
        PRIMARY KEY (user_id, post_id),
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
    """)

    con.commit()
    con.close()


init_db()


class AuthIn(BaseModel):
    username: str = Field(min_length=3, max_length=30)
    password: str = Field(min_length=8, max_length=128)
    email: Optional[str] = Field(default=None, max_length=254)


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


def password_hash(password: str, salt: Optional[bytes] = None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        310000
    )
    return salt.hex() + "$" + digest.hex()


def password_ok(password: str, stored: str):
    try:
        salt_hex, digest_hex = stored.split("$", 1)

        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            bytes.fromhex(salt_hex),
            310000
        )

        return secrets.compare_digest(digest.hex(), digest_hex)

    except Exception:
        return False


def public_user(row):
    return {
        "id": row["id"],
        "username": row["username"],
        "display_name": row["display_name"],
        "bio": row["bio"],
        "avatar": row["avatar"],
        "is_private": bool(row["is_private"]),
        "created_at": row["created_at"],
    }


def current_user(authorization: Optional[str]):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=401,
            detail="Authentication required."
        )

    token = authorization.split(" ", 1)[1].strip()

    con = db()

    row = con.execute(
        """
        SELECT u.*
        FROM users u
        JOIN sessions s ON s.user_id = u.id
        WHERE s.token = ?
        """,
        (token,)
    ).fetchone()

    con.close()

    if not row:
        raise HTTPException(
            status_code=401,
            detail="Invalid session."
        )

    return row, token


@app.get("/")
def home():
    return FileResponse(BASE_DIR / "index.html")


@app.get("/api/health")
def health():
    return {
        "ok": True,
        "service": "ZIVAN",
        "version": "0.1.0"
    }


@app.get("/api/init-app")
def init_app():
    return {
        "app": "ZIVAN",
        "version": "0.1.0",
        "panels": [
            {
                "id": "zivan",
                "name": "ZIVAN"
            }
        ],
        "features": [
            "auth",
            "profiles",
            "follow",
            "posts",
            "likes",
            "comments",
            "notifications"
        ]
    }


@app.post("/api/signup")
def signup(data: AuthIn):

    username = data.username.strip().lstrip("@")
    email = (data.email or "").strip().lower()

    if not email:
        raise HTTPException(
            status_code=400,
            detail="Email is required."
        )

    if not username.replace("_", "").isalnum():
        raise HTTPException(
            status_code=400,
            detail="Username can use letters, numbers and underscores only."
        )

    con = db()

    exists = con.execute(
        """
        SELECT id
        FROM users
        WHERE username = ? OR email = ? COLLATE NOCASE
        """,
        (username, email)
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
        (username, email, password_hash, display_name, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            username,
            email,
            password_hash(data.password),
            username,
            now()
        )
    )

    user_id = cur.lastrowid

    token = secrets.token_urlsafe(48)

    con.execute(
        """
        INSERT INTO sessions
        (token, user_id, created_at)
        VALUES (?, ?, ?)
        """,
        (token, user_id, now())
    )

    row = con.execute(
        "SELECT * FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()

    con.commit()
    con.close()

    return {
        "token": token,
        "user": public_user(row)
    }


@app.post("/api/login")
def login(data: AuthIn):

    username = data.username.strip().lstrip("@")

    con = db()

    row = con.execute(
        """
        SELECT *
        FROM users
        WHERE username = ? COLLATE NOCASE
        """,
        (username,)
    ).fetchone()

    if not row or not password_ok(
        data.password,
        row["password_hash"]
    ):
        con.close()
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password."
        )

    token = secrets.token_urlsafe(48)

    con.execute(
        """
        INSERT INTO sessions
        (token, user_id, created_at)
        VALUES (?, ?, ?)
        """,
        (token, row["id"], now())
    )

    con.commit()
    con.close()

    return {
        "token": token,
        "user": public_user(row)
    }


@app.post("/api/logout")
def logout(
    authorization: Optional[str] = Header(default=None)
):
    _, token = current_user(authorization)

    con = db()

    con.execute(
        "DELETE FROM sessions WHERE token = ?",
        (token,)
    )

    con.commit()
    con.close()

    return {"ok": True}


@app.get("/api/me")
def me(
    authorization: Optional[str] = Header(default=None)
):
    row, _ = current_user(authorization)

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
        "user": public_user(row),
        "followers": followers,
        "following": following
    }


@app.patch("/api/me")
def update_me(
    data: ProfileUpdate,
    authorization: Optional[str] = Header(default=None)
):
    row, _ = current_user(authorization)

    fields = []
    values = []

    if data.display_name is not None:
        fields.append("display_name = ?")
        values.append(data.display_name.strip())

    if data.bio is not None:
        fields.append("bio = ?")
        values.append(data.bio.strip())

    if data.avatar is not None:
        fields.append("avatar = ?")
        values.append(data.avatar.strip())

    if data.is_private is not None:
        fields.append("is_private = ?")
        values.append(int(data.is_private))

    if not fields:
        return {
            "user": public_user(row)
        }

    values.append(row["id"])

    con = db()

    con.execute(
        "UPDATE users SET " +
        ", ".join(fields) +
        " WHERE id = ?",
        values
    )

    updated = con.execute(
        "SELECT * FROM users WHERE id = ?",
        (row["id"],)
    ).fetchone()

    con.commit()
    con.close()

    return {
        "user": public_user(updated)
    }


@app.get("/api/users/{username}")
def get_user(username: str):

    con = db()

    row = con.execute(
        """
        SELECT *
        FROM users
        WHERE username = ? COLLATE NOCASE
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
        "user": public_user(row),
        "followers": followers,
        "following": following
    }


@app.post("/api/users/{username}/follow")
def follow(
    username: str,
    authorization: Optional[str] = Header(default=None)
):
    me_row, _ = current_user(authorization)

    con = db()

    target = con.execute(
        """
        SELECT *
        FROM users
        WHERE username = ? COLLATE NOCASE
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

    con.execute(
        """
        INSERT OR IGNORE INTO follows
        (follower_id, following_id, created_at)
        VALUES (?, ?, ?)
        """,
        (
            me_row["id"],
            target["id"],
            now()
        )
    )

    con.execute(
        """
        INSERT INTO notifications
        (user_id, actor_id, kind, created_at)
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
    authorization: Optional[str] = Header(default=None)
):
    me_row, _ = current_user(authorization)

    con = db()

    target = con.execute(
        """
        SELECT id
        FROM users
        WHERE username = ? COLLATE NOCASE
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


@app.post("/api/posts")
def create_post(
    data: PostIn,
    authorization: Optional[str] = Header(default=None)
):
    row, _ = current_user(authorization)

    con = db()

    cur = con.execute(
        """
        INSERT INTO posts
        (user_id, body, media_url, created_at)
        VALUES (?, ?, ?, ?)
        """,
        (
            row["id"],
            data.body.strip(),
            (data.media_url or "").strip(),
            now()
        )
    )

    post_id = cur.lastrowid

    con.commit()

    post = con.execute(
        """
        SELECT p.*, u.username, u.display_name, u.avatar
        FROM posts p
        JOIN users u ON u.id = p.user_id
        WHERE p.id = ?
        """,
        (post_id,)
    ).fetchone()

    con.close()

    return {
        "post": dict(post)
    }


@app.get("/api/feed")
def feed(
    authorization: Optional[str] = Header(default=None)
):
    row, _ = current_user(authorization)

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
        JOIN users u ON u.id = p.user_id

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
        "posts": [dict(x) for x in posts]
    }


@app.post("/api/posts/{post_id}/like")
def like(
    post_id: int,
    authorization: Optional[str] = Header(default=None)
):
    row, _ = current_user(authorization)

    con = db()

    post = con.execute(
        "SELECT user_id FROM posts WHERE id = ?",
        (post_id,)
    ).fetchone()

    if not post:
        con.close()
        raise HTTPException(
            status_code=404,
            detail="Post not found."
        )

    con.execute(
        """
        INSERT OR IGNORE INTO likes
        (user_id, post_id, created_at)
        VALUES (?, ?, ?)
        """,
        (
            row["id"],
            post_id,
            now()
        )
    )

    if post["user_id"] != row["id"]:
        con.execute(
            """
            INSERT INTO notifications
            (user_id, actor_id, kind, post_id, created_at)
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
    authorization: Optional[str] = Header(default=None)
):
    row, _ = current_user(authorization)

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


@app.post("/api/posts/{post_id}/comments")
def comment(
    post_id: int,
    data: CommentIn,
    authorization: Optional[str] = Header(default=None)
):
    row, _ = current_user(authorization)

    con = db()

    post = con.execute(
        "SELECT user_id FROM posts WHERE id = ?",
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
        (user_id, post_id, body, created_at)
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
            (user_id, actor_id, kind, post_id, created_at)
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
        SELECT c.*, u.username, u.display_name, u.avatar
        FROM comments c
        JOIN users u ON u.id = c.user_id
        WHERE c.id = ?
        """,
        (cur.lastrowid,)
    ).fetchone()

    con.commit()
    con.close()

    return {
        "comment": dict(result)
    }


@app.get("/api/notifications")
def notifications(
    authorization: Optional[str] = Header(default=None)
):
    row, _ = current_user(authorization)

    con = db()

    items = con.execute(
        """
        SELECT n.*, u.username, u.display_name, u.avatar
        FROM notifications n
        LEFT JOIN users u ON u.id = n.actor_id
        WHERE n.user_id = ?
        ORDER BY n.id DESC
        LIMIT 50
        """,
        (row["id"],)
    ).fetchall()

    con.close()

    return {
        "notifications": [dict(x) for x in items]
    }


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
        "users": [dict(x) for x in rows]
    }
