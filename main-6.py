import os, sqlite3, hashlib, secrets, re, json, smtplib, base64
from datetime import datetime, timezone, timedelta
from email.message import EmailMessage
from urllib import request as urlrequest, parse as urlparse
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("ZIVAN_DB", BASE_DIR / "zivan.db"))
app = FastAPI(title="ZIVAN API", version="0.3.1")
# Same-origin hosting works by default; an explicit comma-separated allowlist can be
# supplied in Render as ZIVAN_CORS_ORIGINS. Credentials remain disabled because
# the browser client uses bearer tokens rather than cross-site cookies.
_cors_env = os.getenv("ZIVAN_CORS_ORIGINS", "*").strip()
_cors_origins = [item.strip() for item in _cors_env.split(",") if item.strip()] or ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "geolocation=()")
    return response

def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    return con

def now(): return datetime.now(timezone.utc).isoformat()

def enforce_rate_limit(key: str, limit: int, window_seconds: int):
    """Simple DB-backed throttle for sensitive routes; use a dedicated limiter at scale."""
    current = datetime.now(timezone.utc)
    con = db()
    row = con.execute('SELECT window_start,hits FROM rate_limits WHERE rate_key=?', (key,)).fetchone()
    if row:
        try:
            started = datetime.fromisoformat(row['window_start'])
        except Exception:
            started = current - timedelta(seconds=window_seconds + 1)
        if (current - started).total_seconds() < window_seconds:
            if row['hits'] >= limit:
                con.close()
                raise HTTPException(429, 'Too many requests. Please wait and try again.')
            con.execute('UPDATE rate_limits SET hits=hits+1 WHERE rate_key=?', (key,))
        else:
            con.execute('UPDATE rate_limits SET window_start=?,hits=1 WHERE rate_key=?', (current.isoformat(), key))
    else:
        con.execute('INSERT INTO rate_limits(rate_key,window_start,hits) VALUES(?,?,1)', (key, current.isoformat()))
    con.commit(); con.close()

def audit_event(actor_user_id, event_type, target_type='', target_id='', metadata=None):
    """Store minimal audit metadata only; never store passwords, OTPs, or session tokens."""
    con = db()
    con.execute('INSERT INTO audit_logs(actor_user_id,event_type,target_type,target_id,metadata_json,created_at) VALUES(?,?,?,?,?,?)',
                (actor_user_id, event_type, target_type, str(target_id), json.dumps(metadata or {}, separators=(',', ':')), now()))
    con.commit(); con.close()

def init_db():
    con=db()
    con.executescript('''
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE COLLATE NOCASE,
      email TEXT UNIQUE COLLATE NOCASE,
      phone TEXT UNIQUE,
      password_hash TEXT NOT NULL,
      full_name TEXT NOT NULL,
      display_name TEXT NOT NULL,
      dob TEXT,
      email_verified INTEGER NOT NULL DEFAULT 0,
      phone_verified INTEGER NOT NULL DEFAULT 0,
      bio TEXT NOT NULL DEFAULT '', avatar TEXT NOT NULL DEFAULT '',
      is_private INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS signup_challenges (
      id INTEGER PRIMARY KEY AUTOINCREMENT, channel TEXT NOT NULL, identifier TEXT NOT NULL,
      email TEXT, phone TEXT, username TEXT NOT NULL, full_name TEXT NOT NULL, dob TEXT NOT NULL,
      password_hash TEXT NOT NULL, code_hash TEXT, expires_at TEXT NOT NULL,
      attempts INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS follows (
      follower_id INTEGER NOT NULL, following_id INTEGER NOT NULL, created_at TEXT NOT NULL,
      PRIMARY KEY(follower_id,following_id), CHECK(follower_id!=following_id),
      FOREIGN KEY(follower_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY(following_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, body TEXT NOT NULL,
      media_url TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS likes (
      user_id INTEGER NOT NULL, post_id INTEGER NOT NULL, created_at TEXT NOT NULL,
      PRIMARY KEY(user_id,post_id), FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS comments (
      id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, post_id INTEGER NOT NULL,
      body TEXT NOT NULL, created_at TEXT NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS notifications (
      id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, actor_id INTEGER,
      kind TEXT NOT NULL, post_id INTEGER, read_at TEXT, created_at TEXT NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY(actor_id) REFERENCES users(id) ON DELETE SET NULL,
      FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS reports (
      id INTEGER PRIMARY KEY AUTOINCREMENT, reporter_id INTEGER NOT NULL,
      target_user_id INTEGER, post_id INTEGER, reason TEXT NOT NULL,
      details TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'open',
      created_at TEXT NOT NULL, reviewed_at TEXT,
      FOREIGN KEY(reporter_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY(target_user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS account_appeals (
      id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
      appeal_text TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open',
      created_at TEXT NOT NULL, reviewed_at TEXT,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS moderation_actions (
      id INTEGER PRIMARY KEY AUTOINCREMENT, target_user_id INTEGER NOT NULL,
      action TEXT NOT NULL, reason TEXT NOT NULL, evidence_json TEXT NOT NULL DEFAULT '{}',
      actor_user_id INTEGER, review_required INTEGER NOT NULL DEFAULT 1,
      status TEXT NOT NULL DEFAULT 'pending_review', created_at TEXT NOT NULL,
      FOREIGN KEY(target_user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY(actor_user_id) REFERENCES users(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS admin_roles (
      id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL UNIQUE,
      role TEXT NOT NULL, permissions_json TEXT NOT NULL DEFAULT '[]',
      granted_by INTEGER, created_at TEXT NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY(granted_by) REFERENCES users(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT, actor_user_id INTEGER,
      event_type TEXT NOT NULL, target_type TEXT NOT NULL DEFAULT '',
      target_id TEXT NOT NULL DEFAULT '', metadata_json TEXT NOT NULL DEFAULT '{}',
      created_at TEXT NOT NULL,
      FOREIGN KEY(actor_user_id) REFERENCES users(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS rate_limits (
      rate_key TEXT PRIMARY KEY, window_start TEXT NOT NULL, hits INTEGER NOT NULL DEFAULT 0
    );
    ''')
    # Additive migrations only: preserve existing users, sessions, posts and social data.
    # SQLite cannot add arbitrary constraints to an existing table, so new columns use safe defaults.
    migrations = {
      'users': {
        'phone': 'TEXT',
        'full_name': "TEXT NOT NULL DEFAULT ''",
        'display_name': "TEXT NOT NULL DEFAULT ''",
        'dob': 'TEXT',
        'email_verified': 'INTEGER NOT NULL DEFAULT 0',
        'phone_verified': 'INTEGER NOT NULL DEFAULT 0',
        'bio': "TEXT NOT NULL DEFAULT ''",
        'avatar': "TEXT NOT NULL DEFAULT ''",
        'is_private': 'INTEGER NOT NULL DEFAULT 0',
        'created_at': "TEXT NOT NULL DEFAULT ''",
      },
      'sessions': {'created_at': "TEXT NOT NULL DEFAULT ''", 'expires_at': 'TEXT'},
      'follows': {'created_at': "TEXT NOT NULL DEFAULT ''"},
      'posts': {'media_url': "TEXT NOT NULL DEFAULT ''", 'created_at': "TEXT NOT NULL DEFAULT ''"},
      'likes': {'created_at': "TEXT NOT NULL DEFAULT ''"},
      'comments': {'created_at': "TEXT NOT NULL DEFAULT ''"},
      'notifications': {
        'actor_id': 'INTEGER', 'kind': "TEXT NOT NULL DEFAULT 'system'", 'post_id': 'INTEGER',
        'read_at': 'TEXT', 'created_at': "TEXT NOT NULL DEFAULT ''"
      },
    }
    for table, definitions in migrations.items():
        existing = {r['name'] for r in con.execute(f'PRAGMA table_info({table})').fetchall()}
        for column, definition in definitions.items():
            if column not in existing:
                con.execute(f'ALTER TABLE {table} ADD COLUMN {column} {definition}')
    con.execute("UPDATE users SET display_name=username WHERE COALESCE(display_name,'')=''")
    con.execute("UPDATE users SET full_name=display_name WHERE COALESCE(full_name,'')=''")
    con.execute("UPDATE users SET email_verified=1 WHERE email IS NOT NULL AND email_verified=0")
    con.execute("UPDATE sessions SET expires_at=? WHERE expires_at IS NULL OR expires_at=''", ((datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),))
    con.commit(); con.close()
init_db()

class AuthIn(BaseModel):
    identifier:str=Field(min_length=3,max_length=254)
    password:str=Field(min_length=8,max_length=128)
class LegacyAuthIn(BaseModel):
    identifier:Optional[str]=Field(default=None,max_length=254)
    username:Optional[str]=Field(default=None,max_length=30)
    email:Optional[str]=Field(default=None,max_length=254)
    phone:Optional[str]=Field(default=None,max_length=20)
    password:str=Field(min_length=8,max_length=128)
class SignupStart(BaseModel):
    channel:str
    username:str=Field(min_length=3,max_length=30)
    full_name:str=Field(min_length=1,max_length=80)
    dob:str=Field(min_length=10,max_length=10)
    email:Optional[str]=Field(default=None,max_length=254)
    phone:Optional[str]=Field(default=None,max_length=20)
    password:str=Field(min_length=8,max_length=128)
class VerifyCodeIn(BaseModel):
    challenge_id:int
    code:str=Field(min_length=4,max_length=10)
class ProfileUpdate(BaseModel):
    display_name:Optional[str]=Field(default=None,max_length=80)
    bio:Optional[str]=Field(default=None,max_length=500)
    avatar:Optional[str]=Field(default=None,max_length=500)
    is_private:Optional[bool]=None
class PostIn(BaseModel):
    body:str=Field(min_length=1,max_length=5000)
    media_url:Optional[str]=Field(default='',max_length=2000)
class CommentIn(BaseModel): body:str=Field(min_length=1,max_length=1000)

def password_hash(password,salt=None):
    salt=salt or secrets.token_bytes(16)
    digest=hashlib.pbkdf2_hmac('sha256',password.encode(),salt,310000)
    return salt.hex()+'$'+digest.hex()
def password_ok(password,stored):
    try:
        salt,digest=stored.split('$',1)
        got=hashlib.pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(salt),310000)
        return secrets.compare_digest(got.hex(),digest)
    except Exception: return False

def normalize_phone(phone):
    value=re.sub(r'[^0-9+]','',phone.strip())
    if value.startswith('00'): value='+'+value[2:]
    if not value.startswith('+') or not 10<=len(value)<=16:
        raise HTTPException(400,'Use a valid phone number with country code, e.g. +91...')
    return value

def valid_dob(dob):
    try:
        birth=datetime.fromisoformat(dob).date(); today=datetime.now(timezone.utc).date()
        if birth>today:return False
        age=today.year-birth.year-((today.month,today.day)<(birth.month,birth.day))
        return age>=13
    except Exception:return False

def code_hash(code): return hashlib.sha256(code.encode()).hexdigest()

def send_email_code(email,code):
    host=os.getenv('SMTP_HOST'); port=int(os.getenv('SMTP_PORT','587')); username=os.getenv('SMTP_USERNAME') or os.getenv('SMTP_USER'); password=os.getenv('SMTP_PASSWORD') or os.getenv('SMTP_PASS'); sender=os.getenv('SMTP_FROM') or os.getenv('SMTP_FROM_EMAIL') or username
    if not host or not username or not password or not sender:
        raise HTTPException(503,'Email verification is not configured yet. Add SMTP settings in Render.')
    msg=EmailMessage(); msg['Subject']='Your ZIVAN verification code'; msg['From']=sender; msg['To']=email
    msg.set_content(f'Your ZIVAN verification code is {code}. It expires in 10 minutes. If you did not request this, ignore this email.')
    with smtplib.SMTP(host,port,timeout=15) as server:
        server.starttls(); server.login(username,password); server.send_message(msg)

def twilio_verify(action,to,code=None):
    key=os.getenv('TWILIO_API_KEY') or os.getenv('TWILIO_ACCOUNT_SID'); secret=os.getenv('TWILIO_API_SECRET') or os.getenv('TWILIO_AUTH_TOKEN'); service=os.getenv('TWILIO_VERIFY_SERVICE_SID') or os.getenv('TWILIO_VERIFY_SID')
    if not key or not secret or not service:
        raise HTTPException(503,'Phone verification is not configured yet. Add Twilio Verify settings in Render.')
    if action=='send':
        endpoint=f'https://verify.twilio.com/v2/Services/{service}/Verifications'; payload=urlparse.urlencode({'To':to,'Channel':'sms'}).encode()
    else:
        endpoint=f'https://verify.twilio.com/v2/Services/{service}/VerificationCheck'; payload=urlparse.urlencode({'To':to,'Code':code or ''}).encode()
    req=urlrequest.Request(endpoint,data=payload,method='POST')
    req.add_header('Authorization','Basic '+base64.b64encode((key+':'+secret).encode()).decode())
    req.add_header('Content-Type','application/x-www-form-urlencoded')
    try:
        with urlrequest.urlopen(req,timeout=15) as response:return json.loads(response.read().decode())
    except Exception as exc: raise HTTPException(502,'Verification provider request failed.') from exc

def create_session(con,user_id):
    token=secrets.token_urlsafe(48); expires=(datetime.now(timezone.utc)+timedelta(days=30)).isoformat()
    con.execute('INSERT INTO sessions(token,user_id,created_at,expires_at) VALUES(?,?,?,?)',(token,user_id,now(),expires)); return token

def public_user(row):
    return {'id':row['id'],'username':row['username'],'display_name':row['display_name'],'full_name':row['full_name'] if 'full_name' in row.keys() else row['display_name'],'bio':row['bio'],'avatar':row['avatar'],'is_private':bool(row['is_private']),'created_at':row['created_at']}

def current_user(authorization):
    if not authorization or not authorization.lower().startswith('bearer '): raise HTTPException(401,'Authentication required.')
    token=authorization.split(' ',1)[1].strip(); con=db()
    row=con.execute('SELECT u.*,s.expires_at session_expires_at FROM users u JOIN sessions s ON s.user_id=u.id WHERE s.token=?',(token,)).fetchone()
    if not row: con.close(); raise HTTPException(401,'Invalid session.')
    if row['session_expires_at'] and datetime.fromisoformat(row['session_expires_at'])<=datetime.now(timezone.utc):
        con.execute('DELETE FROM sessions WHERE token=?',(token,)); con.commit(); con.close(); raise HTTPException(401,'Session expired.')
    con.close(); return row,token

@app.get('/')
def home(): return FileResponse(BASE_DIR/'index.html')
@app.get('/api/health')
def health(): return {'ok':True,'service':'ZIVAN','version':'0.3.1'}
@app.get('/api/init-app')
def init_app(): return {'app':'ZIVAN','version':'0.3.1','features':['auth','email_verification','phone_verification','profiles','follow','posts','likes','comments','notifications','moderation_foundation']}

@app.post('/api/auth/request-code')
def request_signup_code(data:SignupStart, request:Request):
    enforce_rate_limit('signup-code:' + (request.client.host if request.client else 'unknown'), 8, 3600)
    channel=data.channel.strip().lower()
    if channel not in {'email','phone'}: raise HTTPException(400,'Choose email or phone.')
    username=data.username.strip().lstrip('@').lower()
    if not username.replace('_','').isalnum(): raise HTTPException(400,'Username can use letters, numbers and underscores only.')
    if not valid_dob(data.dob): raise HTTPException(400,'You must be at least 13 years old to create a ZIVAN account.')
    email=(data.email or '').strip().lower() or None; phone=normalize_phone(data.phone) if data.phone else None
    if channel=='email' and not email: raise HTTPException(400,'Email is required.')
    if channel=='phone' and not phone: raise HTTPException(400,'Phone number is required.')
    con=db()
    if email and con.execute('SELECT id FROM users WHERE email=? COLLATE NOCASE',(email,)).fetchone(): con.close(); raise HTTPException(409,'Email already exists.')
    if phone and con.execute('SELECT id FROM users WHERE phone=?',(phone,)).fetchone(): con.close(); raise HTTPException(409,'Phone number already exists.')
    if con.execute('SELECT id FROM users WHERE username=? COLLATE NOCASE',(username,)).fetchone(): con.close(); raise HTTPException(409,'Username already exists.')
    code=str(secrets.randbelow(900000)+100000) if channel=='email' else None
    expires=(datetime.now(timezone.utc)+timedelta(minutes=10)).isoformat()
    cur=con.execute('INSERT INTO signup_challenges(channel,identifier,email,phone,username,full_name,dob,password_hash,code_hash,expires_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)',(channel,email or phone,email,phone,username,data.full_name.strip(),data.dob,password_hash(data.password),code_hash(code) if code else None,expires,now()))
    cid=cur.lastrowid; con.commit(); con.close()
    try:
        if channel=='email': send_email_code(email,code)
        else: twilio_verify('send',phone)
    except Exception:
        con=db(); con.execute('DELETE FROM signup_challenges WHERE id=?',(cid,)); con.commit(); con.close(); raise
    return {'ok':True,'challenge_id':cid,'channel':channel,'destination':email if channel=='email' else phone,'expires_in':600}

@app.post('/api/auth/verify-code')
def verify_signup_code(data:VerifyCodeIn):
    con=db(); c=con.execute('SELECT * FROM signup_challenges WHERE id=?',(data.challenge_id,)).fetchone()
    if not c: con.close(); raise HTTPException(404,'Verification request not found.')
    if datetime.fromisoformat(c['expires_at'])<=datetime.now(timezone.utc): con.execute('DELETE FROM signup_challenges WHERE id=?',(data.challenge_id,)); con.commit(); con.close(); raise HTTPException(410,'Verification code expired. Request a new code.')
    if c['attempts']>=5: con.close(); raise HTTPException(429,'Too many verification attempts. Request a new code.')
    con.execute('UPDATE signup_challenges SET attempts=attempts+1 WHERE id=?',(data.challenge_id,)); con.commit()
    if c['channel']=='email': valid=secrets.compare_digest(code_hash(data.code),c['code_hash'])
    else: valid=twilio_verify('check',c['phone'],data.code).get('status')=='approved'
    if not valid: con.close(); raise HTTPException(400,'Incorrect verification code.')
    try:
        cur=con.execute('INSERT INTO users(username,email,phone,password_hash,full_name,display_name,dob,email_verified,phone_verified,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)',(c['username'],c['email'],c['phone'],c['password_hash'],c['full_name'],c['full_name'],c['dob'],1 if c['channel']=='email' else 0,1 if c['channel']=='phone' else 0,now()))
    except sqlite3.IntegrityError:
        con.close(); raise HTTPException(409,'Username or contact is already in use.')
    token=create_session(con,cur.lastrowid); row=con.execute('SELECT * FROM users WHERE id=?',(cur.lastrowid,)).fetchone(); con.execute('DELETE FROM signup_challenges WHERE id=?',(data.challenge_id,)); con.commit(); con.close()
    audit_event(row['id'], 'signup_completed', 'account', row['id'])
    return {'token':token,'user':public_user(row)}

@app.post('/api/auth/login')
def login(data:AuthIn, request:Request):
    enforce_rate_limit('login:' + (request.client.host if request.client else 'unknown'), 20, 900)
    identifier=data.identifier.strip().lstrip('@').lower(); con=db()
    row=con.execute('SELECT * FROM users WHERE username=? COLLATE NOCASE OR email=? COLLATE NOCASE OR phone=? LIMIT 1',(identifier,identifier,identifier)).fetchone()
    if not row or not password_ok(data.password,row['password_hash']):
        con.close()
        audit_event(None, 'login_failed', 'account', hashlib.sha256(identifier.encode()).hexdigest()[:16])
        raise HTTPException(401,'Invalid login details.')
    if not row['email_verified'] and not row['phone_verified']: con.close(); raise HTTPException(403,'Account contact is not verified.')
    token=create_session(con,row['id']); con.commit(); con.close(); audit_event(row['id'], 'login_succeeded', 'account', row['id']); return {'token':token,'user':public_user(row)}

@app.post('/api/login')
def legacy_login(data:LegacyAuthIn, request:Request):
    identifier = (data.identifier or data.username or data.email or data.phone or '').strip()
    if not identifier:
        raise HTTPException(400, 'Username, email or phone is required.')
    return login(AuthIn(identifier=identifier, password=data.password), request)

@app.post('/api/signup')
def legacy_signup_disabled():
    # Do not let legacy clients bypass the current 13+ and verified-contact signup flow.
    raise HTTPException(410, 'Please use the current ZIVAN signup flow with contact verification.')

@app.post('/api/logout')
def logout(authorization:Optional[str]=Header(default=None)):
    _,token=current_user(authorization); con=db(); con.execute('DELETE FROM sessions WHERE token=?',(token,)); con.commit(); con.close(); return {'ok':True}

@app.get('/api/me')
def me(authorization:Optional[str]=Header(default=None)):
    row,_=current_user(authorization); con=db(); followers=con.execute('SELECT COUNT(*) c FROM follows WHERE following_id=?',(row['id'],)).fetchone()['c']; following=con.execute('SELECT COUNT(*) c FROM follows WHERE follower_id=?',(row['id'],)).fetchone()['c']; con.close(); return {'user':public_user(row),'followers':followers,'following':following}

@app.patch('/api/me')
def update_me(data:ProfileUpdate,authorization:Optional[str]=Header(default=None)):
    row,_=current_user(authorization); fields=[]; vals=[]
    if data.display_name is not None: fields.append('display_name=?'); vals.append(data.display_name.strip())
    if data.bio is not None: fields.append('bio=?'); vals.append(data.bio.strip())
    if data.avatar is not None: fields.append('avatar=?'); vals.append(data.avatar.strip())
    if data.is_private is not None: fields.append('is_private=?'); vals.append(int(data.is_private))
    if not fields:return {'user':public_user(row)}
    vals.append(row['id']); con=db(); con.execute('UPDATE users SET '+','.join(fields)+' WHERE id=?',vals); updated=con.execute('SELECT * FROM users WHERE id=?',(row['id'],)).fetchone(); con.commit(); con.close(); return {'user':public_user(updated)}

@app.get('/api/users/{username}')
def get_user(username:str):
    con=db(); row=con.execute('SELECT * FROM users WHERE username=? COLLATE NOCASE',(username.lstrip('@'),)).fetchone()
    if not row: con.close(); raise HTTPException(404,'User not found.')
    followers=con.execute('SELECT COUNT(*) c FROM follows WHERE following_id=?',(row['id'],)).fetchone()['c']; following=con.execute('SELECT COUNT(*) c FROM follows WHERE follower_id=?',(row['id'],)).fetchone()['c']; con.close(); return {'user':public_user(row),'followers':followers,'following':following}

@app.post('/api/users/{username}/follow')
def follow(username:str,authorization:Optional[str]=Header(default=None)):
    me_row,_=current_user(authorization); con=db(); target=con.execute('SELECT * FROM users WHERE username=? COLLATE NOCASE',(username.lstrip('@'),)).fetchone()
    if not target: con.close(); raise HTTPException(404,'User not found.')
    if target['id']==me_row['id']: con.close(); raise HTTPException(400,'You cannot follow yourself.')
    cur=con.execute('INSERT OR IGNORE INTO follows(follower_id,following_id,created_at) VALUES(?,?,?)',(me_row['id'],target['id'],now()))
    if cur.rowcount:
        con.execute('INSERT INTO notifications(user_id,actor_id,kind,created_at) VALUES(?,?,?,?)',(target['id'],me_row['id'],'follow',now()))
    con.commit(); con.close(); return {'ok':True,'following':True}
@app.delete('/api/users/{username}/follow')
def unfollow(username:str,authorization:Optional[str]=Header(default=None)):
    me_row,_=current_user(authorization); con=db(); target=con.execute('SELECT id FROM users WHERE username=? COLLATE NOCASE',(username.lstrip('@'),)).fetchone()
    if not target: con.close(); raise HTTPException(404,'User not found.')
    con.execute('DELETE FROM follows WHERE follower_id=? AND following_id=?',(me_row['id'],target['id'])); con.commit(); con.close(); return {'ok':True,'following':False}

@app.post('/api/posts')
def create_post(data:PostIn,authorization:Optional[str]=Header(default=None)):
    row,_=current_user(authorization); con=db(); cur=con.execute('INSERT INTO posts(user_id,body,media_url,created_at) VALUES(?,?,?,?)',(row['id'],data.body.strip(),(data.media_url or '').strip(),now())); post=con.execute('SELECT p.*,u.username,u.display_name,u.avatar FROM posts p JOIN users u ON u.id=p.user_id WHERE p.id=?',(cur.lastrowid,)).fetchone(); con.commit(); con.close(); return {'post':dict(post)}
@app.get('/api/feed')
def feed(authorization:Optional[str]=Header(default=None)):
    row,_=current_user(authorization); con=db(); posts=con.execute('''SELECT p.*,u.username,u.display_name,u.avatar,(SELECT COUNT(*) FROM likes l WHERE l.post_id=p.id) likes,(SELECT COUNT(*) FROM comments c WHERE c.post_id=p.id) comments FROM posts p JOIN users u ON u.id=p.user_id WHERE p.user_id=? OR p.user_id IN(SELECT following_id FROM follows WHERE follower_id=?) ORDER BY p.id DESC LIMIT 50''',(row['id'],row['id'])).fetchall(); con.close(); return {'posts':[dict(x) for x in posts]}
@app.post('/api/posts/{post_id}/like')
def like(post_id:int,authorization:Optional[str]=Header(default=None)):
    row,_=current_user(authorization); con=db(); post=con.execute('SELECT user_id FROM posts WHERE id=?',(post_id,)).fetchone()
    if not post: con.close(); raise HTTPException(404,'Post not found.')
    con.execute('INSERT OR IGNORE INTO likes(user_id,post_id,created_at) VALUES(?,?,?)',(row['id'],post_id,now()));
    if post['user_id']!=row['id']: con.execute('INSERT INTO notifications(user_id,actor_id,kind,post_id,created_at) VALUES(?,?,?,?,?)',(post['user_id'],row['id'],'like',post_id,now()))
    con.commit(); con.close(); return {'ok':True,'liked':True}
@app.delete('/api/posts/{post_id}/like')
def unlike(post_id:int,authorization:Optional[str]=Header(default=None)):
    row,_=current_user(authorization); con=db(); con.execute('DELETE FROM likes WHERE user_id=? AND post_id=?',(row['id'],post_id)); con.commit(); con.close(); return {'ok':True,'liked':False}
@app.get('/api/posts/{post_id}/comments')
def get_comments(post_id:int, authorization:Optional[str]=Header(default=None)):
    # Existing frontend calls this endpoint to display the comments for a post.
    current_user(authorization)
    con=db()
    if not con.execute('SELECT id FROM posts WHERE id=?',(post_id,)).fetchone():
        con.close(); raise HTTPException(404,'Post not found.')
    rows=con.execute('SELECT c.*,u.username,u.display_name,u.avatar FROM comments c JOIN users u ON u.id=c.user_id WHERE c.post_id=? ORDER BY c.id ASC LIMIT 100',(post_id,)).fetchall()
    con.close()
    return {'comments':[dict(item) for item in rows]}

@app.post('/api/posts/{post_id}/comments')
def comment(post_id:int,data:CommentIn,authorization:Optional[str]=Header(default=None)):
    row,_=current_user(authorization); con=db(); post=con.execute('SELECT user_id FROM posts WHERE id=?',(post_id,)).fetchone()
    if not post: con.close(); raise HTTPException(404,'Post not found.')
    cur=con.execute('INSERT INTO comments(user_id,post_id,body,created_at) VALUES(?,?,?,?)',(row['id'],post_id,data.body.strip(),now()))
    if post['user_id']!=row['id']: con.execute('INSERT INTO notifications(user_id,actor_id,kind,post_id,created_at) VALUES(?,?,?,?,?)',(post['user_id'],row['id'],'comment',post_id,now()))
    result=con.execute('SELECT c.*,u.username,u.display_name,u.avatar FROM comments c JOIN users u ON u.id=c.user_id WHERE c.id=?',(cur.lastrowid,)).fetchone(); con.commit(); con.close(); return {'comment':dict(result)}
@app.get('/api/users/{username}/posts')
def user_posts(username:str, authorization:Optional[str]=Header(default=None)):
    con=db()
    user=con.execute('SELECT id,username FROM users WHERE username=? COLLATE NOCASE',(username.lstrip('@'),)).fetchone()
    if not user:
        con.close(); raise HTTPException(404, 'User not found.')
    posts=con.execute('''SELECT p.*,u.username,u.display_name,u.avatar,
        (SELECT COUNT(*) FROM likes l WHERE l.post_id=p.id) likes,
        (SELECT COUNT(*) FROM comments c WHERE c.post_id=p.id) comments
        FROM posts p JOIN users u ON u.id=p.user_id WHERE p.user_id=? ORDER BY p.id DESC LIMIT 50''',(user['id'],)).fetchall()
    con.close()
    return {'posts':[dict(item) for item in posts]}

@app.get('/api/notifications')
def notifications(authorization:Optional[str]=Header(default=None)):
    row,_=current_user(authorization); con=db(); items=con.execute('SELECT n.*,u.username,u.display_name,u.avatar FROM notifications n LEFT JOIN users u ON u.id=n.actor_id WHERE n.user_id=? ORDER BY n.id DESC LIMIT 50',(row['id'],)).fetchall(); con.close(); return {'notifications':[dict(x) for x in items]}
@app.get('/api/search')
def search(q:str=''):
    q=q.strip().lstrip('@')
    if not q:return {'users':[]}
    con=db(); rows=con.execute('SELECT id,username,display_name,bio,avatar,is_private FROM users WHERE username LIKE ? OR display_name LIKE ? ORDER BY username LIMIT 20',(f'%{q}%',f'%{q}%')).fetchall(); con.close(); return {'users':[dict(x) for x in rows]}
