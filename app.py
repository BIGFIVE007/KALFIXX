import sqlite3, secrets, time, random, requests, base64, os, re, hmac, logging, hashlib
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
from datetime import datetime, date, timedelta
from functools import wraps
from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

app = Flask(__name__)

# ─────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────
ALLOWED_ORIGIN = os.environ.get("ALLOWED_ORIGIN", "*")
CORS(app, resources={r"/api/*": {"origins": ALLOWED_ORIGIN}})

app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # 16 KB max request body

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per minute"],
    storage_uri=os.environ.get("LIMITER_STORAGE_URI", "memory://"),
)

DB_FILE        = os.environ.get("DB_FILE", "kalfix.db")
SANDBOX        = os.environ.get("MPESA_SANDBOX", "true").lower() == "true"
MPESA_BASE     = "https://sandbox.safaricom.co.ke" if SANDBOX else "https://api.safaricom.co.ke"

MPESA_CONSUMER_KEY    = os.environ.get("MPESA_CONSUMER_KEY", "")
MPESA_CONSUMER_SECRET = os.environ.get("MPESA_CONSUMER_SECRET", "")
MPESA_SHORTCODE       = os.environ.get("MPESA_SHORTCODE", "174379")
MPESA_PASSKEY         = os.environ.get("MPESA_PASSKEY", "")
MPESA_B2C_INITIATOR   = os.environ.get("MPESA_B2C_INITIATOR", "testapi")
MPESA_B2C_PASSWORD    = os.environ.get("MPESA_B2C_PASSWORD", "")
BASE_URL              = os.environ.get("BASE_URL", "https://yourdomain.com")
MPESA_CALLBACK_URL    = f"{BASE_URL}/api/mpesa/callback"
MPESA_B2C_CALLBACK    = f"{BASE_URL}/api/mpesa/b2c/callback"
MPESA_STK_URL         = f"{MPESA_BASE}/mpesa/stkpush/v1/processrequest"
MPESA_B2C_URL         = f"{MPESA_BASE}/mpesa/b2c/v1/paymentrequest"
MPESA_AUTH_URL        = f"{MPESA_BASE}/oauth/v1/generate?grant_type=client_credentials"

# Safaricom production IP allowlist for callbacks.
# In sandbox all IPs are allowed; in production only Safaricom egress IPs may post callbacks.
# Keep this list updated — see https://developer.safaricom.co.ke/docs#ip-addresses
MPESA_ALLOWED_IPS = set(os.environ.get("MPESA_ALLOWED_IPS", "").split(",")) - {""}
# If the env var is empty we skip IP checking (safe for sandbox; set it in production).

AT_API_KEY   = os.environ.get("AT_API_KEY", "")
AT_USERNAME  = os.environ.get("AT_USERNAME", "sandbox")
AT_SENDER    = os.environ.get("AT_SENDER",   "KALFIXTV")

ADMIN_PHONE    = os.environ.get("ADMIN_PHONE",    "0700000000")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "Admin@12345")

if not ADMIN_PASSWORD:
    raise RuntimeError("ADMIN_PASSWORD environment variable must be set before starting.")

# FIX #7: Raise on default cron secret so it is never shipped unchanged.
_DEFAULT_CRON_SECRET = "changeme-cron-secret"
CRON_SECRET = os.environ.get("CRON_SECRET", "")
if not CRON_SECRET or CRON_SECRET == _DEFAULT_CRON_SECRET:
    raise RuntimeError(
        "CRON_SECRET environment variable must be set to a strong random value before starting. "
        "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
    )

REFERRAL_BONUS    = float(os.environ.get("REFERRAL_BONUS", "100"))
PACKAGE_DAYS      = 45
MIN_WITHDRAWAL    = 50.0
POINTS_TO_KES     = 0.10   # 10 pts = Ksh 1.00  (integer points × 0.10 = KES, exact for multiples of 10)

# M-Pesa token cache
_mpesa_token_cache = {"token": None, "expires_at": 0}

# Argon2 hasher
_ph = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=2)

# ─────────────────────────────────────────────────────
# PACKAGES
# ─────────────────────────────────────────────────────
PACKAGES = {
    "Bronze":   {"price": 1000,  "daily_earn": 30,   "daily_tasks": 1,  "pts_per_task": 300},
    "Silver":   {"price": 5000,  "daily_earn": 100,  "daily_tasks": 4,  "pts_per_task": 250},
    "Gold":     {"price": 10000, "daily_earn": 250,  "daily_tasks": 9,  "pts_per_task": 278},
    "Platinum": {"price": 20000, "daily_earn": 450,  "daily_tasks": 18, "pts_per_task": 250},
    "Diamond":  {"price": 30000, "daily_earn": 700,  "daily_tasks": 27, "pts_per_task": 259},
    "Elite":    {"price": 40000, "daily_earn": 900,  "daily_tasks": 36, "pts_per_task": 250},
    "VIP":      {"price": 50000, "daily_earn": 1150, "daily_tasks": 45, "pts_per_task": 256},
}

# FIX #8: Placeholder IDs are logged loudly at startup so they can't be missed.
DEFAULT_VIDEOS = [
    {"id": "VIDEO_ID_1", "title": "Ad Spot #1"},
    {"id": "VIDEO_ID_2", "title": "Ad Spot #2"},
    {"id": "VIDEO_ID_3", "title": "Ad Spot #3"},
    {"id": "VIDEO_ID_4", "title": "Ad Spot #4"},
    {"id": "VIDEO_ID_5", "title": "Ad Spot #5"},
]
_PLACEHOLDER_PREFIX = "VIDEO_ID_"

# ─────────────────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _warn_placeholder_videos():
    """Warn loudly at startup if placeholder video IDs are still in the DB."""
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id FROM youtube_videos WHERE id LIKE ?", (_PLACEHOLDER_PREFIX + "%",))
    placeholders = [r["id"] for r in c.fetchall()]
    conn.close()
    if placeholders:
        log.warning(
            "⚠️  PLACEHOLDER VIDEO IDs DETECTED: %s — replace these with real YouTube IDs "
            "via /api/admin/videos/add before going live!", placeholders
        )


def init_db():
    conn = get_db()
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS users (
        phone             TEXT PRIMARY KEY,
        name              TEXT DEFAULT '',
        password          TEXT NOT NULL,
        balance           REAL DEFAULT 0.0,
        points            INTEGER DEFAULT 0,
        package           TEXT DEFAULT 'None',
        active            INTEGER DEFAULT 0,
        package_expires   TEXT DEFAULT NULL,
        is_admin          INTEGER DEFAULT 0,
        referral_code     TEXT UNIQUE,
        referred_by       TEXT DEFAULT NULL,
        total_referrals   INTEGER DEFAULT 0,
        referral_earnings REAL DEFAULT 0.0,
        created_at        TEXT DEFAULT (datetime('now'))
    )''')

    # FIX #2: Store SHA-256 hash of session token, not the raw token.
    # token_hash is indexed; the raw token is only ever held by the client.
    c.execute('''CREATE TABLE IF NOT EXISTS sessions (
        token_hash TEXT PRIMARY KEY,
        phone      TEXT NOT NULL,
        created    INTEGER NOT NULL
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS daily_tasks (
        phone     TEXT NOT NULL,
        task_date TEXT NOT NULL,
        count     INTEGER DEFAULT 0,
        PRIMARY KEY (phone, task_date)
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS task_tokens (
        token      TEXT PRIMARY KEY,
        phone      TEXT NOT NULL,
        video_id   TEXT NOT NULL,
        issued_at  INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        used       INTEGER DEFAULT 0
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS transactions (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        phone       TEXT NOT NULL,
        type        TEXT NOT NULL,
        amount      REAL NOT NULL,
        description TEXT,
        status      TEXT DEFAULT 'completed',
        ref         TEXT,
        created_at  TEXT DEFAULT (datetime('now'))
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS otp_codes (
        phone   TEXT PRIMARY KEY,
        code    TEXT NOT NULL,
        expires INTEGER NOT NULL
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS mpesa_requests (
        checkout_id  TEXT PRIMARY KEY,
        phone        TEXT NOT NULL,
        amount       REAL NOT NULL,
        package_name TEXT,
        status       TEXT DEFAULT 'pending',
        created_at   TEXT DEFAULT (datetime('now'))
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS youtube_videos (
        id       TEXT PRIMARY KEY,
        title    TEXT NOT NULL,
        active   INTEGER DEFAULT 1,
        added_at TEXT DEFAULT (datetime('now'))
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS referrals (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        referrer   TEXT NOT NULL,
        referred   TEXT NOT NULL,
        bonus_paid REAL DEFAULT 0.0,
        created_at TEXT DEFAULT (datetime('now'))
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS notifications (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        phone      TEXT NOT NULL,
        message    TEXT NOT NULL,
        read       INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now'))
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS withdrawal_requests (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        phone        TEXT NOT NULL,
        amount       REAL NOT NULL,
        status       TEXT DEFAULT 'pending',
        admin_note   TEXT DEFAULT '',
        mpesa_ref    TEXT DEFAULT '',
        requested_at TEXT DEFAULT (datetime('now')),
        processed_at TEXT DEFAULT NULL
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS cron_runs (
        job_name   TEXT NOT NULL,
        run_date   TEXT NOT NULL,
        PRIMARY KEY (job_name, run_date)
    )''')

    for v in DEFAULT_VIDEOS:
        c.execute("INSERT OR IGNORE INTO youtube_videos (id,title) VALUES (?,?)", (v["id"], v["title"]))

    # Admin account — only insert once
    c.execute("SELECT phone FROM users WHERE phone=?", (ADMIN_PHONE,))
    if not c.fetchone():
        admin_hash = _ph.hash(ADMIN_PASSWORD)
        c.execute(
            "INSERT INTO users (phone,name,password,is_admin,referral_code) VALUES (?,?,?,?,?)",
            (ADMIN_PHONE, "Admin", admin_hash, 1, "ADMIN00")
        )

    conn.commit()
    conn.close()
    _warn_placeholder_videos()


init_db()


# ─────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────

def hash_pw(p):
    return _ph.hash(p)

def verify_pw(stored_hash, password):
    """Returns True if password matches. Handles legacy SHA-256 hashes gracefully."""
    try:
        _ph.verify(stored_hash, password)
        return True
    except VerifyMismatchError:
        return False
    except (InvalidHashError, Exception):
        return False

def needs_rehash(stored_hash):
    return _ph.check_needs_rehash(stored_hash)

def make_ref_code(name):
    base = re.sub(r'[^A-Z0-9]', '', name.upper())[:4] or "USER"
    return base + secrets.token_hex(2).upper()

def _hash_token(tok: str) -> str:
    """SHA-256 hex digest of a session token. Only the hash is stored in the DB."""
    return hashlib.sha256(tok.encode()).hexdigest()

def gen_token(phone):
    """Generate a session token, store its SHA-256 hash, return the raw token to the caller."""
    tok = secrets.token_hex(32)
    tok_hash = _hash_token(tok)
    conn = get_db()
    # Clean up sessions older than 24 hours for all users (house-keeping)
    conn.execute("DELETE FROM sessions WHERE created < ?", (int(time.time()) - 86400,))
    conn.execute(
        "INSERT INTO sessions (token_hash,phone,created) VALUES (?,?,?)",
        (tok_hash, phone, int(time.time()))
    )
    conn.commit()
    conn.close()
    return tok  # raw token goes to client only

def verify_token(tok):
    """Verify a raw session token by hashing it and looking up the hash."""
    if not tok:
        return None
    tok_hash = _hash_token(tok)
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT phone,created FROM sessions WHERE token_hash=?", (tok_hash,))
    row = c.fetchone()
    conn.close()
    if not row or int(time.time()) - row["created"] > 86400:
        return None
    return row["phone"]

def log_tx(conn, phone, t, amount, desc, status="completed", ref=None):
    conn.execute(
        "INSERT INTO transactions (phone,type,amount,description,status,ref) VALUES (?,?,?,?,?,?)",
        (phone, t, amount, desc, status, ref)
    )

def push_notif(conn, phone, message):
    conn.execute("INSERT INTO notifications (phone,message) VALUES (?,?)", (phone, message))

def normalize_phone(p):
    """Normalize and validate a Kenyan phone number."""
    p = re.sub(r'[\s\-]', '', str(p).strip())
    if p.startswith("0"):
        p = "254" + p[1:]
    elif p.startswith("+"):
        p = p[1:]
    if not re.fullmatch(r'254[17]\d{8}', p):
        raise ValueError(f"Invalid Kenyan phone number: {p}")
    return p

def mpesa_token():
    """Return a cached M-Pesa OAuth token, refreshing only when expired."""
    now = time.time()
    if _mpesa_token_cache["token"] and now < _mpesa_token_cache["expires_at"] - 60:
        return _mpesa_token_cache["token"]
    creds = base64.b64encode(f"{MPESA_CONSUMER_KEY}:{MPESA_CONSUMER_SECRET}".encode()).decode()
    try:
        r = requests.get(MPESA_AUTH_URL, headers={"Authorization": f"Basic {creds}"}, timeout=10)
        data = r.json()
        token = data.get("access_token")
        expires_in = int(data.get("expires_in", 3600))
        _mpesa_token_cache["token"] = token
        _mpesa_token_cache["expires_at"] = now + expires_in
        return token
    except Exception as e:
        log.error(f"[MPESA AUTH] {e}")
        return None

def mpesa_pw_ts():
    ts = datetime.now().strftime("%Y%m%d%H%M%S")
    return base64.b64encode(f"{MPESA_SHORTCODE}{MPESA_PASSKEY}{ts}".encode()).decode(), ts

def send_sms(phone, message):
    """Send SMS via Africa's Talking. Always call this OUTSIDE open DB transactions."""
    try:
        import africastalking
        africastalking.initialize(AT_USERNAME, AT_API_KEY)
        africastalking.SMS.send(message, [normalize_phone(phone)], AT_SENDER)
    except Exception as e:
        log.error(f"[SMS ERROR] phone={phone} error={e}")

def expiry_date():
    return (datetime.utcnow() + timedelta(days=PACKAGE_DAYS)).strftime("%Y-%m-%d")

def check_package_expiry(conn, phone):
    """
    Deactivate user if package has expired. Returns True if still active.
    FIX #10: Uses date objects for comparison instead of string comparison.
    FIX #6: SMS is dispatched AFTER the DB commit — caller must commit before
            any code path that triggers the SMS side-effect.
    """
    c = conn.cursor()
    c.execute("SELECT package,active,package_expires FROM users WHERE phone=?", (phone,))
    row = c.fetchone()
    if not row or not row["active"]:
        return False
    if row["package_expires"]:
        # FIX #10: safe date comparison using date objects, not strings
        expires = date.fromisoformat(row["package_expires"])
        if date.today() > expires:
            conn.execute("UPDATE users SET active=0 WHERE phone=?", (phone,))
            push_notif(conn, phone,
                f"Your {row['package']} package expired. Renew to continue earning.")
            conn.commit()
            # FIX #6: SMS sent after commit, outside transaction
            send_sms(phone,
                f"KALFIX TV: Your {row['package']} package has expired. Renew now to keep earning!")
            return False
    return True

# ── Task token helpers ────────────────────────────────

def issue_task_token(phone, video_id):
    """Issue a task token valid for 12 minutes (10 min watch + 2 min grace)."""
    tok = secrets.token_hex(24)
    issued = int(time.time())
    expires = issued + 720
    conn = get_db()
    conn.execute(
        "INSERT INTO task_tokens (token,phone,video_id,issued_at,expires_at) VALUES (?,?,?,?,?)",
        (tok, phone, video_id, issued, expires)
    )
    conn.commit()
    conn.close()
    return tok

def consume_task_token(token, phone):
    """
    Atomically validate and consume a task token.
    Returns (ok:bool, reason:str)
    """
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT phone,used,issued_at,expires_at FROM task_tokens WHERE token=?", (token,))
    row = c.fetchone()
    if not row:
        conn.close()
        return False, "Invalid task token"
    if row["phone"] != phone:
        conn.close()
        return False, "Token does not belong to this user"
    if row["used"]:
        conn.close()
        return False, "Task token already used"
    now = int(time.time())
    if now > row["expires_at"]:
        conn.close()
        return False, "Task token expired — did you finish the video?"
    if now - row["issued_at"] < 570:
        elapsed = now - row["issued_at"]
        conn.close()
        return False, f"Too fast — only {elapsed}s elapsed, 570s required"
    result = conn.execute(
        "UPDATE task_tokens SET used=1 WHERE token=? AND used=0", (token,)
    )
    if result.rowcount == 0:
        conn.close()
        return False, "Task token already used"
    conn.commit()
    conn.close()
    return True, "ok"

# ── FIX #4: M-Pesa callback IP verification ──────────────────────────────────

def _verify_mpesa_origin():
    """
    Verify that a callback came from an allowed Safaricom IP.
    In sandbox mode (MPESA_ALLOWED_IPS is empty) this is a no-op.
    In production, set MPESA_ALLOWED_IPS to a comma-separated list of
    Safaricom egress IPs (see https://developer.safaricom.co.ke/docs#ip-addresses).
    Returns (allowed:bool, reason:str).
    """
    if not MPESA_ALLOWED_IPS:
        # Sandbox: no IP restriction configured — allow all.
        return True, "sandbox"
    remote = request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()
    if remote in MPESA_ALLOWED_IPS:
        return True, remote
    log.warning(f"[MPESA CALLBACK] Rejected callback from disallowed IP: {remote}")
    return False, remote


def auth_required(f):
    @wraps(f)
    def w(*a, **k):
        if request.method == "OPTIONS":
            return jsonify({"success": True}), 200
        tok = request.headers.get("Authorization", "").replace("Bearer ", "")
        ph = verify_token(tok)
        if not ph:
            return jsonify({"success": False, "message": "Unauthorized"}), 401
        request.user_phone = ph
        return f(*a, **k)
    return w

def admin_required(f):
    @wraps(f)
    def w(*a, **k):
        if request.method == "OPTIONS":
            return jsonify({"success": True}), 200
        tok = request.headers.get("Authorization", "").replace("Bearer ", "")
        ph = verify_token(tok)
        if not ph:
            return jsonify({"success": False, "message": "Unauthorized"}), 401
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT is_admin FROM users WHERE phone=?", (ph,))
        row = c.fetchone()
        conn.close()
        if not row or not row["is_admin"]:
            return jsonify({"success": False, "message": "Admin only"}), 403
        request.user_phone = ph
        return f(*a, **k)
    return w


# ─────────────────────────────────────────────────────
# AUTH
# ─────────────────────────────────────────────────────
@app.route("/api/auth/register", methods=["POST"])
@limiter.limit("10 per hour")
def register():
    d = request.get_json(force=True)
    ph  = (d.get("phone", "")).strip()
    nm  = (d.get("name", "")).strip()
    pw  = d.get("password", "")
    ref = (d.get("referral_code", "")).strip().upper()

    if not ph or not pw:
        return jsonify({"success": False, "message": "Phone and password required"}), 400
    if len(pw) < 6:
        return jsonify({"success": False, "message": "Password must be 6+ characters"}), 400

    try:
        normalized = normalize_phone(ph)
    except ValueError as e:
        return jsonify({"success": False, "message": str(e)}), 400

    my_code = make_ref_code(nm or ph)
    referred_by = None
    conn = get_db()
    c = conn.cursor()

    if ref:
        c.execute("SELECT phone FROM users WHERE referral_code=?", (ref,))
        rr = c.fetchone()
        if rr:
            referred_by = rr["phone"]

    try:
        conn.execute(
            "INSERT INTO users (phone,name,password,referral_code,referred_by) VALUES (?,?,?,?,?)",
            (normalized, nm, hash_pw(pw), my_code, referred_by)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"success": False, "message": "Phone already registered"}), 409

    conn.close()
    return jsonify({
        "success": True, "token": gen_token(normalized),
        "name": nm, "phone": normalized,
        "balance": 0, "points": 0, "package": "None",
        "is_admin": False, "referral_code": my_code
    })


@app.route("/api/auth/login", methods=["POST"])
@limiter.limit("10 per minute")
def login():
    d = request.get_json(force=True)
    ph = (d.get("phone", "")).strip()
    pw = d.get("password", "")

    try:
        ph = normalize_phone(ph)
    except ValueError:
        return jsonify({"success": False, "message": "Invalid phone number"}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute(
        "SELECT name,password,balance,points,package,is_admin,referral_code FROM users WHERE phone=?",
        (ph,)
    )
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({"success": False, "message": "Phone not found"}), 404

    if not verify_pw(row["password"], pw):
        conn.close()
        return jsonify({"success": False, "message": "Incorrect password"}), 401

    if needs_rehash(row["password"]):
        conn.execute("UPDATE users SET password=? WHERE phone=?", (hash_pw(pw), ph))
        conn.commit()

    conn.close()
    return jsonify({
        "success": True, "token": gen_token(ph), "phone": ph,
        "name": row["name"], "balance": row["balance"],
        "points": row["points"], "package": row["package"],
        "is_admin": bool(row["is_admin"]), "referral_code": row["referral_code"]
    })


@app.route("/api/auth/logout", methods=["POST", "OPTIONS"])
@auth_required
def logout():
    tok = request.headers.get("Authorization", "").replace("Bearer ", "")
    tok_hash = _hash_token(tok)
    conn = get_db()
    conn.execute("DELETE FROM sessions WHERE token_hash=?", (tok_hash,))
    conn.commit()
    conn.close()
    return jsonify({"success": True})


# ─────────────────────────────────────────────────────
# OTP
# ─────────────────────────────────────────────────────
@app.route("/api/auth/otp/send", methods=["POST"])
@limiter.limit("3 per 10 minutes")
def send_otp():
    d = request.get_json(force=True)
    ph = (d.get("phone", "")).strip()

    try:
        ph = normalize_phone(ph)
    except ValueError:
        return jsonify({"success": False, "message": "Invalid phone number"}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT phone FROM users WHERE phone=?", (ph,))
    if not c.fetchone():
        conn.close()
        return jsonify({"success": False, "message": "Phone not registered"}), 404

    code = str(random.randint(100000, 999999))
    conn.execute(
        "INSERT OR REPLACE INTO otp_codes (phone,code,expires) VALUES (?,?,?)",
        (ph, code, int(time.time()) + 300)
    )
    conn.commit()
    conn.close()

    # FIX #6: SMS outside transaction (already was, kept clean)
    send_sms(ph, f"KALFIX TV: Your reset code is {code}. Valid 5 mins. Do not share.")

    resp = {"success": True, "message": "OTP sent to your number"}
    if SANDBOX:
        resp["dev_code"] = code
    return jsonify(resp)


@app.route("/api/auth/otp/verify", methods=["POST"])
@limiter.limit("5 per 10 minutes")
def verify_otp():
    d = request.get_json(force=True)
    ph   = (d.get("phone", "")).strip()
    code = (d.get("code", "")).strip()
    new_pw = d.get("new_password", "")

    try:
        ph = normalize_phone(ph)
    except ValueError:
        return jsonify({"success": False, "message": "Invalid phone number"}), 400

    if len(new_pw) < 6:
        return jsonify({"success": False, "message": "Password must be 6+ characters"}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT code,expires FROM otp_codes WHERE phone=?", (ph,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({"success": False, "message": "No OTP found"}), 400
    if int(time.time()) > row["expires"]:
        conn.close()
        return jsonify({"success": False, "message": "OTP expired"}), 400
    if not hmac.compare_digest(row["code"], code):
        conn.close()
        return jsonify({"success": False, "message": "Invalid OTP"}), 400

    conn.execute("UPDATE users SET password=? WHERE phone=?", (hash_pw(new_pw), ph))
    conn.execute("DELETE FROM otp_codes WHERE phone=?", (ph,))
    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": "Password updated"})


# ─────────────────────────────────────────────────────
# USER
# ─────────────────────────────────────────────────────
@app.route("/api/user/me", methods=["GET", "OPTIONS"])
@auth_required
def get_me():
    ph = request.user_phone
    conn = get_db()
    c = conn.cursor()
    check_package_expiry(conn, ph)
    c.execute(
        """SELECT name,balance,points,package,active,is_admin,referral_code,
                  total_referrals,referral_earnings,package_expires
           FROM users WHERE phone=?""",
        (ph,)
    )
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({"success": False, "message": "Not found"}), 404

    today = date.today().isoformat()
    c.execute("SELECT count FROM daily_tasks WHERE phone=? AND task_date=?", (ph, today))
    tc = c.fetchone()
    c.execute("SELECT COUNT(*) as n FROM notifications WHERE phone=? AND read=0", (ph,))
    notif = c.fetchone()
    conn.close()

    pkg = row["package"] or "None"
    pkg_data = PACKAGES.get(pkg, {})
    days_left = None
    if row["package_expires"]:
        # FIX #10: date comparison via date objects
        delta = (date.fromisoformat(row["package_expires"]) - date.today()).days
        days_left = max(delta, 0)

    return jsonify({
        "success": True, "name": row["name"], "balance": row["balance"],
        "points": row["points"], "package": pkg, "active": bool(row["active"]),
        "is_admin": bool(row["is_admin"]), "referral_code": row["referral_code"],
        "total_referrals": row["total_referrals"], "referral_earnings": row["referral_earnings"],
        "package_expires": row["package_expires"], "days_left": days_left,
        "tasks_today": tc["count"] if tc else 0,
        "daily_limit": pkg_data.get("daily_tasks", 0),
        "daily_earn": pkg_data.get("daily_earn", 0),
        "unread_notifications": notif["n"] if notif else 0
    })


@app.route("/api/packages", methods=["GET"])
def get_packages():
    return jsonify({"success": True, "packages": [{"name": k, **v} for k, v in PACKAGES.items()]})


@app.route("/api/winners", methods=["GET"])
def get_winners():
    """
    Public endpoint for the home-page 'recent winners' banner.
    Returns the most recent completed withdrawals (real M-Pesa payouts) and
    package purchases, with names masked for privacy
    (e.g. "Moses M." or "0712***259" if no name is set).

    No auth required — this is social proof shown to logged-out and
    logged-in users alike. No sensitive data (full phone, exact balances,
    user IDs) is ever exposed here.
    """
    limit = min(int(request.args.get("limit", 15)), 30)
    conn = get_db()
    c = conn.cursor()

    def mask_name(name, phone):
        name = (name or "").strip()
        if name:
            parts = name.split()
            first = parts[0]
            last_initial = (parts[1][0] + ".") if len(parts) > 1 else ""
            return f"{first} {last_initial}".strip()
        # Fall back to masked phone: 0712***259
        digits = re.sub(r'\D', '', phone)
        if len(digits) >= 6:
            return f"0{digits[-9:-6]}***{digits[-3:]}"
        return "A user"

    # Recent approved withdrawals — real M-Pesa payouts received
    c.execute("""
        SELECT w.amount, w.processed_at AS ts, u.name, u.phone
        FROM withdrawal_requests w
        LEFT JOIN users u ON w.phone = u.phone
        WHERE w.status='approved'
        ORDER BY w.id DESC LIMIT ?
    """, (limit,))
    withdrawals = [
        {
            "type": "withdrawal",
            "name": mask_name(r["name"], r["phone"]),
            "amount": r["amount"],
            "message": "received via M-Pesa",
            "timestamp": r["ts"]
        }
        for r in c.fetchall()
    ]

    # Recent package purchases — new earners joining
    c.execute("""
        SELECT t.amount, t.description, t.created_at AS ts, u.name, u.phone
        FROM transactions t
        LEFT JOIN users u ON t.phone = u.phone
        WHERE t.type='purchase' AND t.status='completed'
        ORDER BY t.id DESC LIMIT ?
    """, (limit,))
    purchases = [
        {
            "type": "purchase",
            "name": mask_name(r["name"], r["phone"]),
            "amount": r["amount"],
            "message": (r["description"] or "activated a package"),
            "timestamp": r["ts"]
        }
        for r in c.fetchall()
    ]

    conn.close()

    # Merge, sort by timestamp descending, cap to limit
    combined = sorted(
        withdrawals + purchases,
        key=lambda x: x["timestamp"] or "",
        reverse=True
    )[:limit]

    return jsonify({"success": True, "winners": combined})


# ─────────────────────────────────────────────────────
# NOTIFICATIONS
# ─────────────────────────────────────────────────────
@app.route("/api/notifications", methods=["GET", "OPTIONS"])
@auth_required
def get_notifications():
    ph = request.user_phone
    conn = get_db()
    c = conn.cursor()
    c.execute(
        "SELECT id,message,read,created_at FROM notifications WHERE phone=? ORDER BY id DESC LIMIT 30",
        (ph,)
    )
    rows = c.fetchall()
    conn.execute("UPDATE notifications SET read=1 WHERE phone=?", (ph,))
    conn.commit()
    conn.close()
    return jsonify({"success": True, "notifications": [
        {"id": r["id"], "message": r["message"], "read": bool(r["read"]), "created_at": r["created_at"]}
        for r in rows
    ]})


# ─────────────────────────────────────────────────────
# REFERRALS
# ─────────────────────────────────────────────────────
@app.route("/api/referrals", methods=["GET", "OPTIONS"])
@auth_required
def get_referrals():
    ph = request.user_phone
    conn = get_db()
    c = conn.cursor()
    c.execute(
        """SELECT r.referred,u.name,u.package,u.active,r.bonus_paid,r.created_at
           FROM referrals r LEFT JOIN users u ON r.referred=u.phone
           WHERE r.referrer=? ORDER BY r.id DESC""",
        (ph,)
    )
    rows = c.fetchall()
    c.execute(
        "SELECT referral_code,total_referrals,referral_earnings FROM users WHERE phone=?",
        (ph,)
    )
    me = c.fetchone()
    conn.close()
    return jsonify({
        "success": True, "referral_code": me["referral_code"],
        "total_referrals": me["total_referrals"], "referral_earnings": me["referral_earnings"],
        "referral_bonus": REFERRAL_BONUS,
        "referrals": [
            {"phone": r["referred"], "name": r["name"] or "—", "package": r["package"],
             "active": bool(r["active"]), "bonus": r["bonus_paid"], "joined": r["created_at"]}
            for r in rows
        ]
    })


def process_referral_bonus(conn, new_user_phone, pkg_name):
    """
    Credit referral bonus to the referrer.
    FIX #6: SMS is NOT sent here — caller must dispatch SMS after conn.commit().
    Returns the referrer's phone if a bonus was paid, else None.
    """
    c = conn.cursor()
    c.execute("SELECT referred_by FROM users WHERE phone=?", (new_user_phone,))
    row = c.fetchone()
    if not row or not row["referred_by"]:
        return None
    referrer = row["referred_by"]
    c.execute(
        "SELECT COUNT(*) as n FROM referrals WHERE referrer=? AND referred=?",
        (referrer, new_user_phone)
    )
    if c.fetchone()["n"] == 0:
        conn.execute(
            "INSERT INTO referrals (referrer,referred) VALUES (?,?)",
            (referrer, new_user_phone)
        )
    conn.execute(
        """UPDATE users SET balance=balance+?,total_referrals=total_referrals+1,
           referral_earnings=referral_earnings+? WHERE phone=?""",
        (REFERRAL_BONUS, REFERRAL_BONUS, referrer)
    )
    conn.execute(
        "UPDATE referrals SET bonus_paid=? WHERE referrer=? AND referred=?",
        (REFERRAL_BONUS, referrer, new_user_phone)
    )
    log_tx(conn, referrer, "referral_bonus", REFERRAL_BONUS,
           f"Referral — {new_user_phone} activated {pkg_name}")
    push_notif(conn, referrer,
        f"Your referral activated {pkg_name}! Ksh {REFERRAL_BONUS:.0f} added to your balance.")
    return referrer  # caller sends SMS after commit


# ─────────────────────────────────────────────────────
# M-PESA STK PUSH
# ─────────────────────────────────────────────────────
@app.route("/api/package/buy", methods=["POST", "OPTIONS"])
@auth_required
@limiter.limit("5 per minute")
def buy_package():
    ph = request.user_phone
    d = request.get_json(force=True)
    pkg_name = d.get("package_name", "")
    if pkg_name not in PACKAGES:
        return jsonify({"success": False, "message": "Invalid package"}), 400

    amount = PACKAGES[pkg_name]["price"]

    try:
        mpesa_ph = normalize_phone(ph)
    except ValueError as e:
        return jsonify({"success": False, "message": str(e)}), 400

    tok = mpesa_token()
    if not tok:
        return jsonify({"success": False, "message": "M-Pesa service unavailable. Try again."}), 503

    pw, ts = mpesa_pw_ts()
    payload = {
        "BusinessShortCode": MPESA_SHORTCODE,
        "Password": pw,
        "Timestamp": ts,
        "TransactionType": "CustomerPayBillOnline",
        "Amount": amount,
        "PartyA": mpesa_ph,
        "PartyB": MPESA_SHORTCODE,
        "PhoneNumber": mpesa_ph,
        "CallBackURL": MPESA_CALLBACK_URL,
        "AccountReference": f"KALFIX-{pkg_name.replace(' ', '')}",
        "TransactionDesc": f"KALFIX TV {pkg_name} Package"
    }
    try:
        r = requests.post(MPESA_STK_URL, json=payload,
                          headers={"Authorization": f"Bearer {tok}"}, timeout=15)
        resp = r.json()
        log.info(f"[STK PUSH] {resp}")
        cid = resp.get("CheckoutRequestID")
        if not cid:
            return jsonify({"success": False, "message": resp.get("errorMessage", "STK push failed")}), 400

        conn = get_db()
        conn.execute(
            "INSERT OR REPLACE INTO mpesa_requests (checkout_id,phone,amount,package_name) VALUES (?,?,?,?)",
            (cid, ph, amount, pkg_name)
        )
        conn.commit()
        conn.close()
        return jsonify({
            "success": True, "checkout_id": cid,
            "message": f"Check your phone ({ph}) and enter M-Pesa PIN."
        })
    except Exception as e:
        log.error(f"[STK ERROR] {e}")
        return jsonify({"success": False, "message": "M-Pesa request failed. Try again."}), 503


@app.route("/api/mpesa/callback", methods=["POST"])
def mpesa_callback():
    # FIX #4: Verify callback origin before processing
    allowed, origin = _verify_mpesa_origin()
    if not allowed:
        return jsonify({"ResultCode": 1, "ResultDesc": "Forbidden"}), 403

    data = request.get_json(force=True)
    cb   = data.get("Body", {}).get("stkCallback", {})
    code = cb.get("ResultCode")
    cid  = cb.get("CheckoutRequestID")
    log.info(f"[STK CALLBACK] code={code} cid={cid} origin={origin}")

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT phone,package_name FROM mpesa_requests WHERE checkout_id=?", (cid,))
    row = c.fetchone()

    referrer_for_sms = None
    ph = pkg = None

    if row:
        ph, pkg = row["phone"], row["package_name"]
        if code == 0:
            expiry = expiry_date()
            conn.execute("UPDATE mpesa_requests SET status='completed' WHERE checkout_id=?", (cid,))
            conn.execute(
                "UPDATE users SET package=?,active=1,package_expires=? WHERE phone=?",
                (pkg, expiry, ph)
            )
            log_tx(conn, ph, "purchase", PACKAGES.get(pkg, {}).get("price", 0),
                   f"Package: {pkg}", "completed", cid)
            referrer_for_sms = process_referral_bonus(conn, ph, pkg)
            push_notif(conn, ph,
                f"{pkg} activated until {expiry}! Start watching to earn Ksh {PACKAGES[pkg]['daily_earn']}/day.")
        else:
            conn.execute("UPDATE mpesa_requests SET status='failed' WHERE checkout_id=?", (cid,))
            push_notif(conn, ph, "Payment failed or cancelled. Please try again.")

    conn.commit()
    conn.close()

    # FIX #6: SMS dispatched after commit, outside transaction
    if ph and pkg and code == 0:
        send_sms(ph,
            f"KALFIX TV: {pkg} package active until {expiry}. Earn Ksh {PACKAGES[pkg]['daily_earn']}/day. Open app now!")
        if referrer_for_sms:
            send_sms(referrer_for_sms,
                f"KALFIX TV: Your referral activated a package! Ksh {REFERRAL_BONUS:.0f} credited.")

    return jsonify({"ResultCode": 0, "ResultDesc": "Accepted"})


@app.route("/api/package/status/<cid>", methods=["GET", "OPTIONS"])
@auth_required
def pkg_status(cid):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT status,package_name FROM mpesa_requests WHERE checkout_id=?", (cid,))
    row = c.fetchone()
    conn.close()
    if not row:
        return jsonify({"success": False, "message": "Not found"}), 404
    return jsonify({"success": True, "status": row["status"], "package": row["package_name"]})


@app.route("/api/package/activate", methods=["POST", "OPTIONS"])
@auth_required
def activate_package():
    """Sandbox manual activation only. Blocked in production."""
    if not SANDBOX:
        return jsonify({"success": False, "message": "Manual activation disabled in production"}), 403
    ph = request.user_phone
    d = request.get_json(force=True)
    pkg = d.get("package_name", "")
    if pkg not in PACKAGES:
        return jsonify({"success": False, "message": "Invalid package"}), 400
    expiry = expiry_date()
    conn = get_db()
    conn.execute(
        "UPDATE users SET package=?,active=1,package_expires=? WHERE phone=?",
        (pkg, expiry, ph)
    )
    log_tx(conn, ph, "purchase", PACKAGES[pkg]["price"], f"Package: {pkg} (sandbox)")
    referrer_for_sms = process_referral_bonus(conn, ph, pkg)
    push_notif(conn, ph, f"{pkg} activated (sandbox) until {expiry}.")
    conn.commit()
    conn.close()
    # FIX #6: SMS after commit
    if referrer_for_sms:
        send_sms(referrer_for_sms,
            f"KALFIX TV: Your referral activated a package! Ksh {REFERRAL_BONUS:.0f} credited.")
    return jsonify({"success": True, "message": f"{pkg} activated! Expires {expiry}.", "expires": expiry})


# ─────────────────────────────────────────────────────
# TASKS
# ─────────────────────────────────────────────────────
@app.route("/api/tasks/start", methods=["POST", "OPTIONS"])
@auth_required
@limiter.limit("20 per hour")
def task_start():
    ph = request.user_phone
    d  = request.get_json(force=True)
    video_id = (d.get("video_id", "")).strip()
    if not video_id:
        return jsonify({"success": False, "message": "video_id required"}), 400

    conn = get_db()
    if not check_package_expiry(conn, ph):
        conn.close()
        return jsonify({"success": False, "message": "No active package or package expired"}), 403

    c = conn.cursor()
    c.execute("SELECT package FROM users WHERE phone=?", (ph,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({"success": False, "message": "User not found"}), 404

    today = date.today().isoformat()
    pkg_data = PACKAGES.get(row["package"], {})
    daily_limit = pkg_data.get("daily_tasks", 0)

    c.execute("SELECT count FROM daily_tasks WHERE phone=? AND task_date=?", (ph, today))
    tc = c.fetchone()
    done = tc["count"] if tc else 0

    if done >= daily_limit:
        conn.close()
        return jsonify({"success": False,
                        "message": f"Daily limit of {daily_limit} tasks reached"}), 429

    token = issue_task_token(ph, video_id)
    conn.close()
    return jsonify({
        "success": True, "task_token": token,
        "expires_in": 720, "min_watch_seconds": 570
    })


@app.route("/api/tasks/earn", methods=["POST", "OPTIONS"])
@auth_required
@limiter.limit("20 per hour")
def earn():
    ph    = request.user_phone
    d     = request.get_json(force=True)
    token = (d.get("task_token", "")).strip()

    if not token:
        return jsonify({"success": False, "message": "task_token required — did you call /tasks/start?"}), 400

    ok, reason = consume_task_token(token, ph)
    if not ok:
        return jsonify({"success": False, "message": reason}), 400

    today = date.today().isoformat()
    conn  = get_db()
    c     = conn.cursor()

    if not check_package_expiry(conn, ph):
        conn.close()
        return jsonify({"success": False, "message": "Package expired"}), 403

    c.execute("SELECT package FROM users WHERE phone=?", (ph,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({"success": False, "message": "User not found"}), 404

    pkg_name     = row["package"]
    pkg          = PACKAGES.get(pkg_name)
    if not pkg:
        conn.close()
        return jsonify({"success": False, "message": "Invalid package"}), 400

    daily_limit  = pkg["daily_tasks"]
    pts_per_task = pkg["pts_per_task"]

    c.execute("SELECT count FROM daily_tasks WHERE phone=? AND task_date=?", (ph, today))
    tc   = c.fetchone()
    done = tc["count"] if tc else 0

    if done >= daily_limit:
        conn.close()
        return jsonify({"success": False,
                        "message": f"Daily limit of {daily_limit} tasks reached"}), 429

    with conn:
        conn.execute("UPDATE users SET points=points+? WHERE phone=?", (pts_per_task, ph))
        conn.execute(
            """INSERT INTO daily_tasks (phone,task_date,count) VALUES (?,?,1)
               ON CONFLICT(phone,task_date) DO UPDATE SET count=count+1""",
            (ph, today)
        )
        log_tx(conn, ph, "earn", pts_per_task, f"Task {done+1}/{daily_limit} ({pkg_name})")
        if done + 1 >= daily_limit:
            push_notif(conn, ph,
                f"All {daily_limit} tasks complete for today! Convert your points to cash.")

    c.execute("SELECT points,balance FROM users WHERE phone=?", (ph,))
    updated = c.fetchone()
    conn.close()

    return jsonify({
        "success": True,
        "total_pending": updated["points"],
        "current_balance": updated["balance"],
        "tasks_today": done + 1,
        "daily_limit": daily_limit,
        "pts_earned": pts_per_task
    })


# ─────────────────────────────────────────────────────
# VIDEOS
# ─────────────────────────────────────────────────────
@app.route("/api/videos", methods=["GET", "OPTIONS"])
@auth_required
def get_videos():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id,title FROM youtube_videos WHERE active=1 ORDER BY added_at")
    rows = c.fetchall()
    conn.close()
    return jsonify({"success": True, "videos": [{"id": r["id"], "title": r["title"]} for r in rows]})


# ─────────────────────────────────────────────────────
# WALLET
# ─────────────────────────────────────────────────────
@app.route("/api/wallet/convert", methods=["POST", "OPTIONS"])
@auth_required
@limiter.limit("10 per hour")
def convert():
    ph = request.user_phone
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT points FROM users WHERE phone=?", (ph,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({"success": False, "message": "Not found"}), 404
    if row["points"] <= 0:
        conn.close()
        return jsonify({"success": False, "message": "No points to convert"})

    pts    = row["points"]
    earned = round(pts * POINTS_TO_KES, 2)

    with conn:
        conn.execute(
            "UPDATE users SET points=0, balance=ROUND(balance+?,2) WHERE phone=?",
            (earned, ph)
        )
        log_tx(conn, ph, "convert", earned, f"Converted {pts} pts -> Ksh {earned}")
        push_notif(conn, ph, f"Converted {pts} pts -> Ksh {earned}.")

    c.execute("SELECT balance FROM users WHERE phone=?", (ph,))
    new_bal = c.fetchone()["balance"]
    conn.close()
    return jsonify({
        "success": True, "new_balance": new_bal,
        "message": f"Converted {pts} pts -> Ksh {earned}"
    })


@app.route("/api/wallet/withdraw/request", methods=["POST", "OPTIONS"])
@auth_required
@limiter.limit("5 per hour")
def request_withdrawal():
    ph = request.user_phone
    d  = request.get_json(force=True)

    try:
        amount = float(d.get("amount", 0))
    except (TypeError, ValueError):
        return jsonify({"success": False, "message": "Invalid amount"}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT balance FROM users WHERE phone=?", (ph,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({"success": False, "message": "Not found"}), 404

    if amount < MIN_WITHDRAWAL:
        conn.close()
        return jsonify({"success": False,
                        "message": f"Minimum withdrawal is Ksh {MIN_WITHDRAWAL:.0f}"}), 400
    if row["balance"] < amount:
        conn.close()
        return jsonify({"success": False, "message": "Insufficient balance"}), 400

    c.execute(
        "SELECT COUNT(*) as n FROM withdrawal_requests WHERE phone=? AND status='pending'",
        (ph,)
    )
    if c.fetchone()["n"] >= 1:
        conn.close()
        return jsonify({"success": False,
                        "message": "You already have a pending withdrawal. Wait for it to be processed."}), 400

    new_bal = round(row["balance"] - amount, 2)
    with conn:
        conn.execute("UPDATE users SET balance=? WHERE phone=?", (new_bal, ph))
        conn.execute("INSERT INTO withdrawal_requests (phone,amount) VALUES (?,?)", (ph, amount))
        log_tx(conn, ph, "withdraw_pending", amount,
               "Withdrawal request — pending admin approval", "pending")
        push_notif(conn, ph,
            f"Withdrawal request of Ksh {int(amount)} submitted. Processing within 24 hours.")

    conn.close()
    return jsonify({
        "success": True, "new_balance": new_bal,
        "message": f"Withdrawal of Ksh {int(amount)} queued for approval. Processing within 24hrs."
    })


@app.route("/api/wallet/history", methods=["GET", "OPTIONS"])
@auth_required
def history():
    ph = request.user_phone
    conn = get_db()
    c = conn.cursor()
    c.execute(
        """SELECT type,amount,description,status,created_at FROM transactions
           WHERE phone=? ORDER BY id DESC LIMIT 50""",
        (ph,)
    )
    rows = c.fetchall()
    conn.close()
    return jsonify({"success": True, "transactions": [
        {"type": r["type"], "amount": r["amount"], "description": r["description"],
         "status": r["status"], "created_at": r["created_at"]}
        for r in rows
    ]})


# ─────────────────────────────────────────────────────
# M-PESA B2C CALLBACK
# ─────────────────────────────────────────────────────
@app.route("/api/mpesa/b2c/callback", methods=["POST"])
def b2c_callback():
    # FIX #4: Verify callback origin
    allowed, origin = _verify_mpesa_origin()
    if not allowed:
        return jsonify({"ResultCode": 1, "ResultDesc": "Forbidden"}), 403

    data   = request.get_json(force=True)
    result = data.get("Result", {})
    code   = result.get("ResultCode")
    ref    = result.get("OriginatorConversationID", "")
    log.info(f"[B2C CALLBACK] code={code} ref={ref} origin={origin}")

    if code == 0:
        log.info(f"[B2C] Payment successful ref={ref}")
    else:
        log.warning(f"[B2C] Payment failed code={code} ref={ref}")
        conn = get_db()
        c = conn.cursor()
        c.execute(
            "SELECT phone,amount FROM withdrawal_requests WHERE mpesa_ref=?",
            (ref,)
        )
        row = c.fetchone()
        ph = amt = None
        if row:
            ph, amt = row["phone"], row["amount"]
            with conn:
                conn.execute(
                    "UPDATE users SET balance=balance+? WHERE phone=?",
                    (amt, ph)
                )
                conn.execute(
                    "UPDATE withdrawal_requests SET status='failed' WHERE mpesa_ref=?",
                    (ref,)
                )
                push_notif(conn, ph,
                    f"Withdrawal of Ksh {int(amt)} failed. Amount refunded.")
        conn.close()
        # FIX #6: SMS after commit
        if ph:
            send_sms(ph, f"KALFIX TV: Withdrawal of Ksh {int(amt)} failed. Amount refunded to your balance.")
    return jsonify({"ResultCode": 0, "ResultDesc": "Accepted"})


# ─────────────────────────────────────────────────────
# CRON — idempotent daily reset
# ─────────────────────────────────────────────────────
@app.route("/api/cron/daily-reset", methods=["POST"])
def daily_reset():
    if request.headers.get("X-Cron-Secret") != CRON_SECRET:
        return jsonify({"success": False, "message": "Forbidden"}), 403

    today = date.today().isoformat()
    conn  = get_db()
    c     = conn.cursor()

    try:
        conn.execute(
            "INSERT INTO cron_runs (job_name,run_date) VALUES (?,?)",
            ("daily-reset", today)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"success": False, "message": "Already run today"}), 409

    c.execute("SELECT phone,name,package,package_expires FROM users WHERE active=1 AND is_admin=0")
    users = c.fetchall()

    # Collect SMS payloads to send after DB work is done (FIX #6)
    sms_queue = []
    notified = 0

    for u in users:
        ph  = u["phone"]
        pkg = PACKAGES.get(u["package"], {})
        if not pkg:
            continue
        expires = u["package_expires"]
        if expires:
            # FIX #10: date object comparison
            delta = (date.fromisoformat(expires) - date.today()).days
            if delta == 7:
                push_notif(conn, ph,
                    f"Your {u['package']} package expires in 7 days ({expires}). Renew soon!")
                sms_queue.append((ph,
                    f"KALFIX TV: Your {u['package']} package expires in 7 days. Renew to keep earning!"))
            elif delta == 3:
                push_notif(conn, ph,
                    f"Your {u['package']} package expires in 3 days ({expires}). Renew now!")
                sms_queue.append((ph,
                    f"KALFIX TV: URGENT — Your package expires in 3 days. Renew now!"))
            elif delta <= 0:
                conn.execute("UPDATE users SET active=0 WHERE phone=?", (ph,))
                push_notif(conn, ph,
                    f"Your {u['package']} package has expired. Renew to continue earning.")
                sms_queue.append((ph,
                    f"KALFIX TV: Your package expired. Renew today to continue earning daily!"))
                continue

        msg = (f"Good morning! Your {u['package']} tasks are ready. "
               f"Watch {pkg['daily_tasks']} video(s) to earn Ksh {pkg['daily_earn']} today!")
        push_notif(conn, ph, msg)
        sms_queue.append((ph, f"KALFIX TV: {msg}"))
        notified += 1

    conn.commit()
    conn.close()

    # FIX #6: All SMS sent after DB commit
    for (ph, msg) in sms_queue:
        send_sms(ph, msg)

    return jsonify({"success": True, "notified": notified})


# ─────────────────────────────────────────────────────
# ADMIN
# ─────────────────────────────────────────────────────
@app.route("/api/admin/stats", methods=["GET", "OPTIONS"])
@admin_required
def admin_stats():
    conn = get_db()
    c = conn.cursor()
    today = date.today().isoformat()
    c.execute("SELECT COUNT(*) as n FROM users WHERE is_admin=0"); total = c.fetchone()["n"]
    c.execute("SELECT COUNT(*) as n FROM users WHERE active=1 AND is_admin=0"); active = c.fetchone()["n"]
    c.execute("SELECT COALESCE(SUM(balance),0) as s FROM users"); total_bal = c.fetchone()["s"]
    c.execute("SELECT COALESCE(SUM(amount),0) as s FROM transactions WHERE type='purchase'"); rev = c.fetchone()["s"]
    c.execute("SELECT COALESCE(SUM(count),0) as s FROM daily_tasks WHERE task_date=?", (today,)); tasks = c.fetchone()["s"]
    c.execute("SELECT COUNT(*) as n FROM withdrawal_requests WHERE status='pending'"); pend_wd = c.fetchone()["n"]
    c.execute("SELECT COALESCE(SUM(amount),0) as s FROM withdrawal_requests WHERE status='pending'"); pend_amt = c.fetchone()["s"]
    c.execute("SELECT COUNT(*) as n FROM referrals"); total_refs = c.fetchone()["n"]
    c.execute("SELECT COALESCE(SUM(bonus_paid),0) as s FROM referrals"); ref_paid = c.fetchone()["s"]
    conn.close()
    return jsonify({
        "success": True, "total_users": total, "active_users": active,
        "total_balance": round(total_bal, 2), "total_revenue": round(rev, 2),
        "tasks_today": tasks, "pending_withdrawals": pend_wd,
        "pending_withdrawal_amount": round(pend_amt, 2),
        "total_referrals": total_refs, "referral_payouts": round(ref_paid, 2)
    })


@app.route("/api/admin/withdrawals", methods=["GET", "OPTIONS"])
@admin_required
def admin_withdrawals():
    status = request.args.get("status", "pending")
    conn = get_db()
    c = conn.cursor()
    c.execute(
        """SELECT w.id,w.phone,u.name,w.amount,w.status,w.admin_note,
                  w.mpesa_ref,w.requested_at,w.processed_at
           FROM withdrawal_requests w LEFT JOIN users u ON w.phone=u.phone
           WHERE w.status=? ORDER BY w.id DESC LIMIT 100""",
        (status,)
    )
    rows = c.fetchall()
    conn.close()
    return jsonify({"success": True, "withdrawals": [
        {"id": r["id"], "phone": r["phone"], "name": r["name"] or "—",
         "amount": r["amount"], "status": r["status"], "admin_note": r["admin_note"],
         "mpesa_ref": r["mpesa_ref"], "requested_at": r["requested_at"],
         "processed_at": r["processed_at"]}
        for r in rows
    ]})


@app.route("/api/admin/withdrawals/<int:wd_id>/approve", methods=["POST", "OPTIONS"])
@admin_required
def approve_withdrawal(wd_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM withdrawal_requests WHERE id=? AND status='pending'", (wd_id,))
    wd = c.fetchone()
    if not wd:
        conn.close()
        return jsonify({"success": False, "message": "Request not found or already processed"}), 404

    ph     = wd["phone"]
    amount = wd["amount"]

    tok = mpesa_token()
    if not tok:
        conn.close()
        return jsonify({"success": False, "message": "M-Pesa unavailable"}), 503

    try:
        mpesa_ph = normalize_phone(ph)
    except ValueError as e:
        conn.close()
        return jsonify({"success": False, "message": str(e)}), 400

    payload = {
        "InitiatorName":      MPESA_B2C_INITIATOR,
        "SecurityCredential": MPESA_B2C_PASSWORD,
        "CommandID":          "BusinessPayment",
        "Amount":             int(amount),
        "PartyA":             MPESA_SHORTCODE,
        "PartyB":             mpesa_ph,
        "Remarks":            f"KALFIX TV Withdrawal #{wd_id}",
        "QueueTimeOutURL":    MPESA_B2C_CALLBACK,
        "ResultURL":          MPESA_B2C_CALLBACK,
        "Occasion":           ""
    }
    try:
        r = requests.post(MPESA_B2C_URL, json=payload,
                          headers={"Authorization": f"Bearer {tok}"}, timeout=15)
        resp = r.json()
        log.info(f"[B2C APPROVE] {resp}")
        if resp.get("ResponseCode") != "0":
            conn.close()
            return jsonify({"success": False,
                            "message": resp.get("ResponseDescription", "B2C failed")}), 400

        mpesa_ref = resp.get("ConversationID", "")
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        with conn:
            conn.execute(
                """UPDATE withdrawal_requests
                   SET status='approved',mpesa_ref=?,processed_at=?,admin_note='Approved by admin'
                   WHERE id=?""",
                (mpesa_ref, now, wd_id)
            )
            conn.execute(
                """UPDATE transactions SET status='completed',ref=?
                   WHERE phone=? AND type='withdraw_pending' AND status='pending'
                   ORDER BY rowid DESC LIMIT 1""",
                (mpesa_ref, ph)
            )
            push_notif(conn, ph, f"Withdrawal of Ksh {int(amount)} approved and sent to your M-Pesa!")

        conn.close()
        # FIX #6: SMS after commit
        send_sms(ph, f"KALFIX TV: Ksh {int(amount)} sent to your M-Pesa. Ref: {mpesa_ref}")
        return jsonify({"success": True,
                        "message": f"Ksh {int(amount)} sent to {ph}",
                        "mpesa_ref": mpesa_ref})
    except Exception as e:
        conn.close()
        log.error(f"[B2C APPROVE ERROR] {e}")
        return jsonify({"success": False, "message": "M-Pesa request failed"}), 503


@app.route("/api/admin/withdrawals/<int:wd_id>/reject", methods=["POST", "OPTIONS"])
@admin_required
def reject_withdrawal(wd_id):
    d = request.get_json(force=True)
    note = (d.get("note", "No reason given")).strip()
    conn = get_db()
    c = conn.cursor()
    c.execute(
        "SELECT phone,amount FROM withdrawal_requests WHERE id=? AND status='pending'",
        (wd_id,)
    )
    wd = c.fetchone()
    if not wd:
        conn.close()
        return jsonify({"success": False, "message": "Not found or already processed"}), 404

    ph, amount = wd["phone"], wd["amount"]
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    with conn:
        conn.execute("UPDATE users SET balance=balance+? WHERE phone=?", (amount, ph))
        conn.execute(
            "UPDATE withdrawal_requests SET status='rejected',admin_note=?,processed_at=? WHERE id=?",
            (note, now, wd_id)
        )
        conn.execute(
            """UPDATE transactions SET status='rejected'
               WHERE phone=? AND type='withdraw_pending' AND status='pending'
               ORDER BY rowid DESC LIMIT 1""",
            (ph,)
        )
        push_notif(conn, ph,
            f"Withdrawal of Ksh {int(amount)} was rejected. Reason: {note}. Amount refunded.")

    conn.close()
    # FIX #6: SMS after commit
    send_sms(ph, f"KALFIX TV: Withdrawal of Ksh {int(amount)} rejected — {note}. Amount refunded.")
    return jsonify({"success": True, "message": f"Rejected and refunded Ksh {int(amount)} to {ph}"})


@app.route("/api/admin/users", methods=["GET", "OPTIONS"])
@admin_required
def admin_users():
    page   = int(request.args.get("page", 1))
    pp     = 20
    offset = (page - 1) * pp
    q      = request.args.get("q", "")
    today  = date.today().isoformat()
    conn   = get_db()
    c      = conn.cursor()

    base = """SELECT phone,name,balance,points,package,active,package_expires,
                     total_referrals,referral_earnings,created_at
              FROM users WHERE is_admin=0"""
    if q:
        c.execute(f"{base} AND (phone LIKE ? OR name LIKE ?) ORDER BY created_at DESC LIMIT ? OFFSET ?",
                  (f"%{q}%", f"%{q}%", pp, offset))
    else:
        c.execute(f"{base} ORDER BY created_at DESC LIMIT ? OFFSET ?", (pp, offset))

    rows   = c.fetchall()
    result = []
    for r in rows:
        c.execute("SELECT count FROM daily_tasks WHERE phone=? AND task_date=?", (r["phone"], today))
        tc = c.fetchone()
        pkg_data  = PACKAGES.get(r["package"], {})
        days_left = None
        if r["package_expires"]:
            # FIX #10: date object comparison
            days_left = max((date.fromisoformat(r["package_expires"]) - date.today()).days, 0)
        result.append({
            "phone": r["phone"], "name": r["name"], "balance": r["balance"],
            "points": r["points"], "package": r["package"], "active": bool(r["active"]),
            "package_expires": r["package_expires"], "days_left": days_left,
            "daily_earn": pkg_data.get("daily_earn", 0),
            "daily_tasks": pkg_data.get("daily_tasks", 0),
            "tasks_today": tc["count"] if tc else 0,
            "total_referrals": r["total_referrals"], "referral_earnings": r["referral_earnings"],
            "created_at": r["created_at"]
        })

    c.execute("SELECT COUNT(*) as n FROM users WHERE is_admin=0")
    total = c.fetchone()["n"]
    conn.close()
    return jsonify({"success": True, "users": result, "total": total, "page": page})


# FIX #9: Admin transactions endpoint now supports pagination
@app.route("/api/admin/transactions", methods=["GET", "OPTIONS"])
@admin_required
def admin_txns():
    page   = max(int(request.args.get("page", 1)), 1)
    pp     = 50
    offset = (page - 1) * pp
    phone_filter = request.args.get("phone", "").strip()
    type_filter  = request.args.get("type", "").strip()

    conn = get_db()
    c = conn.cursor()

    where_clauses = []
    params = []
    if phone_filter:
        where_clauses.append("t.phone LIKE ?")
        params.append(f"%{phone_filter}%")
    if type_filter:
        where_clauses.append("t.type=?")
        params.append(type_filter)

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    c.execute(
        f"""SELECT t.phone,u.name,t.type,t.amount,t.description,t.status,t.created_at
            FROM transactions t LEFT JOIN users u ON t.phone=u.phone
            {where_sql}
            ORDER BY t.id DESC LIMIT ? OFFSET ?""",
        params + [pp, offset]
    )
    rows = c.fetchall()

    c.execute(
        f"SELECT COUNT(*) as n FROM transactions t {where_sql}",
        params
    )
    total = c.fetchone()["n"]
    conn.close()

    return jsonify({
        "success": True,
        "transactions": [
            {"phone": r["phone"], "name": r["name"], "type": r["type"], "amount": r["amount"],
             "description": r["description"], "status": r["status"], "created_at": r["created_at"]}
            for r in rows
        ],
        "total": total,
        "page": page,
        "pages": max(1, -(-total // pp))  # ceiling division
    })


@app.route("/api/admin/referrals", methods=["GET", "OPTIONS"])
@admin_required
def admin_referrals():
    conn = get_db()
    c = conn.cursor()
    c.execute(
        """SELECT r.referrer,u1.name as rname,r.referred,u2.name as nname,
                  u2.package,r.bonus_paid,r.created_at
           FROM referrals r LEFT JOIN users u1 ON r.referrer=u1.phone
           LEFT JOIN users u2 ON r.referred=u2.phone ORDER BY r.id DESC LIMIT 100"""
    )
    rows = c.fetchall()
    conn.close()
    return jsonify({"success": True, "referrals": [
        {"referrer": r["referrer"], "ref_name": r["rname"] or "—",
         "referred": r["referred"], "new_name": r["nname"] or "—",
         "package": r["package"], "bonus": r["bonus_paid"], "date": r["created_at"]}
        for r in rows
    ]})


@app.route("/api/admin/videos", methods=["GET", "OPTIONS"])
@admin_required
def admin_videos():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id,title,active,added_at FROM youtube_videos ORDER BY added_at DESC")
    rows = c.fetchall()
    conn.close()
    return jsonify({"success": True, "videos": [
        {"id": r["id"], "title": r["title"], "active": bool(r["active"]), "added_at": r["added_at"]}
        for r in rows
    ]})


@app.route("/api/admin/videos/add", methods=["POST", "OPTIONS"])
@admin_required
def admin_add_video():
    d = request.get_json(force=True)
    vid = (d.get("id", "")).strip()
    ttl = (d.get("title", "")).strip()
    if not vid or not ttl:
        return jsonify({"success": False, "message": "ID and title required"}), 400
    try:
        conn = get_db()
        conn.execute("INSERT INTO youtube_videos (id,title) VALUES (?,?)", (vid, ttl))
        conn.commit()
        conn.close()
        return jsonify({"success": True, "message": "Video added"})
    except sqlite3.IntegrityError:
        return jsonify({"success": False, "message": "Video ID already exists"}), 409


@app.route("/api/admin/videos/<vid_id>/toggle", methods=["POST", "OPTIONS"])
@admin_required
def admin_toggle_video(vid_id):
    conn = get_db()
    conn.execute(
        "UPDATE youtube_videos SET active=CASE WHEN active=1 THEN 0 ELSE 1 END WHERE id=?",
        (vid_id,)
    )
    conn.commit()
    conn.close()
    return jsonify({"success": True})


@app.route("/api/admin/videos/<vid_id>", methods=["DELETE", "OPTIONS"])
@admin_required
def admin_del_video(vid_id):
    conn = get_db()
    conn.execute("DELETE FROM youtube_videos WHERE id=?", (vid_id,))
    conn.commit()
    conn.close()
    return jsonify({"success": True})


@app.route("/api/admin/user/<phone>/adjust", methods=["POST", "OPTIONS"])
@admin_required
def admin_adjust(phone):
    d = request.get_json(force=True)
    action = d.get("action")
    value  = d.get("value")
    conn   = get_db()

    if action == "set_package" and value in PACKAGES:
        expiry = expiry_date()
        conn.execute(
            "UPDATE users SET package=?,active=1,package_expires=? WHERE phone=?",
            (value, expiry, phone)
        )
        push_notif(conn, phone, f"Package set to {value} by admin. Expires {expiry}.")

    elif action == "add_balance":
        # FIX #3: Validate that value is a positive number
        try:
            credit = float(value)
        except (TypeError, ValueError):
            conn.close()
            return jsonify({"success": False, "message": "Invalid amount"}), 400
        if credit <= 0:
            conn.close()
            return jsonify({"success": False, "message": "Amount must be greater than zero"}), 400
        conn.execute("UPDATE users SET balance=balance+? WHERE phone=?", (credit, phone))
        log_tx(conn, phone, "admin_credit", credit, "Admin credit")
        push_notif(conn, phone, f"Ksh {credit:.0f} credited by admin.")

    elif action == "deactivate":
        conn.execute(
            "UPDATE users SET active=0,package='None',package_expires=NULL WHERE phone=?",
            (phone,)
        )
        push_notif(conn, phone, "Account deactivated. Contact support.")

    elif action == "notify":
        # FIX: validate notify message is not empty
        if not value or not str(value).strip():
            conn.close()
            return jsonify({"success": False, "message": "Notification message cannot be empty"}), 400
        push_notif(conn, phone, str(value).strip())
        conn.commit()
        conn.close()
        send_sms(phone, f"KALFIX TV: {str(value).strip()}")
        return jsonify({"success": True, "message": "'notify' applied"})

    else:
        conn.close()
        return jsonify({"success": False, "message": f"Unknown or invalid action: {action}"}), 400

    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": f"'{action}' applied"})


@app.route("/api/admin/broadcast", methods=["POST", "OPTIONS"])
@admin_required
def admin_broadcast():
    d = request.get_json(force=True)
    message = (d.get("message", "")).strip()
    if not message:
        return jsonify({"success": False, "message": "Message required"}), 400
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT phone FROM users WHERE is_admin=0 AND active=1")
    users = c.fetchall()
    phones = [u["phone"] for u in users]
    for ph in phones:
        push_notif(conn, ph, message)
    conn.commit()
    conn.close()
    # FIX #6: SMS sent after commit
    for ph in phones:
        send_sms(ph, f"KALFIX TV: {message}")
    return jsonify({"success": True, "sent_to": len(phones)})




@app.route("/", methods=["GET"])
def index():
    from flask import render_template
    return render_template("index.html")


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "sandbox": SANDBOX, "time": datetime.now().isoformat()})


if __name__ == "__main__":
    port  = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=port, debug=debug)
