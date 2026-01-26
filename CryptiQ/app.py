import os, re, secrets
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

from cipher_tools.breakers import (
    atbash_break,
    base64_break,
    hex_break,
    binary_break,
    baconian_break
)
from dotenv import load_dotenv
load_dotenv()
from flask import (
    Flask, request, jsonify, render_template, redirect,
    url_for, session, flash, send_from_directory, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os
from datetime import datetime
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
import re

# --- Cipher tools ---
from cipher_tools.vigenere import *
from cipher_tools.caesar import caesar_break
from cipher_tools.permutation import permutation_break
from cipher_tools.columnar_transposition import columnar_break
from cipher_tools.frequency_analyser import analyse
from cipher_tools.affine import affine_break
from cipher_tools.amsco import amsco_break
from cipher_tools.railfence import railfence_break
from cipher_tools.polybius_square import *
from cipher_tools.unique import unique
from cipher_tools.replace import replace
from cipher_tools.random_tools import *

from datetime import datetime
from cipher_tools.breakers import (
            atbash_break,
            base64_break,
            hex_break,
            binary_break,
            baconian_break
        )
from cipher_tools.auto_break import auto_break  #  new auto detector
from cipher_tools.random_tools import nospace
from cipher_tools.random_tools import remove_punc
# from cipher_tools.playfair import make_score_fn, playfair_break
from helpers import get_db, current_user, set_currency, get_currency, get_currency_symbol

# PLAYFAIR_SCORE_FN, PLAYFAIR_USING_FILE = make_score_fn("english_tetragrams.txt")

FREE_MAX_LABS = 3          # free users can have up to 3 labs
FREE_MAX_TABS = 5 


def migrate_weekly_tables():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("PRAGMA table_info(cipher_submissions)")
    cols = {row["name"] for row in cur.fetchall()}
    if "score" not in cols:
        cur.execute("ALTER TABLE cipher_submissions ADD COLUMN score INTEGER DEFAULT 0")
    if "season" not in cols:
        cur.execute("ALTER TABLE cipher_submissions ADD COLUMN season INTEGER DEFAULT 1")
    if "solve_time_seconds" not in cols:
        cur.execute("ALTER TABLE cipher_submissions ADD COLUMN solve_time_seconds INTEGER DEFAULT NULL")
    if "created_at" not in cols:
        cur.execute("ALTER TABLE cipher_submissions ADD COLUMN created_at TEXT DEFAULT CURRENT_TIMESTAMP")
    conn.commit()
    conn.close()


from datetime import datetime, timezone

def get_current_season():
    """Season 1 starts 2025-12-01 00:00 UTC. Each season is 2 calendar months."""
    start = datetime(2025, 12, 1, tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)

    months_since = (now.year - start.year) * 12 + (now.month - start.month)
    return max(1, (months_since // 2) + 1)


import re

# keep this small + explicit
BANNED_WORDS = {
    "fuck", "shit", "bitch", "cunt", "nigger", "faggot",
    "retard", "rape", "porn", "sex", "nazi",
}

NORMALIZE = str.maketrans({
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "@": "a",
    "$": "s"
})

def normalize(text):
    return text.lower().translate(NORMALIZE)

def contains_profanity(text):
    clean = normalize(text)
    return any(
        re.search(rf"\b{re.escape(word)}\b", clean)
        for word in BANNED_WORDS
    )


# ----- Configuration -----
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
DB_PATH = os.path.join(BASE_DIR, "cryptiq.db")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}

ADMIN_EMAIL = "jimcalstrom@gmail.com"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)

# ---- Mail configuration ----
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = "thecipherlab@gmail.com"   # your sender email
app.config["MAIL_PASSWORD"] = os.environ.get("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = ("The Cipher Lab Support", "thecipherlab@gmail.com")

mail = Mail(app)

app.secret_key = os.environ.get("CRYPTIQ_SECRET") or "dev-secret-key"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 6 * 1024 * 1024  # 6 MB upload limit

# Token generator for password resets
serializer = URLSafeTimedSerializer(app.secret_key)

# ----- Database helpers -----


def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT,
        password_hash TEXT NOT NULL,
        is_admin INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        body TEXT NOT NULL,
        image_filename TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        post_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        parent_comment_id INTEGER,
        body TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(post_id) REFERENCES posts(id),
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(parent_comment_id) REFERENCES comments(id)
    )
    """)
    conn.commit()
    conn.close()


def init_core_tables_on_boot():
    """Ensure core tables and forward migrations exist.

    This app is often run with an existing cryptiq.db created before newer
    features (e.g., nested comment replies). We run lightweight migrations on
    boot so older DBs keep working without manual schema edits.
    """
    # Create base tables if missing
    try:
        init_db()
    except Exception:
        # If something goes wrong here, the app can still start; individual
        # routes may raise clearer errors.
        pass

    # Apply incremental migrations
    try:
        migrate_db()
    except Exception:
        pass

    try:
        migrate_comments_table()
    except Exception:
        pass

    # Optional migrations that exist in this codebase
    for fn in ("migrate_shared_labs", "migrate_labs_pro_fields", "migrate_guest_setup_fields"):
        try:
            globals()[fn]()
        except Exception:
            pass

def migrate_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("PRAGMA table_info(users)")
    cols = {row["name"] for row in cur.fetchall()}
    if "email" not in cols:
        cur.execute("ALTER TABLE users ADD COLUMN email TEXT")
    if "is_admin" not in cols:
        cur.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0")
    if "has_posted" not in cols:
        cur.execute("ALTER TABLE users ADD COLUMN has_posted INTEGER NOT NULL DEFAULT 0")

    conn.commit()
    conn.close()


def migrate_comments_table():
    """Add parent_comment_id column + index if missing (supports nested replies)."""
    conn = get_db()
    cur = conn.cursor()

    cur.execute("PRAGMA table_info(comments)")
    cols = {row["name"] for row in cur.fetchall()}

    if "parent_comment_id" not in cols:
        cur.execute("ALTER TABLE comments ADD COLUMN parent_comment_id INTEGER")

    # Helpful index for thread lookups
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_comments_post_parent_time
        ON comments(post_id, parent_comment_id, created_at)
    """)

    conn.commit()
    conn.close()

def migrate_weekly_tables():
    conn = get_db()
    cur = conn.cursor()
    # Add score column if missing
    cur.execute("PRAGMA table_info(cipher_submissions)")
    cols = {row["name"] for row in cur.fetchall()}
    if "score" not in cols:
        cur.execute("ALTER TABLE cipher_submissions ADD COLUMN score INTEGER DEFAULT 0")
    conn.commit()
    conn.close()


import time
from collections import defaultdict, deque
from flask import request, jsonify

# ip -> endpoint -> deque[timestamps]
_RATE = defaultdict(lambda: defaultdict(deque))

def rate_limit(key: str, limit: int, window_s: int):
    """
    key: e.g. "api_cipher" or "ws_create"
    limit: requests allowed
    window_s: sliding window in seconds
    """
    # best-effort IP (works behind some proxies if you set ProxyFix; otherwise remote_addr)
    ip = request.headers.get("CF-Connecting-IP") or request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or request.remote_addr or "unknown"
    now = time.time()

    q = _RATE[ip][key]
    # drop old
    while q and q[0] <= now - window_s:
        q.popleft()

    if len(q) >= limit:
        return False, ip

    q.append(now)
    return True, ip


@app.after_request
def add_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "img-src 'self' data: https://api.producthunt.com https://ph-files.imgix.net https://www.producthunt.com; "
        "script-src 'self' 'unsafe-inline' https://www.producthunt.com; "
        "style-src 'self' 'unsafe-inline'; "
        "frame-src https://www.producthunt.com;"
    )
    return resp

from functools import wraps
from flask import abort

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user:
            return redirect(url_for("login"))
        if not user.get("is_admin"):
            abort(403)
        return fn(*args, **kwargs)
    return wrapper


def migrate_shared_labs():
    conn = get_db()
    cur = conn.cursor()

    # ensure FK enforcement (SQLite)
    cur.execute("PRAGMA foreign_keys=ON")

    # --- workspaces columns ---
    cur.execute("PRAGMA table_info(workspaces)")
    cols = {row["name"] if isinstance(row, sqlite3.Row) else row[1] for row in cur.fetchall()}

    if "share_token" not in cols:
        cur.execute("ALTER TABLE workspaces ADD COLUMN share_token TEXT")
    if "is_shared" not in cols:
        cur.execute("ALTER TABLE workspaces ADD COLUMN is_shared INTEGER NOT NULL DEFAULT 0")
    if "last_edited_by" not in cols:
        cur.execute("ALTER TABLE workspaces ADD COLUMN last_edited_by INTEGER")

    # --- collaborators table ---
    cur.execute("""
    CREATE TABLE IF NOT EXISTS workspace_collaborators (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      workspace_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      role TEXT NOT NULL DEFAULT 'editor',
      added_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(workspace_id, user_id),
      FOREIGN KEY(workspace_id) REFERENCES workspaces(id),
      FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_wc_workspace ON workspace_collaborators(workspace_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_wc_user ON workspace_collaborators(user_id)")

    # enforce uniqueness for tokens (since ALTER TABLE can't add UNIQUE)
    cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_workspaces_share_token ON workspaces(share_token)")

    conn.commit()
    conn.close()
# --- FIXED app.py (only change is migration function bug fix) ---

def migrate_guest_setup_fields():
    """Flags for accounts created via guest checkout (Pro-first flow)."""
    conn = get_db()
    cur = conn.cursor()

    # FIX: cols was never defined before
    cur.execute("PRAGMA table_info(users)")
    cols = {row[1] for row in cur.fetchall()}

    if "needs_password" not in cols:
        cur.execute(
            "ALTER TABLE users ADD COLUMN needs_password INTEGER NOT NULL DEFAULT 0"
        )

    if "needs_username" not in cols:
        cur.execute(
            "ALTER TABLE users ADD COLUMN needs_username INTEGER NOT NULL DEFAULT 0"
        )

    conn.commit()
    conn.close()




def migrate_labs_pro_fields():
    """Add/ensure Labs Pro billing-related columns on users table."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("PRAGMA table_info(users)")
    cols = {r[1] for r in cur.fetchall()}

    if "pro_current_period_end" not in cols:
        cur.execute("ALTER TABLE users ADD COLUMN pro_current_period_end TEXT")  # ISO string

    if "pro_cancel_at_period_end" not in cols:
        cur.execute("ALTER TABLE users ADD COLUMN pro_cancel_at_period_end INTEGER NOT NULL DEFAULT 0")

    if "labs_tour_seen" not in cols:
        cur.execute("ALTER TABLE users ADD COLUMN labs_tour_seen INTEGER NOT NULL DEFAULT 0")

    conn.commit()
    conn.close()

def ensure_admin_flag():
    if not ADMIN_EMAIL:
        return
    conn = get_db()
    conn.execute("UPDATE users SET is_admin=1 WHERE LOWER(IFNULL(email,'')) = LOWER(?)", (ADMIN_EMAIL,))
    conn.commit()
    conn.close()


# (Social login removed)


def is_admin(user):
    if not user:
        return False
    return (user.get("is_admin") == 1) or (user.get("email", "").lower() == ADMIN_EMAIL.lower())


def pro_limit(user, free_limit, pro_limit):
    return pro_limit if is_pro(user) else free_limit


def is_pro(user):
    if not user:
        return False

    try:
        # works for sqlite3.Row and dict
        return bool(user["is_pro"])
    except Exception:
        return False


def fetch_post(post_id):
    conn = get_db()
    cur = conn.execute("""
        SELECT 
            p.*,
            u.username AS author
        FROM posts p
        LEFT JOIN users u ON p.user_id = u.id
        WHERE p.id = ?
    """, (post_id,))
    post = cur.fetchone()
    conn.close()
    return post


def delete_image_file(filename):
    if not filename:
        return
    path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception:
        pass

def get_recent_posts(limit=6):
    conn = get_db()
    cur = conn.execute("""
        SELECT 
            p.id, 
            p.title, 
            p.body, 
            p.created_at, 
            u.username AS author
        FROM posts p
        LEFT JOIN users u ON p.user_id = u.id
        WHERE (u.banned IS NULL OR u.banned = 0)
        ORDER BY datetime(p.created_at) DESC
        LIMIT ?
    """, (limit,))
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]

# ------------------- HOME -------------------
@app.route("/", methods=["GET"])
def index():
    user = current_user()
    recent_posts = get_recent_posts(limit=6)
    return render_template("index.html", user=user, recent_posts=recent_posts)

app.add_url_rule("/", endpoint="home", view_func=index)

# ------------------- BREAKER -------------------
# ------------------- BREAKER -------------------
@app.route("/breaker", methods=["GET", "POST"])
def breaker():
    if request.method == "POST":
        text = request.form.get("text", "")
        cipher_type = request.form.get("cipher_type", "vigenere").lower()
        known_plaintext = request.form.get("known_plaintext", "").strip()

        # --- Parse fixed map ---
        fixed_map = None
        if known_plaintext and "=" in known_plaintext:
            fixed_map = {}
            pairs = [p.strip() for p in known_plaintext.replace(";", ",").split(",") if p.strip()]
            for pair in pairs:
                if "=" in pair:
                    ciph, plain = pair.split("=", 1)
                    if ciph and plain:
                        fixed_map[ciph.strip().upper()] = plain.strip().upper()

        key, plaintext, detected_cipher = None, text, cipher_type

        try:
            # ======================
            # Standard breakers
            # ======================
            if cipher_type == "caesar":
                key, plaintext = caesar_break(text)
            elif cipher_type == "vigenere":
                res = break_vigenere(text)   # returns Result(key, plaintext, method)
                key, plaintext = res.key, res.plaintext

                
            elif cipher_type == "affine":
                key, plaintext = affine_break(text)
            elif cipher_type == "amsco":
                key, plaintext = amsco_break(text)
            elif cipher_type == "railfence":
                key, plaintext = railfence_break(text)
            elif cipher_type == "columnar":
                key, plaintext = columnar_break(text)
            elif cipher_type == "permutation":
                key, plaintext = permutation_break(text)

            # ======================
            # Polybius (standardize → 2-stage substitution)
            # ======================
            elif cipher_type == "polybius":
                    key, plaintext = substitution_break(
                        polybius_standardize(text),
                        max_restarts=3,
                        sa_steps=2000,
                        seed=42,
                        time_limit_seconds=25,
                        threads=None,   # auto: Render → 1, local → cores
                        fixed=fixed_map,
                        verbose=True
                    )
                    
            # ======================
            # Substitution (true 2-stage pipeline)
            # ======================
            elif cipher_type == "substitution":
                key, plaintext = substitution_break(
                    text,
                    max_restarts=30,
                    sa_steps=14000,
                    seed=42,
                    time_limit_seconds=10,
                    threads=1,   # auto: Render → 1, local → cores
                    fixed=fixed_map,
                    verbose=True
                )
                
                
            # Non-key ciphers
            # ======================
            elif cipher_type == "atbash":
                key, plaintext = atbash_break(text)
            elif cipher_type == "base64":
                key, plaintext = base64_break(text)
            elif cipher_type == "hex":
                key, plaintext = hex_break(text)
            elif cipher_type == "binary":
                key, plaintext = binary_break(text)
            elif cipher_type == "baconian":
                key, plaintext = baconian_break(text)
            elif cipher_type == "playfair":
                # Choose budget based on how long you’ll allow per request
                # "fast" ~ quickest, "normal" balanced, "hard" stronger
                key_square, plaintext = playfair_break(
                    text,
                    score_fn=PLAYFAIR_SCORE_FN,
                    time_budget="fast",
                    seed=42
                )
                key = key_square  # return the 25-letter square as the "key"

            # ======================
            # AUTO-DETECT
            # ======================
            elif cipher_type == "auto":
                result = auto_break(text)
                detected_cipher = result.get("cipher", "Unknown")
                key = result.get("key")
                plaintext = result.get("plaintext")

            else:
                key, plaintext = None, "Unsupported cipher type."

        except Exception as e:
            key, plaintext, detected_cipher = None, f"Error breaking cipher: {e}", "Error"

        return jsonify({
            "cipher": detected_cipher,
            "key": key,
            "text": plaintext
        })

    return render_template("breaker.html", user=current_user())

# ------------------- Tools Page -------------------
@app.route("/tools", methods=["GET"])
def tools_page():
    return render_template("tools.html", user=current_user())

app.add_url_rule("/tools", endpoint="tools", view_func=tools_page)

# ------------------- Tools API -------------------

@app.route("/tools/run", methods=["POST"])
def tools_run():
    text = request.form.get("text", "")
    tool_type = request.form.get("tool_type", "").lower()

    if tool_type == "frequency":
        trigrams, bigrams, unigrams, cipher_type = analyse(text)
        unigrams_str = ", ".join([f"{letter}: {count}" for letter, count in unigrams])
        trigrams=", ".join([f"{letter}: {count}" for letter, count in trigrams])
        bigrams=", ".join([f"{letter}: {count}" for letter, count in bigrams])

        result_text = (
            f"Common trigrams: {trigrams}\n\n"
            f"Common bigrams: {bigrams}\n\n"
            f"Letter frequencies: {unigrams_str}\n\n"
            f"Likely cipher type: {cipher_type}"
        )

    elif tool_type == "polybius":
        initial_text = polybius_standardize(text)
        trigrams, bigrams, unigrams, cipher_type = analyse(initial_text)
        unigrams_str = ", ".join([f"{letter}: {count}" for letter, count in unigrams])
        result_text  = initial_text + "\n"
        trigrams=", ".join([f"{letter}: {count}" for letter, count in trigrams])
        unigrams_str = ", ".join([f"{letter}: {count}" for letter, count in unigrams])
        trigrams=", ".join([f"{letter}: {count}" for letter, count in trigrams])
        bigrams=", ".join([f"{letter}: {count}" for letter, count in bigrams])
        result_text += f"Common trigrams: {trigrams}\n"
        result_text += f"Common bigrams: {bigrams}\n"
        result_text += f"Letter frequencies: {unigrams_str}\n"

    elif tool_type == "unique":
        result_text = '\n'.join(unique(text))

    elif tool_type == "text_spacer":
        try:
            block_length = int(request.form.get("block_length", 5))
        except Exception:
            block_length = 5
        message = text.replace(' ', '')
        result_text = ' '.join(message[i:i+block_length] for i in range(0, len(message), block_length))

    elif tool_type == "text_replacer":
        to_replace = request.form.get("to_replace", "")
        replacement = request.form.get("replacement", "")
        result_text = replace(text, to_replace, replacement)

    elif tool_type == "substitution":
        result_text = text.upper()

    elif tool_type == "remove_spaces":
        # remove only spaces, do NOT strip punctuation
        result_text = nospace(text, remove_punctuation=False)

    elif tool_type == "remove_punctuation":
        # use your remove_punc function
        result_text = remove_punc(text)

    else:
        result_text = "Unknown tool selected."

    return jsonify({"text": result_text})

# ------------------- Info Page -------------------
@app.route("/info", methods=["GET"])
def info_page():
    return render_template("info.html", user=current_user())

app.add_url_rule("/info", endpoint="info", view_func=info_page)

# ------------------- Posts -------------------
# ------------------- Posts -------------------
@app.route("/posts", methods=["GET"])
def posts_list():
    user = current_user()

    page = max(int(request.args.get("page", 1)), 1)
    per_page = 10
    offset = (page - 1) * per_page

    sort = (request.args.get("sort") or "new").lower()
    if sort not in ("new", "top", "hot"):
        sort = "new"

    search = (request.args.get("search") or "").strip()

    conn = get_db()
    params = []

    # Always exclude banned users' posts
    base_condition = "(users.banned IS NULL OR users.banned = 0)"

    if search:
        like = f"%{search}%"
        where_clause = f"""
            WHERE {base_condition}
              AND (
                    posts.title LIKE ?
                 OR posts.body LIKE ?
                 OR users.username LIKE ?
              )
        """
        params.extend([like, like, like])
    else:
        where_clause = f"WHERE {base_condition}"

    if sort == "new":
        order_clause = """
            ORDER BY posts.pinned DESC,
                     datetime(posts.created_at) DESC
        """
    elif sort == "top":
        order_clause = """
            ORDER BY posts.pinned DESC,
                     posts.upvotes DESC,
                     datetime(posts.created_at) DESC
        """
    else:  # hot
        order_clause = """
            ORDER BY posts.pinned DESC,
                     (posts.upvotes * 1.0) /
                     ( ((julianday('now') - julianday(posts.created_at)) * 24) + 2 )
                     DESC
        """

    cur = conn.execute(f"""
        SELECT 
            posts.id,
            posts.user_id AS owner_id,
            posts.title,
            posts.body,
            posts.image_filename,
            posts.created_at,
            posts.pinned,
            posts.upvotes,
            users.username,
            users.email,
            users.is_admin,
            users.is_pro,
            users.banned
        FROM posts
        LEFT JOIN users ON posts.user_id = users.id
        {where_clause}
        {order_clause}
        LIMIT ? OFFSET ?
    """, (*params, per_page, offset))
    posts = [dict(r) for r in cur.fetchall()]

    # Count total posts (with same filter)
    cur = conn.execute(f"""
        SELECT COUNT(*) AS total
        FROM posts
        LEFT JOIN users ON posts.user_id = users.id
        {where_clause}
    """, params)
    total_posts = cur.fetchone()["total"]

    uid = user["id"] if user else None

    for p in posts:
        if not p.get("username"):
            p["username"] = "[Deleted User]"
            p["is_admin"] = 0
            p["is_pro"] = 0
            p["banned"] = 0

        if uid:
            row = conn.execute("""
                SELECT vote FROM post_votes
                WHERE user_id=? AND post_id=?
            """, (uid, p["id"])).fetchone()
            p["viewer_hearted"] = (row and row["vote"] == 1)
        else:
            p["viewer_hearted"] = False

    conn.close()

    total_pages = max((total_posts + per_page - 1) // per_page, 1)
    return render_template(
        "posts.html",
        posts=posts,
        user=user,
        user_is_admin=is_admin(user),
        page=page,
        total_pages=total_pages,
        user_is_pro=is_pro(user),
        sort=sort,
        search=search,
    )


app.add_url_rule("/posts", endpoint="posts", view_func=posts_list)

@app.route("/posts/new", methods=["GET", "POST"], endpoint="posts_new")
def posts_new():
    user = current_user()

    # 🔒 1. Must check login first — otherwise user could be None and cause error
    if not user:
        flash("You must be logged in to create a post.", "warning")
        return redirect(url_for("login"))

    # 🚫 2. Then check if banned
    if user.get("banned"):
        flash("You are banned from posting or commenting.", "error")
        return redirect(url_for("posts_list"))

    

    user_id = user["id"]   # <-- REQUIRED FIX

    # ✍️ 3. Handle post creation
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        body = request.form.get("body", "").strip()
        image = request.files.get("image")
        image_filename = None
        pinned = 1 if (request.form.get("pinned") and is_admin(user)) else 0

        if not title or not body:
            flash("Title and body are required.", "error")
            return redirect(url_for("posts_new"))
        
        if contains_profanity(title) or contains_profanity(body):
            flash("Your post contains inappropriate language.", "error")
            return redirect(url_for("posts_new"))

        # Image handling
        if image and image.filename:
            if not allowed_file(image.filename):
                flash("Unsupported image type.", "error")
                return redirect(url_for("posts_new"))
            filename = secure_filename(
                f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{image.filename}"
            )
            image.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
            image_filename = filename

        conn = get_db()

        # Insert post
        conn.execute(
            """
            INSERT INTO posts (user_id, title, body, image_filename, pinned, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (user_id, title, body, image_filename, pinned, datetime.utcnow().isoformat())
        )

        # Mark user as having posted
        conn.execute("UPDATE users SET has_posted = 1 WHERE id = ?", (user_id,))

        conn.commit()
        conn.close()

        flash("Post created successfully.", "success")
        return redirect(url_for("posts_list"))

    # 🖼️ Render post form
    return render_template("new_post.html", user=user, user_is_admin=is_admin(user))

@app.route("/posts/<int:post_id>/edit", methods=["GET", "POST"])
def posts_edit(post_id):
    user = current_user()
    if not user:
        flash("Please log in.", "warning")
        return redirect(url_for("login"))

    post = fetch_post(post_id)
    if not post:
        abort(404)
    if (post["user_id"] != user["id"]) and (not is_admin(user)):
        flash("You can only edit your own post.", "error")
        return redirect(url_for("posts_list"))

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        body = request.form.get("body", "").strip()
        delete_image = request.form.get("delete_image") == "true"
        new_image = request.files.get("image")
        pinned = 1 if (request.form.get("pinned") and is_admin(user)) else 0  # ✅ NEW

        image_filename = post["image_filename"]

        if not title or not body:
            flash("Title and body are required.", "error")
            return redirect(url_for("posts_edit", post_id=post_id))

        if delete_image and image_filename:
            delete_image_file(image_filename)
            image_filename = None

        if new_image and new_image.filename:
            if not allowed_file(new_image.filename):
                flash("Unsupported image type.", "error")
                return redirect(url_for("posts_edit", post_id=post_id))
            if image_filename:
                delete_image_file(image_filename)
            filename = secure_filename(f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{new_image.filename}")
            new_image.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
            image_filename = filename

        conn = get_db()
        conn.execute(
            "UPDATE posts SET title=?, body=?, image_filename=?, pinned=? WHERE id=?",
            (title, body, image_filename, pinned, post_id)
        )
        conn.commit()
        conn.close()

        flash("Post updated successfully.", "success")
        return redirect(url_for("posts_list"))

    return render_template("edit_post.html", post=post, user=user, user_is_admin=is_admin(user))

@app.route("/posts/<int:post_id>/delete", methods=["POST"])
def posts_delete(post_id):
    user = current_user()
    if not user:
        flash("Please log in.", "warning")
        return redirect(url_for("login"))

    post = fetch_post(post_id)
    if not post:
        abort(404)
    if (post["user_id"] != user["id"]) and (not is_admin(user)):
        flash("You can only delete your own post.", "error")
        return redirect(url_for("posts_list"))

    conn = get_db()
    conn.execute("DELETE FROM comments WHERE post_id=?", (post_id,))
    conn.commit()

    delete_image_file(post["image_filename"])
    conn.execute("DELETE FROM posts WHERE id=?", (post_id,))
    conn.commit()
    conn.close()
    flash("Post deleted.", "info")
    return redirect(url_for("posts_list"))

@app.route("/posts/<int:post_id>/pin", methods=["POST"])
def posts_toggle_pin(post_id):
    user = current_user()
    if not is_admin(user):
        return jsonify({"ok": False, "error": "Unauthorized"}), 403

    conn = get_db()
    cur = conn.execute("SELECT pinned FROM posts WHERE id = ?", (post_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({"ok": False, "error": "Post not found"}), 404

    new_value = 0 if row["pinned"] else 1
    conn.execute("UPDATE posts SET pinned = ? WHERE id = ?", (new_value, post_id))
    conn.commit()
    conn.close()

    return jsonify({"ok": True, "pinned": new_value})


@app.route("/posts/<int:post_id>")
def posts_view(post_id):
    user = current_user()
    post = fetch_post(post_id)
    if not post:
        abort(404)

    return render_template("post_view.html", post=post, user=user)

@app.route("/posts/<int:post_id>/vote", methods=["POST"])
def heart_post(post_id):
    user = current_user()
    if not user:
        return jsonify({"ok": False, "error": "login required"}), 401

    data = request.get_json(silent=True) or {}
    heart = int(data.get("vote", 0))  # always 1 for toggle

    conn = get_db()
    cur = conn.cursor()

    # Check if user already hearted
    cur.execute("""
        SELECT vote FROM post_votes
        WHERE user_id=? AND post_id=?
    """, (user["id"], post_id))
    row = cur.fetchone()

    old_vote = row["vote"] if row else 0

    # Toggle logic: if already hearted → unheart
    new_vote = 0 if old_vote == 1 else 1   # ✔ GOOD

    # Update DB
    if row:
        cur.execute("""
            UPDATE post_votes SET vote=?
            WHERE user_id=? AND post_id=?
        """, (new_vote, user["id"], post_id))
    else:
        cur.execute("""
            INSERT INTO post_votes (user_id, post_id, vote)
            VALUES (?, ?, ?)
        """, (user["id"], post_id, new_vote))

    # Recalculate total hearts
    cur.execute("""
        SELECT SUM(vote) as hearts
        FROM post_votes WHERE post_id=?
    """, (post_id,))
    total = cur.fetchone()["hearts"] or 0

    # Save to posts table
    cur.execute("UPDATE posts SET upvotes=? WHERE id=?", (total, post_id))

    conn.commit()
    conn.close()

    return jsonify({
        "ok": True,
        "hearted": new_vote == 1,
        "hearts": total
    })


# ------------------- Comments (AJAX) -------------------
@app.route("/comments/list", methods=["GET"])
def comments_list():
    post_id = request.args.get("post_id", type=int)
    if not post_id:
        return jsonify({"ok": False, "error": "post_id required"}), 400

    user = current_user()
    uid = user["id"] if user else None
    admin = is_admin(user)

    conn = get_db()
    cur = conn.execute("""
        SELECT
            c.id,
            c.post_id,
            c.user_id,
            c.parent_comment_id,
            c.body,
            c.created_at,
            u.username
        FROM comments c
        LEFT JOIN users u ON c.user_id = u.id  -- keep comments after user deletion
        WHERE c.post_id = ?
        ORDER BY datetime(c.created_at) ASC
    """, (post_id,))
    rows = cur.fetchall()
    conn.close()

    comments = []
    for r in rows:
        username = r["username"] if r["username"] else "[Deleted User]"
        user_id = r["user_id"]
        comments.append({
            "id": r["id"],
            "post_id": r["post_id"],
            "user_id": user_id,
            "parent_comment_id": r["parent_comment_id"],
            "username": username,
            "body": r["body"],
            "created_at": r["created_at"],
            "can_delete": bool(admin or (uid and uid == user_id))
        })

    return jsonify({
        "ok": True,
        "count": len(comments),
        "comments": comments
    })


@app.route("/comments/add", methods=["POST"])
def comments_add():
    user = current_user()
    if user and user.get("banned"):
        return jsonify({"ok": False, "error": "You are banned from posting or commenting."}), 403

    if not user:
        return jsonify({"ok": False, "error": "login required"}), 401

    # JSON or form
    if request.is_json:
        data = request.get_json(silent=True) or {}
        post_id = int(data.get("post_id") or 0)
        body = (data.get("body") or "").strip()
        parent_comment_id = data.get("parent_comment_id")
        try:
            parent_comment_id = int(parent_comment_id) if parent_comment_id not in (None, "") else None
        except Exception:
            parent_comment_id = None
    else:
        post_id = request.form.get("post_id", type=int)
        body = (request.form.get("body") or "").strip()
        parent_comment_id = request.form.get("parent_comment_id", type=int)

    if not post_id or not body:
        return jsonify({"ok": False, "error": "post_id and body required"}), 400

    post = fetch_post(post_id)
    if not post:
        return jsonify({"ok": False, "error": "post not found"}), 404

    now = datetime.utcnow().isoformat()
    conn = get_db()
    # Help avoid "database is locked" on busy Windows dev setups
    try:
        conn.execute("PRAGMA busy_timeout = 5000")
    except Exception:
        pass
    cur = conn.cursor()

    # Validate parent comment (must belong to same post)
    parent_user_id = None
    if parent_comment_id is not None:
        cur.execute("SELECT id, user_id, post_id FROM comments WHERE id=?", (parent_comment_id,))
        prow = cur.fetchone()
        if not prow or int(prow["post_id"]) != int(post_id):
            conn.close()
            return jsonify({"ok": False, "error": "invalid parent_comment_id"}), 400
        parent_user_id = prow["user_id"]

    # Insert comment
    cur.execute(
        "INSERT INTO comments (post_id, user_id, parent_comment_id, body, created_at) VALUES (?, ?, ?, ?, ?)",
        (post_id, user["id"], parent_comment_id, body, now)
    )
    comment_id = cur.lastrowid

    # Fetch it back with username
    cur.execute("""
        SELECT c.id, c.post_id, c.user_id, c.parent_comment_id, c.body, c.created_at, u.username
        FROM comments c
        JOIN users u ON c.user_id = u.id
        WHERE c.id = ?
    """, (comment_id,))
    row = cur.fetchone()

    # Notifications
    # fetch_post() returns sqlite3.Row; it doesn't have .get()
    try:
        post_owner_id = post["user_id"]
    except Exception:
        post_owner_id = None

    # Notify post owner (unless self)
    if post_owner_id and post_owner_id != user["id"]:
        message = f"{user['username']} replied to your post"
        cur.execute("""
            INSERT INTO notifications (user_id, actor_id, post_id, comment_id, message, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (post_owner_id, user["id"], post_id, comment_id, message, now))

    # Notify parent comment author (unless self or same as post owner to avoid duplicate notif)
    if parent_user_id and parent_user_id != user["id"] and parent_user_id != post_owner_id:
        message = f"{user['username']} replied to your comment"
        cur.execute("""
            INSERT INTO notifications (user_id, actor_id, post_id, comment_id, message, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (parent_user_id, user["id"], post_id, comment_id, message, now))

    conn.commit()
    conn.close()

    comment = {
        "id": row["id"],
        "post_id": row["post_id"],
        "user_id": row["user_id"],
        "parent_comment_id": row["parent_comment_id"],
        "username": row["username"],
        "body": row["body"],
        "created_at": row["created_at"],
        "can_delete": True
    }
    return jsonify({"ok": True, "comment": comment})

@app.route("/comments/<int:comment_id>/delete", methods=["POST"])
def comments_delete(comment_id):
    user = current_user()
    if not user:
        return jsonify({"ok": False, "error": "login required"}), 401

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT id, user_id, post_id FROM comments WHERE id=?", (comment_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({"ok": False, "error": "comment not found"}), 404

    if (row["user_id"] != user["id"]) and (not is_admin(user)):
        conn.close()
        return jsonify({"ok": False, "error": "forbidden"}), 403

    # Delete this comment AND all descendants (nested replies)
    to_delete = [comment_id]
    i = 0
    while i < len(to_delete):
        cid = to_delete[i]
        cur.execute("SELECT id FROM comments WHERE parent_comment_id=?", (cid,))
        kids = [r["id"] for r in cur.fetchall()]
        for k in kids:
            if k not in to_delete:
                to_delete.append(k)
        i += 1

    # Clean up notifications pointing at deleted comments (best-effort)
    cur.execute(
        f"DELETE FROM notifications WHERE comment_id IN ({','.join(['?']*len(to_delete))})",
        to_delete,
    )
    cur.execute(
        f"DELETE FROM comments WHERE id IN ({','.join(['?']*len(to_delete))})",
        to_delete,
    )

    conn.commit()
    conn.close()
    return jsonify({"ok": True, "deleted": len(to_delete)})

# Serve uploaded images
@app.route("/uploads/<filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


@app.route("/notifications/unread", methods=["GET"])
def notifications_unread():
    """Return notifications for the user (read + unread), and count unread separately."""
    user = current_user()
    if not user:
        return jsonify({"ok": False, "error": "login required"}), 401

    conn = get_db()

    # Get ALL notifications (so dropdown keeps them)
    cur = conn.execute("""
        SELECT
            n.id,
            n.post_id,
            n.comment_id,
            n.message,
            n.created_at,
            n.is_read,
            p.title AS post_title
        FROM notifications n
        JOIN posts p ON n.post_id = p.id
        WHERE n.user_id = ?
        ORDER BY datetime(n.created_at) DESC
        LIMIT 40
    """, (user["id"],))
    rows = cur.fetchall()

    # Count UNREAD for the red badge
    cur2 = conn.execute("""
        SELECT COUNT(*) AS c
        FROM notifications
        WHERE user_id = ? AND is_read = 0
    """, (user["id"],))
    unread_count = cur2.fetchone()["c"]

    conn.close()

    notifications = []

    for r in rows:
        page = get_post_page(r["post_id"])

        notifications.append({
            "id": r["id"],
            "post_id": r["post_id"],
            "comment_id": r["comment_id"],
            "message": r["message"],
            "post_title": r["post_title"],
            "created_at": r["created_at"],
            "is_read": r["is_read"],
            "url": url_for(
                "posts_list",
                page=page,
                _anchor=f"post-{r['post_id']}"
            )
        })


    return jsonify({
        "ok": True,
        "notifications": notifications,
        "count": unread_count
    })


@app.route("/notifications/mark_read", methods=["POST"])
def notifications_mark_read():
    """Mark one or more notifications as read for the current user."""
    user = current_user()
    if not user:
        return jsonify({"ok": False, "error": "login required"}), 401

    data = request.get_json(silent=True) or {}
    ids = data.get("ids") or []

    # Allow single id or list
    if isinstance(ids, (int, str)):
        ids = [ids]

    clean_ids = []
    for val in ids:
        try:
            clean_ids.append(int(val))
        except (TypeError, ValueError):
            continue

    if not clean_ids:
        return jsonify({"ok": False, "error": "no ids provided"}), 400

    placeholders = ",".join("?" for _ in clean_ids)
    params = [user["id"], *clean_ids]

    conn = get_db()
    conn.execute(
        f"UPDATE notifications SET is_read = 1 WHERE user_id = ? AND id IN ({placeholders})",
        params
    )
    conn.commit()
    conn.close()

    return jsonify({"ok": True})


@app.route("/api/search_posts")
def api_search_posts():
    q = (request.args.get("q") or "").strip().lower()
    if not q:
        return jsonify({"ok": True, "posts": []})

    conn = get_db()
    cur = conn.execute("""
        SELECT 
            p.id, 
            p.title, 
            p.body, 
            p.created_at, 
            p.image_filename,
            u.username,
            u.is_admin AS is_admin,
            u.is_pro AS is_pro,
            u.banned AS banned
        FROM posts p
        LEFT JOIN users u ON u.id = p.user_id
        WHERE (u.banned IS NULL OR u.banned = 0)
        ORDER BY p.created_at DESC
    """)
    rows = cur.fetchall()
    conn.close()

    results = []
    for r in rows:
        results.append({
            "id": r["id"],
            "title": r["title"],
            "body": r["body"],
            "username": r["username"] or "[Deleted User]",
            "created_at": r["created_at"],
            "pinned": False,  # still unused
            "image_filename": r["image_filename"],
            "is_admin": r["is_admin"],
            "is_pro": r["is_pro"],
            "banned": r["banned"],
        })

    return jsonify({"ok": True, "posts": results})

def get_post_page(post_id, per_page=10,sort='new'):
    conn = get_db()

    rows = conn.execute("""
        SELECT posts.id
        FROM posts
        LEFT JOIN users ON posts.user_id = users.id
        WHERE (users.banned IS NULL OR users.banned = 0)
        ORDER BY posts.pinned DESC,
                 datetime(posts.created_at) DESC
    """).fetchall()

    conn.close()

    ids = [r["id"] for r in rows]

    if post_id not in ids:
        return 1

    index = ids.index(post_id)
    return (index // per_page) + 1

@app.route("/api/search")
def api_search():
    q = (request.args.get("q") or "").strip().lower()

    user = current_user()
    viewer_logged_in = bool(user)
    viewer_id = user["id"] if user else None
    viewer_is_admin = bool(user and user.get("is_admin"))

    conn = get_db()
    cur = conn.execute("""
        SELECT 
            posts.id,
            posts.title,
            posts.body,
            posts.image_filename,
            posts.created_at,
            posts.pinned,
            posts.user_id AS owner_id,
            users.username,
            users.is_admin AS is_admin,
            users.is_pro AS is_pro,
            users.banned
        FROM posts
        LEFT JOIN users ON users.id = posts.user_id
        WHERE (users.banned IS NULL OR users.banned = 0)
        ORDER BY posts.pinned DESC, datetime(posts.created_at) DESC
    """)
    rows = cur.fetchall()
    conn.close()

    posts = []
    for r in rows:
        owner_id = r["owner_id"]

        can_edit = viewer_is_admin or (viewer_logged_in and viewer_id == owner_id)
        can_delete = can_edit

        posts.append({
            "id": r["id"],
            "title": r["title"],
            "body": r["body"],
            "image_filename": r["image_filename"],
            "created_at": r["created_at"],
            "pinned": bool(r["pinned"]),
            "owner_id": owner_id,
            "username": r["username"] or "[Deleted User]",
            "is_admin": bool(r["is_admin"]),
            "is_pro": bool(r["is_pro"]),
            "banned": bool(r["banned"]),
            "can_edit": bool(can_edit),
            "can_delete": bool(can_delete),
        })

    return jsonify({
        "ok": True,
        "viewer_is_admin": viewer_is_admin,
        "viewer_logged_in": viewer_logged_in,
        "posts": posts,
    })


# ------------------- Accounts -------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == 'POST':
        email = request.form['email'].strip()
        username = request.form['username'].strip()
        password = request.form['password']
        confirm = request.form['confirm']

        if password != confirm:
            flash("Passwords do not match.", "error")
            return render_template('register.html')

        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM users WHERE email=? OR username=?", (email, username))
            existing_user = c.fetchone()

        if existing_user:
            flash("Email or username already exists.", "error")
            return render_template('register.html')

        hashed = generate_password_hash(password)
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute(
                "INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (email, username, hashed, datetime.utcnow().isoformat())
            )
            conn.commit()

        flash("Account created successfully! You can now log in.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')
@app.route("/comments/count")
def comments_count():
    post_id = request.args.get("post_id", type=int)
    if not post_id:
        return jsonify({"ok": False, "error": "post_id required"}), 400

    conn = get_db()
    cur = conn.execute("SELECT COUNT(*) AS c FROM comments WHERE post_id=?", (post_id,))
    row = cur.fetchone()
    conn.close()

    return jsonify({"ok": True, "count": row["c"] if row else 0})

from urllib.parse import urlparse, urljoin
from flask import request, redirect, url_for, flash, render_template, session

def is_safe_url(target: str) -> bool:
    """
    Only allow redirects to same-host relative URLs.
    Prevents open redirect attacks.
    """
    if not target:
        return False

    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))

    return (
        test_url.scheme in ("http", "https") and
        ref_url.netloc == test_url.netloc
    )



@app.route("/login", methods=["GET", "POST"])
def login():
    # If redirected here by an API gate (e.g. Pro Analysis), show a friendly message
    reason = request.args.get("reason", "")
    if reason == "pro_analysis":
        flash("Please log in to use Pro Analysis.", "info")

    # capture next from querystring or form
    next_url = (request.args.get("next") or request.form.get("next") or "").strip()

    if request.method == "POST":
        identifier = (request.form.get("username") or "").strip()
        password = request.form.get("password", "")

        conn = get_db()
        cur = conn.execute("""
            SELECT id, username, email, password_hash
            FROM users
            WHERE lower(username)=lower(?)
               OR lower(email)=lower(?)
            LIMIT 1
        """, (identifier, identifier))
        user = cur.fetchone()
        conn.close()

        if not user:
            flash("No account found with that username or email.", "error")
            # keep next on redirect back to login
            return redirect(url_for("login", next=next_url) if next_url else url_for("login"))

        if not check_password_hash(user["password_hash"], password):
            flash("Incorrect password.", "error")
            return redirect(url_for("login", next=next_url) if next_url else url_for("login"))

        session["user_id"] = user["id"]
        flash(f"Welcome back, {user['username']}!", "success")

        # redirect back to where they came from (if safe)
        if next_url and is_safe_url(next_url):
            return redirect(next_url)

        return redirect(url_for("posts"))

    # GET: render login with next preserved so the form can POST it back
    return render_template("login.html", user=current_user(), next=next_url)

# ------------------- Forgot/Reset Password -------------------
import os
import threading
import logging
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash
from flask import request, redirect, url_for, flash, render_template

import sendgrid
from sendgrid.helpers.mail import Mail

# -------------------------------------------------
# Proxy fix (Render / reverse proxy safe)
# -------------------------------------------------
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# -------------------------------------------------
# SendGrid async sender (NO SMTP)
# -------------------------------------------------
MAIL_FROM = os.environ.get(
    "MAIL_DEFAULT_SENDER",
    "The Cipher Lab Support <thecipherlab@gmail.com>"
)

def _parse_sender(sender):
    if "<" in sender and ">" in sender:
        name = sender.split("<", 1)[0].strip()
        email = sender.split("<", 1)[1].split(">", 1)[0].strip()
        return email, name
    return sender, None

def _send_sendgrid_async(flask_app, to_email, subject, text_body, html_body=None):
    with flask_app.app_context():
        api_key = os.environ.get("SENDGRID_API_KEY")
        if not api_key:
            flask_app.logger.warning("[MAIL] SENDGRID_API_KEY not set")
            return

        from_email, from_name = _parse_sender(MAIL_FROM)

        try:
            sg = sendgrid.SendGridAPIClient(api_key=api_key)
            message = Mail(
                from_email=(from_email, from_name) if from_name else from_email,
                to_emails=to_email,
                subject=subject,
                plain_text_content=text_body,
                html_content=html_body
            )
            resp = sg.send(message)

            if resp.status_code not in (200, 202):
                flask_app.logger.warning(
                    f"[MAIL] SendGrid returned {resp.status_code}"
                )
        except Exception as e:
            flask_app.logger.warning(f"[MAIL] SendGrid send failed: {e}")

def send_mail_nonblocking(to_email, subject, text_body, html_body=None):
    threading.Thread(
        target=_send_sendgrid_async,
        args=(app, to_email, subject, text_body, html_body),
        daemon=True
    ).start()

# -------------------------------------------------
# Forgot password
# -------------------------------------------------
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()

        conn = get_db()
        user = conn.execute(
            "SELECT id FROM users WHERE lower(email)=?",
            (email,)
        ).fetchone()
        conn.close()

        # Prevent account enumeration
        flash(
            "If an account with that email exists, a reset link has been sent. If you cant' find it, check your spam folder.",
            "info"
        )

        if user:
            token = serializer.dumps(email, salt="password-reset")
            reset_url = url_for(
                "reset_password",
                token=token,
                _external=True
            )

            subject = "CryptiQ — Password Reset"
            text_body = (
                "Reset your password using this link (valid for 1 hour):\n\n"
                f"{reset_url}\n"
            )
            html_body = f"""
              <div style="font-family:Arial,sans-serif;line-height:1.6">
                <h2>Password reset</h2>
                <p>This link is valid for <b>1 hour</b>.</p>
                <p><a href="{reset_url}">Reset your password</a></p>
                <p style="font-size:12px;color:#666">
                  If you didn’t request this, you can safely ignore this email.
                </p>
              </div>
            """

            send_mail_nonblocking(email, subject, text_body, html_body)

        return redirect(url_for("forgot_password"))

    return render_template("forgot_password.html", user=current_user())

# -------------------------------------------------
# Reset password
# -------------------------------------------------
@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    try:
        email = serializer.loads(
            token,
            salt="password-reset",
            max_age=3600
        )
    except Exception:
        flash("Invalid or expired reset link.", "error")
        return redirect(url_for("forgot_password"))

    email_norm = (email or "").strip().lower()

    if request.method == "POST":
        new_pass = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if new_pass != confirm:
            flash("Passwords do not match.", "error")
            return redirect(url_for("reset_password", token=token))

        if len(new_pass) < 8:
            flash("Password must be at least 8 characters.", "error")
            return redirect(url_for("reset_password", token=token))

        hashed = generate_password_hash(new_pass)

        conn = get_db()
        conn.execute(
            "UPDATE users SET password_hash=? WHERE lower(email)=?",
            (hashed, email_norm)
        )
        conn.commit()
        conn.close()

        flash("Password reset successfully. You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html", email=email_norm)


from werkzeug.security import check_password_hash, generate_password_hash

from werkzeug.security import generate_password_hash, check_password_hash

@app.route("/account/change-password", methods=["POST"])
def account_change_password():
    user = current_user()
    if not user:
        flash("Please log in to change your password.", "error")
        return redirect(url_for("login"))

    back = url_for("account") + "#security"

    new_pass = request.form.get("new_password", "")
    confirm  = request.form.get("confirm_password", "")

    conn = get_db()
    row = conn.execute(
        "SELECT password_hash, needs_password FROM users WHERE id=?",
        (user["id"],)
    ).fetchone()

    if not row or not row["password_hash"]:
        conn.close()
        flash("Account error: password not found.", "error")
        return redirect(back)

    # ✅ FIX: sqlite3.Row has no .get()
    try:
        needs_password = int(row["needs_password"] or 0)
    except (KeyError, IndexError, TypeError):
        needs_password = 0

    # ------------------------------------------------------
    # Pro-first accounts: Set password (skip old password)
    # ------------------------------------------------------
    if needs_password:
        if not new_pass or not confirm:
            conn.close()
            flash("Please fill in all fields.", "error")
            return redirect(back)

        if new_pass != confirm:
            conn.close()
            flash("New passwords do not match.", "error")
            return redirect(back)

        if len(new_pass) < 8:
            conn.close()
            flash("Password must be at least 8 characters.", "error")
            return redirect(back)

        new_hash = generate_password_hash(new_pass)
        conn.execute(
            "UPDATE users SET password_hash=?, needs_password=0 WHERE id=?",
            (new_hash, user["id"])
        )
        conn.commit()
        conn.close()

        flash("Password set.", "success")
        return redirect(back)

    # ------------------------------------------------------
    # Normal accounts: Change password (require old password)
    # ------------------------------------------------------
    old_pass = request.form.get("old_password", "")

    if not old_pass or not new_pass or not confirm:
        conn.close()
        flash("Please fill in all fields.", "error")
        return redirect(back)

    if old_pass == new_pass:
        conn.close()
        flash("New password must be different from your current password.", "error")
        return redirect(back)

    if new_pass != confirm:
        conn.close()
        flash("New passwords do not match.", "error")
        return redirect(back)

    if len(new_pass) < 8:
        conn.close()
        flash("Password must be at least 8 characters.", "error")
        return redirect(back)

    if not check_password_hash(row["password_hash"], old_pass):
        conn.close()
        flash("Current password is incorrect.", "error")
        return redirect(back)

    new_hash = generate_password_hash(new_pass)
    conn.execute(
        "UPDATE users SET password_hash=? WHERE id=?",
        (new_hash, user["id"])
    )
    conn.commit()
    conn.close()

    flash("Password updated.", "success")
    return redirect(back)


@app.route("/account/change-username", methods=["POST"])
def account_change_username():
    user = current_user()
    if not user:
        flash("Please log in to change your username.", "error")
        return redirect(url_for("login"))

    back = url_for("account") + "#security"

    new_username = (request.form.get("new_username") or "").strip()
    password = request.form.get("password") or ""

    if not new_username:
        flash("Please enter a username.", "error")
        return redirect(back)

    if len(new_username) < 3 or len(new_username) > 24:
        flash("Username must be 3–24 characters.", "error")
        return redirect(back)

    if not re.match(r"^[A-Za-z0-9_]+$", new_username):
        flash("Username can only contain letters, numbers, and underscores.", "error")
        return redirect(back)

    conn = get_db()
    row = conn.execute(
        "SELECT password_hash, needs_username FROM users WHERE id=?",
        (user["id"],)
    ).fetchone()

    if not row:
        conn.close()
        flash("Account error.", "error")
        return redirect(back)

    # ✅ FIX: sqlite3.Row has no .get()
    try:
        needs_username = int(row["needs_username"] or 0)
    except (KeyError, IndexError, TypeError):
        needs_username = 0

    # Normal accounts: confirm password before changing username
    if not needs_username:
        if not password:
            conn.close()
            flash("Please enter your password to change your username.", "error")
            return redirect(back)

        if not check_password_hash(row["password_hash"], password):
            conn.close()
            flash("Password is incorrect.", "error")
            return redirect(back)

    # uniqueness check (case-insensitive)
    exists = conn.execute(
        "SELECT id FROM users WHERE lower(username)=lower(?) AND id<>?",
        (new_username, user["id"])
    ).fetchone()

    if exists:
        conn.close()
        flash("That username is taken.", "error")
        return redirect(back)

    conn.execute(
        "UPDATE users SET username=?, needs_username=0 WHERE id=?",
        (new_username, user["id"])
    )
    conn.commit()
    conn.close()

    flash("Username set." if needs_username else "Username updated.", "success")
    return redirect(back)

@app.route("/logout")
def logout():
    session.pop("user_id", None)
    flash("Logged out successfully.", "info")
    return redirect(url_for("index"))

@app.route("/account")
def account():
    user = current_user()
    if not user:
        flash("Please log in to view your account.", "warning")
        return redirect(url_for("login"))

    # User info + posts
    conn = get_db()
    cur = conn.execute("SELECT username, email, created_at, needs_password, needs_username FROM users WHERE id=?", (user["id"],))
    user_info = cur.fetchone()

    # --- My Posts pagination (same style as /posts) ---
    posts_per_page = 9
    try:
        posts_page = int(request.args.get("posts_page") or request.args.get("page") or 1)
    except ValueError:
        posts_page = 1
    if posts_page < 1:
        posts_page = 1

    total_posts_row = conn.execute(
        "SELECT COUNT(*) AS c FROM posts WHERE user_id=?",
        (user["id"],)
    ).fetchone()
    total_posts = (total_posts_row["c"] if total_posts_row else 0) or 0

    posts_total_pages = (total_posts + posts_per_page - 1) // posts_per_page if total_posts else 0
    if posts_total_pages and posts_page > posts_total_pages:
        posts_page = posts_total_pages

    posts_offset = (posts_page - 1) * posts_per_page

    cur = conn.execute("""
        SELECT id, title, body, image_filename, created_at
        FROM posts
        WHERE user_id=?
        ORDER BY datetime(created_at) DESC
        LIMIT ? OFFSET ?
    """, (user["id"], posts_per_page, posts_offset))
    posts = [dict(r) for r in cur.fetchall()]

    # For each post, compute which /posts page it appears on (so links work beyond page 1)
    # Uses the same ordering as /posts (pinned desc, newest first).
    for p in posts:
        try:
            p["list_page"] = get_post_page(p["id"])
        except Exception:
            p["list_page"] = 1


    # Leaderboard data
    lb_data = conn.execute("""
        SELECT username,
               COUNT(DISTINCT cipher_week) AS weeks_played,
               SUM(score) AS total_score
        FROM cipher_submissions
        WHERE username IS NOT NULL
        GROUP BY username
        ORDER BY total_score DESC
    """).fetchall()

    leaderboard_data = None
    for i, row in enumerate(lb_data, start=1):
        if row["username"].lower() == user_info["username"].lower():
            leaderboard_data = {
                "rank": i,
                "weeks_played": row["weeks_played"],
                "total_score": row["total_score"]
            }
            break

    conn.close()

	# sqlite3.Row supports dict-style access (row["col"]) but does NOT implement .get().
    needs_password = bool(user_info["needs_password"]) if (user_info and ("needs_password" in user_info.keys())) else False
    needs_username = bool(user_info["needs_username"]) if (user_info and ("needs_username" in user_info.keys())) else False

    return render_template(
		"account.html",
		user=user,
		user_info=user_info,
		posts=posts,
		leaderboard_data=leaderboard_data,
		posts_page=posts_page,
		posts_total_pages=posts_total_pages,
		needs_password=needs_password,
		needs_username=needs_username,
	)


@app.route("/delete_account")
def delete_account():
    user = current_user()
    if not user:
        flash("You must be logged in to delete your account.", "warning")
        return redirect(url_for("login"))

    conn = get_db()
    cur = conn.cursor()

    # Keep posts, just unlink user_id
    cur.execute("""
        UPDATE posts
        SET user_id = NULL
        WHERE user_id = ?
    """, (user["id"],))

    # Delete user data
    cur.execute("DELETE FROM cipher_submissions WHERE username = ?", (user["username"],))
    cur.execute("DELETE FROM users WHERE id = ?", (user["id"],))
    conn.commit()
    conn.close()

    session.clear()
    flash("Your account has been deleted. Your posts remain visible as '[Deleted User]'.", "info")
    return redirect(url_for("register"))


@app.route("/api/leaderboard_data")
def leaderboard_data_api():
    user = current_user()
    if not user:
        return jsonify({"error": "Not logged in"}), 403

    conn = get_db()
    lb_data = conn.execute("""
        SELECT username,
               COUNT(DISTINCT cipher_week) AS weeks_played,
               SUM(score) AS total_score
        FROM cipher_submissions
        WHERE username IS NOT NULL
        GROUP BY username
        ORDER BY total_score DESC
    """).fetchall()
    conn.close()

    for i, row in enumerate(lb_data, start=1):
        if row["username"].lower() == user["username"].lower():
            return jsonify({
                "rank": i,
                "total_score": row["total_score"],
                "weeks_played": row["weeks_played"]
            })

    return jsonify({"rank": None, "total_score": 0, "weeks_played": 0})

# ===== Weekly Cipher: DB helpers and routes =====
def init_weekly_tables():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS weekly_cipher (
        id INTEGER PRIMARY KEY CHECK (id=1),
        week_number INTEGER NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        ciphertext TEXT NOT NULL,
        solution TEXT NOT NULL,
        hint TEXT,
        posted_at TEXT NOT NULL,
        score_start_at TEXT NOT NULL
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS cipher_submissions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT,
        cipher_week INTEGER,
        answer TEXT NOT NULL,
        is_correct INTEGER NOT NULL DEFAULT 0,
        submitted_at TEXT NOT NULL
    )
    """)
    # Ensure there is at least one row for weekly_cipher (id=1) with a default
    cur.execute("SELECT 1 FROM weekly_cipher WHERE id=1")
    if not cur.fetchone():
        cur.execute("""
        INSERT INTO weekly_cipher (id, week_number, title, description, ciphertext, solution, hint, posted_at, score_start_at)
        VALUES (1, 1, 'Week #1 — Welcome Cipher',
                'Kickoff puzzle. Decrypt and submit the plaintext keyword.',
                'BJQHTRJ YT YMJ HNUMJW QFG!',  -- HELLO WORLD TEST!
                'WELCOME TO THE CIPHER LAB',
                'Think Caesar…', datetime('now'), datetime('now'))
        """)
    conn.commit()
    conn.close()


def migrate_weekly_cipher_score_start_at():
    """Adds weekly_cipher.score_start_at (used for scoring window) if missing."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("PRAGMA table_info(weekly_cipher)")
    cols = {row["name"] for row in cur.fetchall()}
    if "score_start_at" not in cols:
        cur.execute("ALTER TABLE weekly_cipher ADD COLUMN score_start_at TEXT")
        # Backfill: use posted_at as best available approximation for existing data.
        cur.execute(
            "UPDATE weekly_cipher SET score_start_at = posted_at "
            "WHERE score_start_at IS NULL OR score_start_at = ''"
        )
        conn.commit()
    conn.close()


def init_weekly_archive_tables():
    """Archive store for previous Weekly Ciphers (read-only)."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS weekly_cipher_archive (
            week_number INTEGER PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT,
            ciphertext TEXT NOT NULL,
            solution TEXT NOT NULL,
            hint TEXT,
            posted_at TEXT NOT NULL,
            archived_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_weekly_cipher_archive_posted ON weekly_cipher_archive(posted_at)"
    )
    conn.commit()
    conn.close()


def archive_weekly_cipher_row(wc_row: dict):
    """Insert a weekly_cipher row into the archive (idempotent by week_number)."""
    if not wc_row:
        return
    try:
        wn = int(wc_row.get("week_number") or 0)
    except Exception:
        wn = 0
    if wn <= 0:
        return

    conn = get_db()
    conn.execute(
        """
        INSERT OR IGNORE INTO weekly_cipher_archive
          (week_number, title, description, ciphertext, solution, hint, posted_at, archived_at)
        VALUES
          (?, ?, ?, ?, ?, ?, ?, datetime('now'))
        """,
        (
            wn,
            (wc_row.get("title") or f"Week #{wn}"),
            (wc_row.get("description") or ""),
            (wc_row.get("ciphertext") or ""),
            (wc_row.get("solution") or ""),
            (wc_row.get("hint") or ""),
            (wc_row.get("posted_at") or ""),
        ),
    )
    conn.commit()
    conn.close()

def get_current_weekly():
    conn = get_db()
    cur = conn.execute("SELECT * FROM weekly_cipher WHERE id=1 LIMIT 1")
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None

init_weekly_tables()
init_weekly_archive_tables()
migrate_weekly_tables()

migrate_weekly_cipher_score_start_at()
@app.before_request
def clear_flash_on_login():
    """
    Prevent old flashes on login only if no redirect brought new ones.
    """
    if request.endpoint == "login" and request.method == "GET":
        # Only clear old flashes if there aren't any active ones
        if "_flashes" not in session:
            session.pop("_flashes", None)


@app.route("/weekly")
def weekly_page():
    user = current_user()
    user_is_admin = is_admin(user)

    conn = get_db()
    cur = conn.cursor()

    # Current cipher is always the singleton row (id=1)
    cur.execute("SELECT * FROM weekly_cipher WHERE id=1 LIMIT 1")
    wc = cur.fetchone()

    # Recent archives for quick navigation
    archives = cur.execute(
        """
        SELECT week_number, title, posted_at
        FROM weekly_cipher_archive
        ORDER BY week_number DESC
        LIMIT 24
        """
    ).fetchall()

    # Check if user already solved it
    solved = False
    user_score = 0
    if user and wc:
        cur.execute("""
            SELECT score FROM cipher_submissions
            WHERE user_id=? AND cipher_week=? AND is_correct=1
            LIMIT 1
        """, (user["id"], wc["week_number"]))
        row = cur.fetchone()
        if row:
            solved = True
            user_score = row["score"]

    conn.close()

    return render_template(
        "weekly_cipher.html",
        wc=wc,
        user=user,
        user_is_admin=user_is_admin,
        already_solved=solved,
        solved_score=user_score,
        is_archive=False,
        archives=archives,
        current_week_number=(wc["week_number"] if wc else None),
    )


@app.route("/weekly/archives")
def weekly_archives():
    """List page for all archived weekly ciphers."""
    user = current_user()
    conn = get_db()
    rows = conn.execute(
        """
        SELECT week_number, title, posted_at, archived_at
        FROM weekly_cipher_archive
        ORDER BY week_number DESC
        """
    ).fetchall()
    conn.close()
    return render_template("weekly_archives.html", user=user, archives=rows)


@app.route("/weekly/archive/<int:week_number>")
def weekly_archive_view(week_number: int):
    """Read-only view of an archived Weekly Cipher."""
    user = current_user()
    user_is_admin = is_admin(user)

    conn = get_db()
    row = conn.execute(
        "SELECT * FROM weekly_cipher_archive WHERE week_number=? LIMIT 1",
        (week_number,),
    ).fetchone()

    # Also pass recent archives for dropdown nav
    archives = conn.execute(
        """
        SELECT week_number, title, posted_at
        FROM weekly_cipher_archive
        ORDER BY week_number DESC
        LIMIT 24
        """
    ).fetchall()
    conn.close()

    if not row:
        # fall back to current if they request the active week
        wc = get_current_weekly()
        if wc and int(wc.get("week_number") or -1) == int(week_number):
            return redirect(url_for("weekly_page"))
        abort(404)

    # Make it look like the normal wc object
    wc = dict(row)
    return render_template(
        "weekly_cipher.html",
        wc=wc,
        user=user,
        user_is_admin=user_is_admin,
        already_solved=True,
        solved_score=0,
        is_archive=True,
        archives=archives,
        current_week_number=week_number,
    )



@app.route("/weekly/archive/<int:week_number>/solution")
def weekly_archive_solution(week_number: int):
    """Return the official solution for an archived weekly cipher (used by the reveal animation)."""
    conn = get_db()
    row = conn.execute(
        "SELECT solution FROM weekly_cipher_archive WHERE week_number=? LIMIT 1",
        (week_number,),
    ).fetchone()
    conn.close()

    if not row:
        return jsonify({"ok": False, "error": "Archive not found."}), 404

    return jsonify({"ok": True, "solution": row["solution"] or ""})
import re
import unicodedata

import re
import unicodedata
from datetime import datetime
from flask import request, jsonify

def normalize_submission(text: str) -> str:
    if not text:
        return ""
    # Normalize unicode (smart quotes, em dashes, etc.)
    text = unicodedata.normalize("NFKD", text)
    text = text.upper()
    # Keep only A–Z and digits (remove spaces/punct/case)
    return re.sub(r"[^A-Z0-9]", "", text)


@app.route("/weekly/submit", methods=["POST"])
def weekly_submit():
    data = request.get_json(silent=True) or {}
    answer_raw = (data.get("answer") or "").strip()

    wc = get_current_weekly()
    if not wc:
        return jsonify({"ok": False, "error": "Weekly cipher not found."}), 404

    user = current_user()
    now = datetime.utcnow()

    answer_clean = normalize_submission(answer_raw)
    solution_clean = normalize_submission(wc.get("solution", ""))

    correct = 1 if (answer_clean and answer_clean == solution_clean) else 0
    score = 0
    solve_time_seconds = None

    # === Compute score only if correct ===
    if correct:
        try:
            posted_time = datetime.fromisoformat(
                wc.get("score_start_at") or wc.get("posted_at") or now.isoformat()
            )
        except Exception:
            posted_time = now

        solve_time_seconds = int((now - posted_time).total_seconds())
        total_window = 7 * 24 * 3600
        elapsed = (now - posted_time).total_seconds()
        remaining = max(total_window - elapsed, 0)

        base_score = max(1, int((remaining / total_window) * 100))

        conn = get_db()
        cur = conn.execute(
            "SELECT COUNT(*) AS correct_count FROM cipher_submissions WHERE cipher_week=? AND is_correct=1",
            (wc["week_number"],),
        )
        correct_count = cur.fetchone()["correct_count"]
        conn.close()

        if correct_count == 0:
            bonus = 25
        elif correct_count == 1:
            bonus = 15
        elif correct_count == 2:
            bonus = 10
        else:
            bonus = 0

        score = base_score + bonus
        if score < 20:
            score = 20

    # === Always record submission ===
    conn = get_db()
    conn.execute(
        """
        INSERT INTO cipher_submissions (
            user_id, username, cipher_week, answer, is_correct, score,
            submitted_at, created_at, season, solve_time_seconds
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'), ?, ?)
        """,
        (
            (user["id"] if user else None),
            (user["username"] if user else None),
            wc["week_number"],
            answer_raw,  # store what the user typed
            correct,
            score,
            now.isoformat(),
            get_current_season(),
            solve_time_seconds,
        ),
    )
    conn.commit()
    conn.close()

    return jsonify({"ok": True, "correct": bool(correct), "score": score})

@app.route("/admin/weekly", methods=["GET", "POST"])
def admin_weekly():
    user = current_user()
    if not is_admin(user):
        flash("Admin access required.", "error")
        return redirect(url_for("index"))

    conn = get_db()
    wc = get_current_weekly()  # Get the existing cipher for comparison

    if request.method == "POST":
        week_number = int(request.form.get("week_number") or 1)
        title = (request.form.get("title") or "").strip() or f"Week #{week_number}"
        description = (request.form.get("description") or "").strip()
        ciphertext = (request.form.get("ciphertext") or "").strip()
        solution = (request.form.get("solution") or "").strip() 
        hint = (request.form.get("hint") or "").strip()

        if not ciphertext or not solution:
            flash("Ciphertext and solution are required.", "error")
            conn.close()
            return redirect(url_for("admin_weekly"))

        # --- Detect change (only reset if cipher or solution differ) ---
        reset_needed = False
        if wc:
            if (
                ciphertext.strip() != (wc.get("ciphertext") or "").strip()
                or solution.strip() != (wc.get("solution") or "").strip()
            ):
                reset_needed = True

        # --- Auto-archive the previous current cipher when it changes ---
        # This used to only archive when the week number changed. If you swap in
        # a new puzzle but forget to bump the week number, you'd silently lose
        # the previous puzzle. So we archive when either:
        #   - the week number changes, OR
        #   - the actual puzzle changes (ciphertext/solution)
        if wc and (
            int(wc.get("week_number") or 0) != int(week_number)
            or reset_needed
        ):
            archive_weekly_cipher_row(wc)

        # --- Update weekly_cipher (singleton row id=1) ---
        # posted_at tracks *any* admin edit (including hint/title/description).
        # score_start_at only changes when the actual puzzle changes (ciphertext/solution) OR week number changes.
        now_iso = datetime.utcnow().isoformat()

        puzzle_changed = bool(reset_needed) or (wc and int(wc.get("week_number") or 0) != int(week_number))

        if wc:
            if puzzle_changed:
                conn.execute(
                    """
                    UPDATE weekly_cipher
                    SET week_number=?, title=?, description=?, ciphertext=?, solution=?, hint=?,
                        posted_at=?, score_start_at=?
                    WHERE id=1
                    """,
                    (week_number, title, description, ciphertext, solution, hint, now_iso, now_iso),
                )
            else:
                conn.execute(
                    """
                    UPDATE weekly_cipher
                    SET week_number=?, title=?, description=?, ciphertext=?, solution=?, hint=?,
                        posted_at=?
                    WHERE id=1
                    """,
                    (week_number, title, description, ciphertext, solution, hint, now_iso),
                )
        else:
            # First-time insert
            conn.execute(
                """
                INSERT INTO weekly_cipher (id, week_number, title, description, ciphertext, solution, hint, posted_at, score_start_at)
                VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (week_number, title, description, ciphertext, solution, hint, now_iso, now_iso),
            )


        # --- Reset submissions only if needed ---
        if reset_needed and wc and int(wc.get("week_number") or 0) == int(week_number):
            conn.execute("DELETE FROM cipher_submissions WHERE cipher_week=?", (week_number,))
            flash("Ciphertext or solution changed — previous submissions have been reset.", "warning")
        else:
            flash("Weekly cipher updated successfully.", "success")

        conn.commit()
        conn.close()
        return redirect(url_for("weekly_page"))

    conn.close()
    return render_template("admin_weekly.html", user=user, wc=wc)


from flask import render_template, session
from datetime import datetime


def get_current_season():
    """Season 1 starts 2025-12-01 00:00 UTC. Each season is 2 calendar months."""
    start = datetime(2025, 12, 1, tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)

    months_since = (now.year - start.year) * 12 + (now.month - start.month)
    return max(1, (months_since // 2) + 1)

@app.route("/leaderboard")
def leaderboard():
    user = current_user()
    username = user["username"] if user else None

    conn = get_db()

    # Current season + current week number
    current_season = get_current_season()
    wc = get_current_weekly()
    current_week = int(wc["week_number"]) if wc and wc.get("week_number") is not None else 1

    # === 1) All-Time (correct solves only) ===
    all_time = conn.execute("""
        SELECT
            COALESCE(u.username, s.username) AS username,
            MAX(COALESCE(u.is_admin, 0)) AS is_admin,
            MAX(COALESCE(u.is_pro, 0))   AS is_pro,
            SUM(s.score) AS total_score,
            COUNT(DISTINCT s.cipher_week) AS weeks_played
        FROM cipher_submissions s
        LEFT JOIN users u ON u.id = s.user_id
        WHERE s.username IS NOT NULL
          AND s.is_correct = 1
        GROUP BY COALESCE(u.username, s.username)
        ORDER BY total_score DESC
        LIMIT 50
    """).fetchall()

    # === 2) Seasonal (correct solves only, this season) ===
    seasonal = conn.execute("""
        SELECT
            COALESCE(u.username, s.username) AS username,
            MAX(COALESCE(u.is_admin, 0)) AS is_admin,
            MAX(COALESCE(u.is_pro, 0))   AS is_pro,
            SUM(s.score) AS total_score,
            COUNT(DISTINCT s.cipher_week) AS weeks_played
        FROM cipher_submissions s
        LEFT JOIN users u ON u.id = s.user_id
        WHERE s.username IS NOT NULL
          AND s.is_correct = 1
          AND s.season = ?
        GROUP BY COALESCE(u.username, s.username)
        ORDER BY total_score DESC
        LIMIT 50
    """, (current_season,)).fetchall()

    # === 3) Weekly Fastest Solvers (ONLY current week; resets when week_number changes) ===
    weekly = conn.execute("""
        SELECT
            COALESCE(u.username, s.username) AS username,
            MAX(COALESCE(u.is_admin, 0)) AS is_admin,
            MAX(COALESCE(u.is_pro, 0))   AS is_pro,
            MIN(s.solve_time_seconds) AS best_time,
            MAX(s.score) AS score
        FROM cipher_submissions s
        LEFT JOIN users u ON u.id = s.user_id
        WHERE s.username IS NOT NULL
          AND s.is_correct = 1
          AND s.cipher_week = ?
          AND s.solve_time_seconds IS NOT NULL
        GROUP BY COALESCE(u.username, s.username)
        ORDER BY best_time ASC
        LIMIT 50
    """, (current_week,)).fetchall()

    conn.close()

    return render_template(
        "leaderboard.html",
        user=user,
        all_time=all_time,
        seasonal=seasonal,
        weekly=weekly,
        current_season=current_season,
        current_user=username
    )

@app.route("/encode-decode")
def encode_decode():
    user = current_user()
    return render_template("encode_decode.html", user=user)

# ==============================
#  ENCODER / DECODER API ROUTES
# ==============================
from cipher_tools import encoders  # must resolve to your encoders.py

@app.route("/api/encode", methods=["POST"])
def api_encode():
    ok, _ip = rate_limit("api_cipher", limit=60, window_s=60)  # 60/min
    if not ok:
        return jsonify({"error": "Rate limit exceeded. Try again shortly."}), 429
    data = request.get_json(force=True) or {}
    text = data.get("text", "")
    cipher = (data.get("cipher") or "").strip().lower()
    key = (data.get("key") or "").strip()

    try:
        result = perform_cipher(cipher, text, key, mode="encode")
        return jsonify({"result": result})
    except Exception as e:
        print("Encode error:", e)
        return jsonify({"error": str(e)}), 400


@app.route("/api/decode", methods=["POST"])
def api_decode():
    ok, _ip = rate_limit("api_cipher", limit=60, window_s=60)  # 60/min
    if not ok:
        return jsonify({"error": "Rate limit exceeded. Try again shortly."}), 429
    data = request.get_json(force=True) or {}
    text = data.get("text", "")
    cipher = (data.get("cipher") or "").strip().lower()
    key = (data.get("key") or "").strip()

    try:
        result = perform_cipher(cipher, text, key, mode="decode")
        return jsonify({"result": result})
    except Exception as e:
        print("Decode error:", e)
        return jsonify({"error": str(e)}), 400


# ==============================
#  Helper Function
# ==============================
def perform_cipher(cipher, text, key, mode="encode"):
    """
    Centralized encoder/decoder. Soft-fails (returns a readable warning) rather than crashing.
    Defaults are chosen to match the UI (e.g., Caesar shift 7).
    """
    fn_map = {
        "caesar":     (encoders.caesar_encode,     encoders.caesar_decode),
        "vigenere":   (encoders.vigenere_encode,   encoders.vigenere_decode),
        "affine":     (encoders.affine_encode,     encoders.affine_decode),
        "atbash":     (encoders.atbash_encode,     encoders.atbash_decode),
        "railfence":  (encoders.railfence_encode,  encoders.railfence_decode),
        "columnar":   (encoders.columnar_encode,   encoders.columnar_decode),
        "polybius":   (encoders.polybius_encode,   encoders.polybius_decode),
        "base64":     (encoders.base64_encode,     encoders.base64_decode),
        "hex":        (encoders.hex_encode,        encoders.hex_decode),
        "binary":     (encoders.binary_encode,     encoders.binary_decode),
        "permutation":(encoders.permutation_encode,encoders.permutation_decode),
        "amsco":      (encoders.amsco_encode,      encoders.amsco_decode),
        "baconian":   (encoders.baconian_encode,   encoders.baconian_decode),
    }

    if cipher not in fn_map:
        return f"⚠️ Unsupported cipher: {cipher}"

    encode_func, decode_func = fn_map[cipher]
    func = encode_func if mode == "encode" else decode_func

    # small helpers
    def to_int(def_val):
        try:
            return int(key)
        except Exception:
            return def_val

    try:
        # Caesar: default shift = 7 (UI shows a→h)
        if cipher == "caesar":
            shift = to_int(7)
            return func(text, shift)

        # Affine: expects "a,b" — default (5,8)
        if cipher == "affine":
            a, b = 5, 8
            if key and "," in key:
                parts = [p.strip() for p in key.split(",", 1)]
                if len(parts) == 2:
                    try:
                        a, b = int(parts[0]), int(parts[1])
                    except Exception:
                        pass
            return func(text, a, b)

        # Rail Fence: default 3 rails
                # Rail Fence: expects "rails,offset" — default (3,0)
        if cipher == "railfence":
            rails, offset = 3, 0
            if key:
                if "," in key:
                    p1, p2 = [p.strip() for p in key.split(",", 1)]
                    try: rails = int(p1)
                    except: pass
                    try: offset = int(p2)
                    except: pass
                else:
                    # if only one number provided, treat it as rails
                    try: rails = int(key)
                    except: pass

            return func(text, rails, offset)


                # Keyed ciphers that truly need a key
        if cipher in ("vigenere", "columnar", "permutation", "amsco"):
            if not key:
                return "⚠️ Key required for this cipher."
            return func(text, key)

        # Polybius now supports custom grid key
        if cipher == "polybius":
            return func(text, key)

        # Keyless ciphers
        return func(text)


    except Exception as e:
        return f"⚠️ Error: {str(e)}"


@app.route("/admin/ban_user", methods=["POST"])
@admin_required
def admin_ban_user():
    user = current_user()
    if not user or not is_admin(user):
        return jsonify({"ok": False, "error": "Unauthorized"}), 403

    data = request.get_json(force=True)
    username = data.get("username", "").strip()
    new_ban_state = data.get("banned")

    if username == "":
        return jsonify({"ok": False, "error": "Missing username"}), 400

    conn = get_db()
    cur = conn.execute("SELECT id, banned, is_admin FROM users WHERE username = ?", (username,))
    target = cur.fetchone()

    if not target:
        conn.close()
        return jsonify({"ok": False, "error": "User not found"}), 404

    if target["is_admin"]:
        conn.close()
        return jsonify({"ok": False, "error": "You cannot ban another admin."}), 400

    # Determine toggle if not explicitly passed
    if new_ban_state is None:
        new_ban_state = 0 if target["banned"] else 1

    conn.execute("UPDATE users SET banned = ? WHERE username = ?", (int(new_ban_state), username))
    conn.commit()
    conn.close()

    action = "banned" if new_ban_state else "unbanned"
    return jsonify({
        "ok": True,
        "message": f"User '{username}' has been {action}.",
        "banned": int(new_ban_state)
    })


@app.route("/admin")
@admin_required
def admin_dashboard():
    user = current_user()

    # Only admins can access
    if not user or not is_admin(user):
        return redirect(url_for("home"))  # use "home" route

    # Fetch all users from SQLite
    conn = get_db()
    cur = conn.execute("""
        SELECT id, username, email, is_admin, banned, created_at, has_posted, is_pro
        FROM users
        ORDER BY id ASC
    """)
    users = [dict(row) for row in cur.fetchall()]
    conn.close()

    return render_template("admin.html", user=user, users=users)
# ==============================
# WORKSPACES — ALL ROUTES (DROP-IN)
# ==============================
# Matches your templates:
# - workspace_list.html uses url_for('workspace_view', ws_id=...)
# - workspace.html expects "ws" dict and hits /workspaces/<id>/save
#
# Requires you already have:
# - app, get_db(), current_user()
# - allowed_file(), secure_filename, app.config["UPLOAD_FOLDER"]
# - from flask import request, jsonify, render_template, redirect, url_for, flash, abort
# - from datetime import datetime
# - import os


from io import BytesIO
from flask import send_file
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch

def _history_add_snapshot(conn, ws_row, reason="save", max_keep=200):
    """
    ws_row is a row/dict containing id, owner_id, title, notes, cipher_text.
    Keeps at most max_keep snapshots per workspace (delete oldest beyond limit).
    """
    conn.execute("""
        INSERT INTO workspace_history (workspace_id, owner_id, title, notes, cipher_text, reason)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (ws_row["id"], ws_row["owner_id"], ws_row.get("title") or "", ws_row.get("notes") or "", ws_row.get("cipher_text") or "", reason))

    # prune old snapshots
    conn.execute("""
        DELETE FROM workspace_history
        WHERE id IN (
          SELECT id FROM workspace_history
          WHERE workspace_id=?
          ORDER BY datetime(created_at) DESC
          LIMIT -1 OFFSET ?
        )
    """, (ws_row["id"], max_keep))


def init_workspaces():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS workspaces (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      owner_id INTEGER NOT NULL,
      title TEXT NOT NULL DEFAULT 'Untitled Workspace',
      cipher_text TEXT NOT NULL DEFAULT '',
      notes TEXT NOT NULL DEFAULT '',
      cipher_image_filename TEXT,
      order_index INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(owner_id) REFERENCES users(id)
    );
    """)

    cur.execute("PRAGMA table_info(workspaces)")
    cols = {r[1] for r in cur.fetchall()}

    if "order_index" not in cols:
        cur.execute("ALTER TABLE workspaces ADD COLUMN order_index INTEGER NOT NULL DEFAULT 0")

    # helpful index
    cur.execute("""
    CREATE INDEX IF NOT EXISTS idx_workspaces_owner_order
    ON workspaces(owner_id, order_index);
    """)

    conn.commit()
    conn.close()

# Call once on boot (core tables/migrations + workspaces)
init_core_tables_on_boot()
init_workspaces()


# ----------------------
# Workspaces list
# GET /workspaces
# ----------------------
@app.route("/workspaces", methods=["GET"], endpoint="workspace_list")
def workspace_list():
    user = current_user()

    if not user:
        # guest view
        return render_template(
            "workspace_list.html",
            user=user,
            viewer_is_pro=False,
            free_max_labs=FREE_MAX_LABS,
            workspaces=[],
        )

    # Refresh user so Pro state is accurate for gating/UI.
    conn = get_db()
    fresh_user = conn.execute(
        "SELECT * FROM users WHERE id=? LIMIT 1",
        (user["id"],)
    ).fetchone()
    viewer_is_pro = is_pro(fresh_user) if fresh_user else is_pro(user)

    rows = conn.execute("""
        SELECT
            w.id, w.title, w.cipher_text, w.notes, w.cipher_image_filename,
            w.created_at, w.updated_at,
            CASE WHEN w.owner_id=? THEN 1 ELSE 0 END AS is_owner
        FROM workspaces w
        WHERE w.owner_id=?
           OR EXISTS (
             SELECT 1 FROM workspace_collaborators wc
             WHERE wc.workspace_id=w.id AND wc.user_id=?
           )
        ORDER BY is_owner DESC, w.order_index ASC, datetime(w.updated_at) DESC
    """, (user["id"], user["id"], user["id"])).fetchall()
    conn.close()

    return render_template(
        "workspace_list.html",
        user=user,
        workspaces=[dict(r) for r in rows],
        viewer_is_pro=viewer_is_pro,
        free_max_labs=FREE_MAX_LABS,
    )
# ----------------------
# Create workspace
# GET shows create form, POST creates + redirects
# /workspaces/new
# ----------------------
@app.route("/workspaces/new", methods=["GET", "POST"], endpoint="workspace_new")
def workspace_new():
    user = current_user()

    if not user:
        flash("Please log in.", "warning")
        return redirect(url_for("login"))


    if request.method == "POST":
        ok, _ip = rate_limit("ws_create", limit=10, window_s=3600)  # 10/hour
        if not ok:
            flash("Too many labs created recently. Try again later.", "error")
            return redirect(url_for("workspace_list"))

    if request.method == "GET":
        return render_template("workspace_new.html", user=user)

    # ✅ Enforce free limit
    conn = get_db()
    cur = conn.execute("SELECT COUNT(*) AS c FROM workspaces WHERE owner_id=?", (user["id"],))
    lab_count = cur.fetchone()["c"] or 0

    if (not is_pro(user)) and lab_count >= FREE_MAX_LABS:
        conn.close()
        flash(f"Free plan limit: {FREE_MAX_LABS} Labs. Upgrade to Labs Pro for unlimited labs.", "warning")
        return redirect(url_for("workspace_list"))

    title = (request.form.get("title") or "Untitled Lab").strip() or "Untitled Lab"
    now = datetime.utcnow().isoformat()

    cur = conn.cursor()
    cur.execute("""
        INSERT INTO workspaces (owner_id, title, cipher_text, notes, created_at, updated_at)
        VALUES (?, ?, '', '', ?, ?)
    """, (user["id"], title, now, now))
    ws_id = cur.lastrowid
    conn.commit()
    conn.close()

    return redirect(url_for("workspace_view", ws_id=ws_id))


# ----------------------
# View workspace
# GET /workspaces/<id>
# endpoint MUST be workspace_view because your list template calls it
# ----------------------
@app.route("/workspaces/<int:ws_id>", methods=["GET"], endpoint="workspace_view")
def workspace_view(ws_id):
    user = current_user()
    if not user:
        flash("Please log in.", "warning")
        return redirect(url_for("login"))

    conn = get_db()

    # ✅ Admin override: admins can view any lab (view-only)
    if is_admin(user):
        row = conn.execute("""
            SELECT *
            FROM workspaces
            WHERE id = ?
            LIMIT 1
        """, (ws_id,)).fetchone()

        if not row:
            conn.close()
            abort(404)

        ws = dict(row)

        # refresh user for pro flag correctness (keep your existing behavior)
        fresh_user = conn.execute("SELECT * FROM users WHERE id=? LIMIT 1", (user["id"],)).fetchone()
        fresh_user = dict(fresh_user) if fresh_user else user

        conn.close()

        return render_template(
            "workspace.html",
            user=fresh_user,
            ws=ws,
            is_owner=False,
            show_tour=(not fresh_user.get("labs_tour_seen")),
            viewer_role="admin",
            viewer_can_edit=False,  # admin view-only in lab UI
            viewer_is_pro=is_pro(fresh_user),
            avg_tabs_per_lab=None,
            avg_labs_per_owner=None,
            total_tabs=None,
        )

    # ✅ Normal users: owner or collaborator only (your existing logic)
    row = conn.execute("""
        SELECT *
        FROM workspaces
        WHERE id = ?
          AND (
            owner_id = ?
            OR EXISTS (
              SELECT 1 FROM workspace_collaborators
              WHERE workspace_id = workspaces.id AND user_id = ?
            )
          )
        LIMIT 1
    """, (ws_id, user["id"], user["id"])).fetchone()

    if not row:
        conn.close()
        abort(404)

    ws = dict(row)

    # Viewer context
    is_owner = (ws["owner_id"] == user["id"])
    role = None
    if not is_owner:
        r = conn.execute("""
            SELECT role FROM workspace_collaborators
            WHERE workspace_id=? AND user_id=?
            LIMIT 1
        """, (ws_id, user["id"])).fetchone()
        role = (r["role"] if r else "viewer")  # default safe

    viewer_can_edit = True if is_owner else (role == "editor")

    # refresh user for pro flag correctness
    fresh_user = conn.execute("SELECT * FROM users WHERE id=? LIMIT 1", (user["id"],)).fetchone()
    fresh_user = dict(fresh_user) if fresh_user else user

    conn.close()

    return render_template(
        "workspace.html",
        user=fresh_user,
        ws=ws,
        is_owner=is_owner,
        show_tour=(not fresh_user.get("labs_tour_seen")),
        viewer_role=("owner" if is_owner else (role or "viewer")),
        viewer_can_edit=viewer_can_edit,
        viewer_is_pro=is_pro(fresh_user),
        avg_tabs_per_lab=None,
        avg_labs_per_owner=None,
        total_tabs=None,
    )

# ----------------------
# Save workspace (AJAX)
# POST /workspaces/<id>/save
# ----------------------
@app.route("/workspaces/<int:ws_id>/save", methods=["POST"])
def workspace_save(ws_id):
    user = current_user()
    if not user:
        return jsonify({"ok": False, "error": "login required"}), 401

    

    title = (request.form.get("title") or "").strip() or "Untitled Workspace"
    notes = request.form.get("notes") or ""
    cipher_text = request.form.get("cipher_text") or ""
    now = datetime.utcnow().isoformat()
    if contains_profanity(title) or contains_profanity(notes):
        flash("Your post contains inappropriate language.", "error")
        return redirect(url_for("posts_new"))
    conn = get_db()

    # ✅ Editors can save
    if not can_edit_workspace(conn, ws_id, user["id"]):
        conn.close()
        return jsonify({"ok": False, "error": "forbidden"}), 403

    cur = conn.cursor()
    cur.execute("""
        UPDATE workspaces
        SET title = ?, notes = ?, cipher_text = ?, updated_at = ?
        WHERE id = ?
    """, (title, notes, cipher_text, now, ws_id))
    changed = cur.rowcount

    # ✅ Pro snapshot: only if is_pro(user) AND we can read ws
    try:
        if changed and is_pro(user):
            # Only snapshot if last snapshot was long enough ago
            last = conn.execute("""
                SELECT created_at
                FROM workspace_history
                WHERE workspace_id=?
                ORDER BY datetime(created_at) DESC
                LIMIT 1
            """, (ws_id,)).fetchone()

            should_snapshot = True

            if last:
                last_time = datetime.fromisoformat(last["created_at"])
                delta = (datetime.utcnow() - last_time).total_seconds()

                # ⏱ throttle: 1 snapshot every 120 seconds
                if delta < 120:
                    should_snapshot = False

            if should_snapshot:
                ws_row = conn.execute("""
                    SELECT id, owner_id, title, notes, cipher_text
                    FROM workspaces
                    WHERE id=? LIMIT 1
                """, (ws_id,)).fetchone()
                if ws_row:
                    _history_add_snapshot(conn, dict(ws_row), reason="save")

    except Exception as e:
        app.logger.exception("history snapshot failed: %s", e)

    conn.commit()
    conn.close()

    if not changed:
        return jsonify({"ok": False, "error": "not found"}), 404

    return jsonify({"ok": True, "updated_at": now})


import logging
logging.getLogger("werkzeug").setLevel(logging.INFO)
logging.getLogger("werkzeug").disabled = False


# ============================================================
# NEW: Workspace Images helpers + routes (for tabs / multi-image)
# ============================================================

def _workspace_owned(conn, ws_id, owner_id):
    row = conn.execute(
        "SELECT id FROM workspaces WHERE id=? AND owner_id=? LIMIT 1",
        (ws_id, owner_id)
    ).fetchone()
    return bool(row)


# ----------------------
# NEW: List images for workspace (tabs)
# GET /workspaces/<id>/images
# ----------------------
@app.route("/workspaces/<int:ws_id>/images", methods=["GET"])
def workspace_images_list(ws_id):
    user = current_user()
    if not user:
        return jsonify({"ok": False, "error": "login required"}), 401

    conn = get_db()
    if not can_access_workspace(conn, ws_id, user["id"]):
        conn.close()
        return jsonify({"ok": False, "error": "not found"}), 404

    rows = conn.execute("""
        SELECT id, filename, label, sort_index, created_at
        FROM workspace_images
        WHERE workspace_id=?
        ORDER BY sort_index ASC, id ASC
    """, (ws_id,)).fetchall()
    conn.close()

    images = []
    for r in rows:
        images.append({
            "id": r["id"],
            "filename": r["filename"],
            "label": r["label"],
            "url": url_for("uploaded_file", filename=r["filename"]),
        })

    return jsonify({"ok": True, "images": images})


# ----------------------
# REPLACED: Upload cipher image (MULTI)
# POST /workspaces/<id>/image
# - Always creates a NEW image row (new tab)
# ----------------------
@app.route("/workspaces/<int:ws_id>/image", methods=["POST"])
def workspace_image_upload(ws_id):
    user = current_user()
    if not user:
        return jsonify({"ok": False, "error": "login required"}), 401

    img = request.files.get("image")
    if not img or not img.filename:
        return jsonify({"ok": False, "error": "no image provided"}), 400
    

    conn = get_db()

    # ✅ Editors can upload
    if not can_edit_workspace(conn, ws_id, user["id"]):
        conn.close()
        return jsonify({"ok": False, "error": "forbidden"}), 403

    # enforce free tabs limit (only for non-pro)
    cur = conn.execute("SELECT COUNT(*) AS c FROM workspace_images WHERE workspace_id=?", (ws_id,))
    tab_count = cur.fetchone()["c"] or 0
    if (not is_pro(user)) and tab_count >= FREE_MAX_TABS:
        conn.close()
        return jsonify({
            "ok": False,
            "error": f"Free plan limit: {FREE_MAX_TABS} tabs per Lab. Upgrade to Labs Pro for unlimited tabs."
        }), 403

    row = conn.execute("""
        SELECT COALESCE(MAX(sort_index), -1) AS mx
        FROM workspace_images
        WHERE workspace_id=?
    """, (ws_id,)).fetchone()
    next_index = int(row["mx"] if row and row["mx"] is not None else -1) + 1
    label = f"Image {next_index + 1}"

    filename = secure_filename(f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{img.filename}")
    img.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

    now = datetime.utcnow().isoformat()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO workspace_images (workspace_id, filename, label, sort_index)
        VALUES (?, ?, ?, ?)
    """, (ws_id, filename, label, next_index))
    new_id = cur.lastrowid

    # ✅ no owner filter
    conn.execute("UPDATE workspaces SET updated_at=? WHERE id=?", (now, ws_id))

    conn.commit()
    conn.close()

    return jsonify({
        "ok": True,
        "image": {
            "id": new_id,
            "filename": filename,
            "label": label,
            "url": url_for("uploaded_file", filename=filename)
        },
        "updated_at": now
    })

# ----------------------
# REPLACED: Delete cipher image (MULTI)
# POST /workspaces/<id>/image/delete
# Body JSON: { "image_id": 123 }
# ----------------------
@app.route("/workspaces/<int:ws_id>/image/delete", methods=["POST"])
def workspace_image_delete(ws_id):
    user = current_user()
    if not user:
        return jsonify({"ok": False, "error": "login required"}), 401

    data = request.get_json(silent=True) or {}
    image_id = data.get("image_id")
    try:
        image_id = int(image_id)
    except Exception:
        return jsonify({"ok": False, "error": "image_id required"}), 400

    conn = get_db()

    if not can_edit_workspace(conn, ws_id, user["id"]):
        conn.close()
        return jsonify({"ok": False, "error": "forbidden"}), 403

    row = conn.execute("""
        SELECT id, filename
        FROM workspace_images
        WHERE id=? AND workspace_id=?
        LIMIT 1
    """, (image_id, ws_id)).fetchone()

    if not row:
        conn.close()
        return jsonify({"ok": False, "error": "image not found"}), 404

    filename = row["filename"]
    now = datetime.utcnow().isoformat()

    conn.execute("DELETE FROM workspace_images WHERE id=? AND workspace_id=?", (image_id, ws_id))
    conn.execute("UPDATE workspaces SET updated_at=? WHERE id=?", (now, ws_id))

    conn.commit()
    conn.close()

    # delete the file on disk
    try:
        path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        if os.path.exists(path):
            os.remove(path)
    except Exception:
        pass

    return jsonify({"ok": True, "updated_at": now})


# ----------------------
# REPLACED: Delete workspace (UPDATED: deletes all images too)
# POST /workspaces/<id>/delete
# ----------------------
@app.route("/workspaces/<int:ws_id>/delete", methods=["POST"])
def workspace_delete(ws_id):
    user = current_user()
    if not user:
        return jsonify({"ok": False, "error": "login required"}), 401

    conn = get_db()
    if not _workspace_owned(conn, ws_id, user["id"]):
        conn.close()
        return jsonify({"ok": False, "error": "not found"}), 404

    imgs = conn.execute("""
        SELECT filename FROM workspace_images WHERE workspace_id=?
    """, (ws_id,)).fetchall()
    filenames = [r["filename"] for r in imgs]

    conn.execute("DELETE FROM workspace_images WHERE workspace_id=?", (ws_id,))
    conn.execute("DELETE FROM workspaces WHERE id=? AND owner_id=?", (ws_id, user["id"]))
    conn.commit()
    conn.close()

    for fn in filenames:
        try:
            path = os.path.join(app.config["UPLOAD_FOLDER"], fn)
            if os.path.exists(path):
                os.remove(path)
        except Exception:
            pass

    return jsonify({"ok": True})


# ----------------------
# Leave as-is: reorder
# POST /workspaces/reorder
# ----------------------
@app.route("/workspaces/reorder", methods=["POST"])
def workspace_reorder():
    user = current_user()
    if not user:
        return jsonify({"ok": False, "error": "login required"}), 401

    data = request.get_json(silent=True) or {}
    order = data.get("order")

    if not isinstance(order, list):
        return jsonify({"ok": False, "error": "invalid payload"}), 400

    conn = get_db()
    cur = conn.cursor()

    for idx, ws_id in enumerate(order):
        cur.execute("""
            UPDATE workspaces
            SET order_index = ?
            WHERE id = ? AND owner_id = ?
        """, (idx, ws_id, user["id"]))

    conn.commit()
    conn.close()

    return jsonify({"ok": True})


# ----------------------
# Leave as-is: prefs
# POST /prefs/labs-info-seen
# ----------------------
@app.route("/prefs/labs-info-seen", methods=["POST"])
def prefs_labs_info_seen():
    user = current_user()
    if not user:
        return jsonify({"ok": False, "error": "login required"}), 401

    conn = get_db()
    conn.execute("""
        UPDATE users
        SET labs_info_seen = 1
        WHERE id = ?
    """, (user["id"],))
    conn.commit()
    conn.close()

    return jsonify({"ok": True})


@app.route("/workspaces/<int:ws_id>/image/rename", methods=["POST"])
def workspace_image_rename(ws_id):
    user = current_user()
    if not user:
        return jsonify({"ok": False, "error": "login required"}), 401

    data = request.get_json(silent=True) or {}
    image_id = data.get("image_id")
    label = (data.get("label") or "").strip()

    try:
        image_id = int(image_id)
    except Exception:
        return jsonify({"ok": False, "error": "image_id required"}), 400

    if not label:
        return jsonify({"ok": False, "error": "label required"}), 400

    if len(label) > 60:
        label = label[:60].strip()

    conn = get_db()

    if not can_edit_workspace(conn, ws_id, user["id"]):
        conn.close()
        return jsonify({"ok": False, "error": "forbidden"}), 403

    row = conn.execute("""
        SELECT id
        FROM workspace_images
        WHERE id=? AND workspace_id=?
        LIMIT 1
    """, (image_id, ws_id)).fetchone()
    if not row:
        conn.close()
        return jsonify({"ok": False, "error": "image not found"}), 404

    now = datetime.utcnow().isoformat()

    conn.execute("""
        UPDATE workspace_images
        SET label=?
        WHERE id=? AND workspace_id=?
    """, (label, image_id, ws_id))

    conn.execute("UPDATE workspaces SET updated_at=? WHERE id=?", (now, ws_id))

    conn.commit()
    conn.close()

    return jsonify({"ok": True, "label": label, "updated_at": now})
@app.route("/weekly/open_lab", methods=["POST"])
def weekly_open_lab():
    user = current_user()
    if not user:
        return jsonify({"ok": False, "error": "login required"}), 401

    wc = get_current_weekly()
    if not wc:
        return jsonify({"ok": False, "error": "weekly cipher not found"}), 404

    conn = get_db()

    # ✅ Enforce free limit
    cur = conn.execute("SELECT COUNT(*) AS c FROM workspaces WHERE owner_id=?", (user["id"],))
    lab_count = cur.fetchone()["c"] or 0
    if (not is_pro(user)) and lab_count >= FREE_MAX_LABS:
        conn.close()
        return jsonify({
            "ok": False,
            "error": f"Free plan limit: {FREE_MAX_LABS} Labs. Upgrade to Labs Pro for unlimited labs."
        }), 403

    title = f"Weekly Cipher — Week #{wc['week_number']}"
    posted = (wc.get("posted_at") or "")[:19].replace("T", " ")

    notes = (
        f"[Weekly Cipher]\n"
        f"Week: {wc.get('week_number')}\n"
        f"Title: {wc.get('title')}\n"
        f"Posted: {posted}\n"
        f"Season: {get_current_season()}\n"
        f"\n"
        f"Description:\n{(wc.get('description') or '—')}\n"
        f"\n"
        f"Hint:\n{(wc.get('hint') or '—')}\n"
    )

    cipher_text = wc.get("ciphertext") or ""
    now = datetime.utcnow().isoformat()

    cur = conn.cursor()
    cur.execute("""
        INSERT INTO workspaces (owner_id, title, cipher_text, notes, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (user["id"], title, cipher_text, notes, now, now))

    ws_id = cur.lastrowid
    conn.commit()
    conn.close()

    return jsonify({"ok": True, "ws_id": ws_id})



from helpers import get_currency, get_currency_symbol

PRICE_DISPLAY = {
  "GBP": {"old": "4.99", "new": "2.99"},
  "EUR": {"old": "5.99", "new": "3.49"},
  "USD": {"old": "6.99", "new": "3.99"},
}

@app.route("/labs-pro")
def labs_pro_page():
    user = current_user()
    viewer_is_pro = False

    if user:
        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE id=? LIMIT 1",
            (user["id"],)
        ).fetchone()
        conn.close()

        viewer_is_pro = is_pro(user)

    cur = get_currency()
    sym = get_currency_symbol()
    p = PRICE_DISPLAY.get(cur, PRICE_DISPLAY["GBP"])
    return render_template(
        "labs_pro.html",
        user=current_user(),
        viewer_is_pro=viewer_is_pro,
        currency_code=cur,
        currency_symbol=sym,
        old_price=p["old"],
        new_price=p["new"],
    )

import secrets

def can_access_workspace(conn, ws_id, user_id):
    row = conn.execute("""
        SELECT 1
        FROM workspaces w
        WHERE w.id=?
          AND (
            w.owner_id=?
            OR EXISTS (
              SELECT 1 FROM workspace_collaborators wc
              WHERE wc.workspace_id=w.id AND wc.user_id=?
            )
          )
        LIMIT 1
    """, (ws_id, user_id, user_id)).fetchone()
    return bool(row)


def collaborator_role(conn, ws_id, user_id):
    row = conn.execute("""
        SELECT role
        FROM workspace_collaborators
        WHERE workspace_id=? AND user_id=?
        LIMIT 1
    """, (ws_id, user_id)).fetchone()
    return row["role"] if row else None

def can_edit_workspace(conn, ws_id, user_id):
    row = conn.execute("SELECT owner_id FROM workspaces WHERE id=? LIMIT 1", (ws_id,)).fetchone()
    if not row:
        return False
    if row["owner_id"] == user_id:
        return True
    return collaborator_role(conn, ws_id, user_id) == "editor"

@app.post("/workspaces/<int:ws_id>/share/create")
def workspace_share_create(ws_id):
    user = current_user()
    if not user:
        return jsonify({"ok": False, "error": "login required"}), 401
    
    
    if not is_pro(user):
        return jsonify({"ok": False, "error": "Labs Pro required"}), 403
    
    conn = get_db()
    ws = conn.execute("""
        SELECT id FROM workspaces
        WHERE id=? AND owner_id=?
        LIMIT 1
    """, (ws_id, user["id"])).fetchone()

    if not ws:
        conn.close()
        return jsonify({"ok": False, "error": "forbidden"}), 403

    token = secrets.token_urlsafe(18)  # unguessable
    conn.execute("""
        UPDATE workspaces
        SET is_shared=1, share_token=?
        WHERE id=? AND owner_id=?
    """, (token, ws_id, user["id"]))
    conn.commit()
    conn.close()

    return jsonify({
        "ok": True,
        "share_url": url_for("shared_lab_join", token=token, _external=True)
    })


@app.post("/workspaces/<int:ws_id>/share/disable")
def workspace_share_disable(ws_id):
    user = current_user()
    if not user:
        return jsonify({"ok": False, "error": "login required"}), 401

    if not is_pro(user):
        return jsonify({"ok": False, "error": "Labs Pro required"}), 403

    conn = get_db()
    ws = conn.execute("""
        SELECT id FROM workspaces
        WHERE id=? AND owner_id=?
        LIMIT 1
    """, (ws_id, user["id"])).fetchone()
    if not ws:
        conn.close()
        return jsonify({"ok": False, "error": "forbidden"}), 403

    # kill token + remove collaborators
    conn.execute("UPDATE workspaces SET is_shared=0, share_token=NULL WHERE id=? AND owner_id=?", (ws_id, user["id"]))
    conn.execute("DELETE FROM workspace_collaborators WHERE workspace_id=?", (ws_id,))
    conn.commit()
    conn.close()

    return jsonify({"ok": True})
@app.route("/labs/shared/<token>", methods=["GET"], endpoint="shared_lab_join")
def shared_lab_join(token):
    user = current_user()
    if not user:
        return redirect(url_for("login", next=request.path, reason="pro_analysis"))

    conn = get_db()
    ws = conn.execute("""
        SELECT id, owner_id
        FROM workspaces
        WHERE share_token=? AND is_shared=1
        LIMIT 1
    """, (token,)).fetchone()

    if not ws:
        conn.close()
        abort(404)

    # owner doesn't need collaborator row
    if ws["owner_id"] != user["id"]:
        conn.execute("""
            INSERT OR IGNORE INTO workspace_collaborators (workspace_id, user_id, role)
            VALUES (?, ?, 'editor')
        """, (ws["id"], user["id"]))
        conn.commit()

    conn.close()
    return redirect(url_for("workspace_view", ws_id=ws["id"]))


@app.get("/workspaces/<int:ws_id>/share/collaborators")
def workspace_share_collaborators(ws_id):
    user = current_user()
    if not user:
        return jsonify({"ok": False, "error": "login required"}), 401

    # CoLab is Pro-only in your product rules
    if not is_pro(user):
        return jsonify({"ok": False, "error": "Labs Pro required"}), 403

    conn = get_db()
    ws = conn.execute("""
        SELECT owner_id, share_token, is_shared
        FROM workspaces
        WHERE id=?
        LIMIT 1
    """, (ws_id,)).fetchone()

    if not ws:
        conn.close()
        return jsonify({"ok": False, "error": "not found"}), 404

    owner_id = ws["owner_id"]

    # Determine my role
    if owner_id == user["id"]:
        my_role = "owner"
        owner_only = False
    else:
        r = conn.execute("""
            SELECT role
            FROM workspace_collaborators
            WHERE workspace_id=? AND user_id=?
            LIMIT 1
        """, (ws_id, user["id"])).fetchone()

        if not r:
            conn.close()
            return jsonify({"ok": False, "error": "forbidden"}), 403

        my_role = (r["role"] or "viewer").strip().lower()
        if my_role not in ("editor", "viewer"):
            my_role = "viewer"
        owner_only = True

    rows = conn.execute("""
        SELECT wc.user_id, wc.role, wc.added_at, u.username
        FROM workspace_collaborators wc
        LEFT JOIN users u ON u.id = wc.user_id
        WHERE wc.workspace_id=?
        ORDER BY datetime(wc.added_at) DESC
    """, (ws_id,)).fetchall()

    conn.close()

    return jsonify({
        "ok": True,
        "owner_id": owner_id,
        "my_role": my_role,
        "owner_only": owner_only,

        "is_shared": bool(ws["is_shared"]),
        "share_url": url_for("shared_lab_join", token=ws["share_token"], _external=True) if ws["share_token"] else None,

        "collaborators": [dict(r) for r in rows]
    })


@app.post("/workspaces/<int:ws_id>/share/remove")
def workspace_share_remove(ws_id):
    user = current_user()
    if not user:
        return jsonify({"ok": False, "error": "login required"}), 401


    if not is_pro(user):
        return jsonify({"ok": False, "error": "Labs Pro required"}), 403

    data = request.get_json(silent=True) or {}
    target_id = int(data.get("user_id") or 0)
    if not target_id:
        return jsonify({"ok": False, "error": "user_id required"}), 400

    conn = get_db()
    ws = conn.execute("SELECT owner_id FROM workspaces WHERE id=? LIMIT 1", (ws_id,)).fetchone()
    if not ws:
        conn.close()
        return jsonify({"ok": False, "error": "not found"}), 404
    if ws["owner_id"] != user["id"]:
        conn.close()
        return jsonify({"ok": False, "error": "forbidden"}), 403

    conn.execute("DELETE FROM workspace_collaborators WHERE workspace_id=? AND user_id=?", (ws_id, target_id))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/workspaces/can-create", methods=["GET"])
def workspace_can_create():
    user = current_user()
    if not user:
        return jsonify({
            "ok": False,
            "can_create": False,
            "error": "login required",
            "redirect": url_for("login", next=url_for("workspace_list"))
        }), 401

    conn = get_db()

    # ✅ refresh user so is_pro() has the right fields
    fresh = conn.execute("SELECT * FROM users WHERE id=? LIMIT 1", (user["id"],)).fetchone()
    if not fresh:
        conn.close()
        return jsonify({"ok": False, "can_create": False, "error": "login required"}), 401
    fresh = dict(fresh)

    lab_count = conn.execute(
        "SELECT COUNT(*) AS c FROM workspaces WHERE owner_id=?",
        (user["id"],)
    ).fetchone()["c"] or 0

    conn.close()

    if (not is_pro(fresh)) and lab_count >= FREE_MAX_LABS:
        return jsonify({
            "ok": False,
            "can_create": False,
            "error": f"Free plan limit: {FREE_MAX_LABS} Labs. Upgrade to Labs Pro for unlimited labs.",
            "upgrade_url": url_for("labs_pro_page")
        }), 402

    return jsonify({
        "ok": True,
        "can_create": True
    })


@app.route("/workspaces/<int:ws_id>/history", methods=["GET"])
def workspace_history_list(ws_id):
    user = current_user()
    if not user:
        return jsonify({"ok": False, "error": "login required"}), 401

    if not is_pro(user):
        return jsonify({"ok": False, "error": "Labs Pro required"}), 403

    conn = get_db()
    ws = conn.execute("SELECT id FROM workspaces WHERE id=? AND owner_id=? LIMIT 1", (ws_id, user["id"])).fetchone()
    if not ws:
        conn.close()
        return jsonify({"ok": False, "error": "not found"}), 404

    rows = conn.execute("""
        SELECT id, created_at, reason, title
        FROM workspace_history
        WHERE workspace_id=? AND owner_id=?
        ORDER BY datetime(created_at) DESC
        LIMIT 80
    """, (ws_id, user["id"])).fetchall()
    conn.close()

    return jsonify({
        "ok": True,
        "history": [dict(r) for r in rows]
    })

@app.route("/workspaces/<int:ws_id>/history/<int:h_id>/restore", methods=["POST"])
def workspace_history_restore(ws_id, h_id):
    user = current_user()
    if not user:
        return jsonify({"ok": False, "error": "login required"}), 401

    if not is_pro(user):
        return jsonify({"ok": False, "error": "Labs Pro required"}), 403

    conn = get_db()
    ws = conn.execute("SELECT * FROM workspaces WHERE id=? AND owner_id=? LIMIT 1", (ws_id, user["id"])).fetchone()
    if not ws:
        conn.close()
        return jsonify({"ok": False, "error": "not found"}), 404

    snap = conn.execute("""
        SELECT title, notes, cipher_text
        FROM workspace_history
        WHERE id=? AND workspace_id=? AND owner_id=?
        LIMIT 1
    """, (h_id, ws_id, user["id"])).fetchone()

    if not snap:
        conn.close()
        return jsonify({"ok": False, "error": "snapshot not found"}), 404

    now = datetime.utcnow().isoformat()

    conn.execute("""
        UPDATE workspaces
        SET title=?, notes=?, cipher_text=?, updated_at=?
        WHERE id=? AND owner_id=?
    """, (snap["title"], snap["notes"], snap["cipher_text"], now, ws_id, user["id"]))

    # also record a snapshot of the restore action (so you can undo restores)
    try:
        _history_add_snapshot(conn, {
            "id": ws_id,
            "owner_id": user["id"],
            "title": snap["title"],
            "notes": snap["notes"],
            "cipher_text": snap["cipher_text"],
        }, reason="restore")
    except Exception:
        pass

    conn.commit()
    conn.close()

    return jsonify({"ok": True, "updated_at": now})


@app.route("/workspaces/<int:ws_id>/clone", methods=["POST"])
def workspace_clone(ws_id):
    user = current_user()
    if not user:
        return jsonify({"ok": False, "error": "login required"}), 401

    if not is_pro(user):
        return jsonify({"ok": False, "error": "pro_required"}), 402

    conn = get_db()

    # owner-only clone
    if not _workspace_owned(conn, ws_id, user["id"]):
        conn.close()
        return jsonify({"ok": False, "error": "owner_required"}), 403

    src = conn.execute("""
        SELECT id, owner_id, title, notes, cipher_text
        FROM workspaces
        WHERE id=? AND owner_id=?
        LIMIT 1
    """, (ws_id, user["id"])).fetchone()

    if not src:
        conn.close()
        return jsonify({"ok": False, "error": "not found"}), 404

    now = datetime.utcnow().isoformat()
    new_title = (src["title"] or "Untitled Lab").strip()
    new_title = f"{new_title} (Copy)"

    cur = conn.cursor()
    cur.execute("""
        INSERT INTO workspaces (owner_id, title, cipher_text, notes, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (user["id"], new_title, src["cipher_text"] or "", src["notes"] or "", now, now))
    new_id = cur.lastrowid

    # clone images rows (same filenames)
    try:
        rows = conn.execute("""
            SELECT filename, label, sort_index
            FROM workspace_images
            WHERE workspace_id=?
            ORDER BY sort_index ASC, id ASC
        """, (ws_id,)).fetchall()

        for r in rows:
            conn.execute("""
                INSERT INTO workspace_images (workspace_id, filename, label, sort_index)
                VALUES (?, ?, ?, ?)
            """, (new_id, r["filename"], r["label"], r["sort_index"]))
    except Exception:
        pass

    conn.commit()
    conn.close()

    return jsonify({"ok": True, "ws_id": new_id})

@app.post("/workspaces/<int:ws_id>/share/role")
def workspace_share_set_role(ws_id):
    user = current_user()
    if not user:
        return jsonify({"ok": False, "error": "login required"}), 401

    if not is_pro(user):
        return jsonify({"ok": False, "error": "pro_required"}), 402

    data = request.get_json(silent=True) or {}
    try:
        target_id = int(data.get("user_id") or 0)
    except Exception:
        target_id = 0
    role = (data.get("role") or "").strip().lower()

    if not target_id:
        return jsonify({"ok": False, "error": "user_id required"}), 400
    if role not in ("editor", "viewer"):
        return jsonify({"ok": False, "error": "invalid role"}), 400

    conn = get_db()
    ws = conn.execute("SELECT owner_id FROM workspaces WHERE id=? LIMIT 1", (ws_id,)).fetchone()
    if not ws:
        conn.close()
        return jsonify({"ok": False, "error": "not found"}), 404

    if ws["owner_id"] != user["id"]:
        conn.close()
        return jsonify({"ok": False, "error": "owner_required"}), 403

    conn.execute("""
        UPDATE workspace_collaborators
        SET role=?
        WHERE workspace_id=? AND user_id=?
    """, (role, ws_id, target_id))

    conn.commit()
    conn.close()
    return jsonify({"ok": True, "role": role})

from io import BytesIO
import os
from datetime import datetime

from flask import send_file, abort, redirect, url_for, jsonify
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, HRFlowable, Image as RLImage, PageBreak
)
from reportlab.pdfbase.pdfmetrics import stringWidth

@app.route("/workspaces/<int:ws_id>/export.pdf", methods=["GET"])
def workspace_export_pdf(ws_id):
    user = current_user()
    if not user:
        return redirect(url_for("login", next=url_for("workspace_view", ws_id=ws_id)))

    if not is_pro(user):
        return jsonify({"ok": False, "error": "Labs Pro required"}), 403

    conn = get_db()
    ws = conn.execute("""
        SELECT id, owner_id, title, notes, cipher_text, updated_at
        FROM workspaces
        WHERE id=? AND owner_id=?
        LIMIT 1
    """, (ws_id, user["id"])).fetchone()
    if not ws:
        conn.close()
        abort(404)

    img_rows = conn.execute("""
        SELECT id, filename, label, sort_index, created_at
        FROM workspace_images
        WHERE workspace_id=?
        ORDER BY sort_index ASC, id ASC
    """, (ws_id,)).fetchall()

    ws = dict(ws)
    images = [dict(r) for r in img_rows]
    conn.close()

    # --------------------
    # Build PDF with Platypus
    # --------------------
    buf = BytesIO()

    # slightly wider content, looks more modern
    left = right = 0.75 * inch
    top = 0.75 * inch
    bottom = 0.75 * inch

    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
        leftMargin=left, rightMargin=right,
        topMargin=top, bottomMargin=bottom,
        title=f"Cipher Lab #{ws_id}",
        author="The Cipher Lab"
    )

    styles = getSampleStyleSheet()

    # Custom styles (clean + compact)
    H1 = ParagraphStyle(
        "H1", parent=styles["Title"],
        fontName="Helvetica-Bold", fontSize=18, leading=22,
        spaceAfter=6
    )
    META = ParagraphStyle(
        "META", parent=styles["Normal"],
        fontName="Helvetica", fontSize=9.5, leading=12,
        textColor=colors.HexColor("#555555"),
        spaceAfter=10
    )
    H2 = ParagraphStyle(
        "H2", parent=styles["Heading2"],
        fontName="Helvetica-Bold", fontSize=12.5, leading=16,
        textColor=colors.HexColor("#111111"),
        spaceBefore=8, spaceAfter=6
    )
    BODY = ParagraphStyle(
        "BODY", parent=styles["Normal"],
        fontName="Helvetica", fontSize=10.5, leading=14,
        textColor=colors.HexColor("#111111")
    )
    CODE = ParagraphStyle(
        "CODE", parent=styles["Normal"],
        fontName="Courier", fontSize=9.5, leading=12,
        textColor=colors.HexColor("#111111"),
        backColor=colors.HexColor("#F5F5F5"),
        borderPadding=8,
        spaceBefore=2, spaceAfter=2
    )
    CAPTION = ParagraphStyle(
        "CAPTION", parent=styles["Normal"],
        fontName="Helvetica", fontSize=9.5, leading=12,
        textColor=colors.HexColor("#555555"),
        spaceBefore=6, spaceAfter=12
    )

    def esc(s: str) -> str:
        # Paragraph expects HTML-ish text; escape basic stuff.
        return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    def nice_time(s):
        # best-effort formatting for your stored iso string
        if not s:
            return "—"
        return s.replace("T", " ")[:19]

    title = (ws.get("title") or "Untitled Lab").strip() or "Untitled Lab"
    updated = nice_time(ws.get("updated_at"))

    story = []

    # Header
    story.append(Paragraph(esc(title), H1))
    story.append(Paragraph(f"<b>Lab #{ws_id}</b> &nbsp;&nbsp;•&nbsp;&nbsp; Updated: {esc(updated)}", META))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#DDDDDD"), spaceBefore=6, spaceAfter=10))

    # Notes
    story.append(Paragraph("Notes / Plaintext", H2))
    notes = (ws.get("notes") or "").strip()
    if notes:
        # Use BODY with line breaks preserved
        story.append(Paragraph(esc(notes).replace("\n", "<br/>"), BODY))
    else:
        story.append(Paragraph("<i>No notes.</i>", META))

    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#EEEEEE"), spaceBefore=2, spaceAfter=10))

    # Ciphertext
    story.append(Paragraph("Ciphertext", H2))
    ctext = (ws.get("cipher_text") or "").strip()
    if ctext:
        # Make ciphertext look like a code block
        story.append(Paragraph(esc(ctext).replace("\n", "<br/>"), CODE))
    else:
        story.append(Paragraph("<i>No ciphertext.</i>", META))

    # Images
    if images:
        story.append(Spacer(1, 8))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#EEEEEE"), spaceBefore=2, spaceAfter=10))
        story.append(Paragraph("Cipher Images", H2))

        # available drawing area
        max_w = doc.width
        max_h = 6.4 * inch  # nice big preview, not too huge

        for idx, im in enumerate(images, start=1):
            label = (im.get("label") or f"Image {idx}").strip() or f"Image {idx}"
            filename = (im.get("filename") or "").strip()
            path = os.path.join(app.config["UPLOAD_FOLDER"], filename)

            if not filename or not os.path.exists(path):
                story.append(Paragraph(f"{idx}. {esc(label)}", BODY))
                story.append(Paragraph("(missing image file)", META))
                story.append(Spacer(1, 8))
                continue

            # Put each image on its own “block” with caption.
            # If you prefer each image on its own PAGE, uncomment the PageBreak below.
            # story.append(PageBreak())

            story.append(Paragraph(f"{idx}. {esc(label)}", BODY))
            story.append(Spacer(1, 6))

            img_flow = RLImage(path)
            # Preserve aspect ratio by constraining to box
            iw, ih = img_flow.imageWidth, img_flow.imageHeight
            scale = min(max_w / float(iw), max_h / float(ih), 1.0)
            img_flow.drawWidth = iw * scale
            img_flow.drawHeight = ih * scale
            img_flow.hAlign = "CENTER"
            story.append(img_flow)

            story.append(Paragraph(esc(filename), CAPTION))

    # Footer with page numbers
    def draw_footer(canv, doc_):
        canv.saveState()
        canv.setFont("Helvetica", 9)
        canv.setFillColor(colors.HexColor("#777777"))

        page = canv.getPageNumber()
        footer_left = f"The Cipher Lab • Lab #{ws_id}"
        footer_right = f"Page {page}"

        y = 0.55 * inch
        canv.drawString(doc_.leftMargin, y, footer_left)

        w = stringWidth(footer_right, "Helvetica", 9)
        canv.drawString(doc_.pagesize[0] - doc_.rightMargin - w, y, footer_right)

        canv.restoreState()

    doc.build(story, onFirstPage=draw_footer, onLaterPages=draw_footer)

    buf.seek(0)
    filename = f"cipherlab_lab_{ws_id}.pdf"
    return send_file(buf, mimetype="application/pdf", as_attachment=True, download_name=filename)


@app.route("/prefs/labs-tour-seen", methods=["POST"])
def prefs_labs_tour_seen():
    user = current_user()
    if not user:
        return jsonify({"ok": False, "error": "login required"}), 401

    conn = get_db()
    conn.execute("UPDATE users SET labs_tour_seen = 1 WHERE id = ?", (user["id"],))
    conn.commit()
    conn.close()

    return jsonify({"ok": True})


# app.py — add this route + template render
@app.route("/faqs")
def faqs_page():
    user = current_user()
    return render_template("faqs.html", user=user, viewer_is_pro=is_pro(user) if user else False)

# app.py
from datetime import datetime

@app.context_processor
def inject_now_year():
    return {"now_year": datetime.utcnow().year}


@app.context_processor
def inject_user_setup_flags():
    """Expose needs_password/needs_username globally so the nav can show a setup pulse."""
    u = current_user()
    if not u:
        return {}

    try:
        conn = get_db()
        row = conn.execute(
            "SELECT needs_password, needs_username FROM users WHERE id=?",
            (u["id"],)
        ).fetchone()
        conn.close()
    except Exception:
        return {}

    needs_password = 0
    needs_username = 0
    try:
        if row:
            needs_password = int(row["needs_password"] or 0)
            needs_username = int(row["needs_username"] or 0)
    except Exception:
        # If row isn't indexable for some reason, fail closed (no pulse)
        needs_password = 0
        needs_username = 0

    return {
        "needs_password": needs_password,
        "needs_username": needs_username,
        "setup_needed_global": bool(needs_password or needs_username),
    }

# --- helpers you should already have ---
# current_user() -> dict or None
# get_db() -> sqlite connection
# ensure your users table has: stripe_customer_id, is_pro, pro_until (optional)

from flask import Flask
from billing import billing

app.register_blueprint(billing)


 


# --- Dedicated cipher pages (SEO + higher intent) ---


@app.route("/tools/caesar")
def tool_caesar():
    user = current_user()
    return render_template(
        "cipher_tool.html",
        user=user,
        preset_cipher="caesar",
        page_title="Caesar Cipher Decoder — The Cipher Lab",
        meta_description="Free Caesar cipher decoder and encoder. Enter text, choose a shift, and convert plaintext ↔ ciphertext instantly.",
        canonical_url=request.base_url,
        page_h1="Caesar Cipher Decoder",
        page_blurb="Encode and decode Caesar ciphers instantly. Set a shift and watch plaintext ↔ ciphertext update live.",
        seo_paragraph="The Caesar cipher shifts each letter by a fixed number of positions in the alphabet. Choose a shift (for example 3), and this tool will encode plaintext into ciphertext or decode ciphertext back to readable text in real time.",

        cipher_family="Substitution",
        cipher_era="Ancient Rome",
        cipher_strength="Very weak",
        cipher_history="Traditionally attributed to Julius Caesar for military messages. It’s the classic “shift” cipher and a common first example in cryptography and puzzle hunts—easy to break today with frequency analysis or brute force.",

        seo_steps=[
            "Pick Encode or Decode.",
            "Enter your text on the left (encode) or right (decode).",
            "Set the shift value (0–25).",
            "Copy the result instantly—no submit button."
        ],
        seo_faq=[
            {"q": "What shift did Caesar actually use?", "a": "The famous historical association is a shift of 3, but in puzzles you’ll see any shift from 0–25."},
            {"q": "How do you break a Caesar cipher?", "a": "Try all 26 shifts (brute force) or use letter frequency—common in English is E, T, A, O."},
            {"q": "Does it keep punctuation and spaces?", "a": "Typically yes—only letters are shifted; other characters are left unchanged."},
        ],

        default_key="7",
        default_keyword="LEMON",
        default_affine_a=5,
        default_affine_b=8,
        default_rail_rails=3,
        default_rail_offset=0,
    )


@app.route("/tools/vigenere")
def tool_vigenere():
    user = current_user()
    return render_template(
        "cipher_tool.html",
        user=user,
        preset_cipher="vigenere",
        page_title="Vigenère Cipher Decoder — The Cipher Lab",
        meta_description="Free Vigenère cipher decoder and encoder. Use a keyword to encrypt or decrypt text instantly.",
        canonical_url=request.base_url,
        page_h1="Vigenère Cipher Decoder",
        page_blurb="Encode and decode Vigenère ciphers with a keyword. Great for classical cipher puzzles and CTFs.",
        seo_paragraph="The Vigenère cipher uses a repeating keyword to apply a different Caesar shift to each letter. Enter your keyword and this tool will encode or decode instantly, which is especially useful when you’re testing multiple keywords while solving puzzles.",

        cipher_family="Polyalphabetic substitution",
        cipher_era="1500s–1800s",
        cipher_strength="Weak (by modern standards)",
        cipher_history="Popularised in Renaissance Europe and long nicknamed “le chiffre indéchiffrable” (“the indecipherable cipher”). It’s stronger than Caesar because the shifts change each letter, but it can be broken with techniques like Kasiski examination and index of coincidence.",

        seo_steps=[
            "Pick Encode or Decode.",
            "Enter text (left for encode, right for decode).",
            "Type a keyword (letters only).",
            "The output updates instantly as you edit."
        ],
        seo_faq=[
            {"q": "Do I repeat the keyword?", "a": "Yes—Vigenère repeats the keyword to match the message length."},
            {"q": "How do you break Vigenère without the key?", "a": "Estimate key length (Kasiski / index of coincidence), then solve each Caesar-like column with frequency analysis."},
            {"q": "Are spaces/punctuation encrypted?", "a": "Most implementations leave non-letters unchanged; the keyword typically advances only on letters."},
        ],

        default_key="7",
        default_keyword="LEMON",
        default_affine_a=5,
        default_affine_b=8,
        default_rail_rails=3,
        default_rail_offset=0,
    )


@app.route("/tools/affine")
def tool_affine():
    user = current_user()
    return render_template(
        "cipher_tool.html",
        user=user,
        preset_cipher="affine",
        page_title="Affine Cipher Decoder — The Cipher Lab",
        meta_description="Free Affine cipher decoder and encoder. Set parameters a and b and convert plaintext ↔ ciphertext instantly.",
        canonical_url=request.base_url,
        page_h1="Affine Cipher Decoder",
        page_blurb="Encode and decode Affine ciphers using a and b parameters. Useful when Caesar isn’t enough.",
        seo_paragraph="The Affine cipher is a substitution cipher defined by two numbers, a and b, applied to letter indices modulo 26. Enter a and b and this tool will encode or decode immediately, making it easy to experiment with parameters and verify solutions.",

        cipher_family="Substitution (mathematical)",
        cipher_era="Classical / early modern",
        cipher_strength="Weak",
        cipher_history="An affine cipher generalises Caesar by multiplying and shifting letter indices: E(x)=ax+b (mod 26). It’s still a monoalphabetic substitution, so frequency analysis applies, but the math angle makes it common in classrooms and puzzle sets.",

        seo_steps=[
            "Pick Encode or Decode.",
            "Enter your text.",
            "Set a and b (mod 26).",
            "If decoding fails, your a likely isn’t invertible mod 26."
        ],
        seo_faq=[
            {"q": "What values of a are valid?", "a": "a must be coprime with 26 (e.g., 1,3,5,7,9,11,15,17,19,21,23,25) so an inverse exists."},
            {"q": "Why does decoding sometimes not work?", "a": "If a shares a factor with 26, it has no modular inverse, so decoding isn’t well-defined."},
            {"q": "Is Affine stronger than Caesar?", "a": "Slightly, but still monoalphabetic—frequency analysis breaks it quickly."},
        ],

        default_key="7",
        default_keyword="LEMON",
        default_affine_a=5,
        default_affine_b=8,
        default_rail_rails=3,
        default_rail_offset=0,
    )


@app.route("/tools/rail-fence")
def tool_rail_fence():
    user = current_user()
    return render_template(
        "cipher_tool.html",
        user=user,
        preset_cipher="railfence",
        page_title="Rail Fence Cipher Decoder — The Cipher Lab",
        meta_description="Free Rail Fence cipher decoder and encoder. Choose the number of rails (and optional offset) and convert text instantly.",
        canonical_url=request.base_url,
        page_h1="Rail Fence Cipher Decoder",
        page_blurb="Encode and decode Rail Fence ciphers with rails and optional offset.",
        seo_paragraph="The Rail Fence cipher writes text in a zig-zag pattern across a chosen number of rails, then reads it row by row. Set the number of rails (and optional offset) and this tool will encode or decode instantly so you can test rail counts quickly.",

        cipher_family="Transposition",
        cipher_era="1800s+ (popular puzzles)",
        cipher_strength="Weak",
        cipher_history="A classic transposition cipher: it scrambles order rather than substituting letters. It’s widely used in puzzle books and beginner CTFs because you can often guess the rail count by trying small values and looking for readable output.",

        seo_steps=[
            "Pick Encode or Decode.",
            "Set the number of rails (try 2–6 first).",
            "Optional: set offset if you suspect a shifted start.",
            "Watch the output; readable text often appears quickly."
        ],
        seo_faq=[
            {"q": "What’s a good first guess for rails?", "a": "Try 2–5. Many puzzle rail fences use small rail counts."},
            {"q": "What does offset do?", "a": "It shifts the starting zig-zag position before placing the first character—useful for variants seen in puzzles."},
            {"q": "How do you break it without rails?", "a": "Brute-force small rail counts and check for crib words/patterns; transposition keeps letter frequencies intact."},
        ],

        default_key="7",
        default_keyword="LEMON",
        default_affine_a=5,
        default_affine_b=8,
        default_rail_rails=3,
        default_rail_offset=0,
    )


@app.route("/tools/columnar")
def tool_columnar():
    user = current_user()
    return render_template(
        "cipher_tool.html",
        user=user,
        preset_cipher="columnar",
        page_title="Columnar Transposition Decoder — The Cipher Lab",
        meta_description="Free columnar transposition encoder and decoder. Enter a key to transpose text and recover plaintext instantly.",
        canonical_url=request.base_url,
        page_h1="Columnar Transposition Decoder",
        page_blurb="Encode and decode columnar transposition with a key. Ideal for many classic puzzle ciphers.",
        seo_paragraph="Columnar transposition rearranges text by writing it into columns and reading columns in an order determined by a key. Enter your key and this tool will encode or decode immediately, which helps when you’re verifying a suspected transposition key.",

        cipher_family="Transposition",
        cipher_era="1800s–WWII era (variants)",
        cipher_strength="Weak–medium (variant dependent)",
        cipher_history="Columnar transposition has been used in many historical systems and countless puzzle variants. The key determines column order; with enough ciphertext, patterns and probable words can help recover the key length and ordering.",

        seo_steps=[
            "Pick Encode or Decode.",
            "Enter a keyword (e.g. ZEBRAS).",
            "The key sets the column order (alphabetical ranking).",
            "If it looks close-but-wrong, you may have padding/spacing differences."
        ],
        seo_faq=[
            {"q": "How is the key applied?", "a": "Typically columns are numbered by sorting the key’s letters; ties are handled by position order. Implementations vary."},
            {"q": "Why do I get slightly different results from other tools?", "a": "Padding rules, tie-breaking, and whether spaces are removed can differ between implementations."},
            {"q": "How do you break columnar transposition?", "a": "Guess key length, use cribs, try common keywords, or use automated scoring/hill-climbing for longer texts."},
        ],

        default_key="ZEBRAS",
        default_keyword="LEMON",
        default_affine_a=5,
        default_affine_b=8,
        default_rail_rails=3,
        default_rail_offset=0,
    )


@app.route("/tools/save_to_lab", methods=["POST"])
def tools_save_to_lab():
    user = current_user()
    if not user:
        return jsonify({
            "ok": False,
            "error": "login required",
            "redirect": url_for("login", next=request.path, reason="pro_analysis")
        }), 401

    data = request.get_json(silent=True) or {}

    title = (data.get("title") or "").strip() or "Untitled Lab"
    notes = data.get("notes") or ""
    cipher_text = data.get("cipher_text") or ""

    # Optional: basic profanity check like your workspace_save()
    if contains_profanity(title) or contains_profanity(notes):
        return jsonify({"ok": False, "error": "inappropriate content"}), 400

    conn = get_db()

    # Enforce free lab limit (same logic as /workspaces/new)
    lab_count = conn.execute(
        "SELECT COUNT(*) AS c FROM workspaces WHERE owner_id=?",
        (user["id"],)
    ).fetchone()["c"] or 0

    if (not is_pro(user)) and lab_count >= FREE_MAX_LABS:
        conn.close()
        return jsonify({
            "ok": False,
            "error": f"Free plan limit: {FREE_MAX_LABS} Labs. Upgrade to Labs Pro for unlimited labs.",
            "upgrade_url": url_for("labs_pro_page")
        }), 402

    now = datetime.utcnow().isoformat()

    cur = conn.cursor()
    cur.execute("""
        INSERT INTO workspaces (owner_id, title, cipher_text, notes, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (user["id"], title, cipher_text, notes, now, now))

    ws_id = cur.lastrowid
    conn.commit()
    conn.close()

    return jsonify({
        "ok": True,
        "ws_id": ws_id,
        "redirect": url_for("workspace_view", ws_id=ws_id)
    })


from datetime import datetime, timedelta
from flask import render_template

@app.route("/admin/labs-analytics")
@admin_required
def admin_labs_analytics():
    user = current_user()
    conn = get_db()

    # ---- KPIs (best-effort: some tables may not exist depending on migrations) ----
    def q1(sql, params=()):
        return conn.execute(sql, params).fetchone()

    def qall(sql, params=()):
        return conn.execute(sql, params).fetchall()

    # Workspaces (Labs)
    total_labs = q1("SELECT COUNT(*) AS c FROM workspaces").fetchone()["c"] if False else q1(
        "SELECT COUNT(*) AS c FROM workspaces"
    )["c"]

    labs_last_7d = q1("""
        SELECT COUNT(*) AS c
        FROM workspaces
        WHERE datetime(updated_at) >= datetime('now','-7 days')
    """)["c"]

    labs_last_30d = q1("""
        SELECT COUNT(*) AS c
        FROM workspaces
        WHERE datetime(updated_at) >= datetime('now','-30 days')
    """)["c"]

    # Unique owners + avg labs per owner
    owners = q1("SELECT COUNT(DISTINCT owner_id) AS c FROM workspaces")["c"] or 0
    avg_labs_per_owner = (total_labs / owners) if owners else 0

    # Tabs (workspace_images)
    try:
        total_tabs = q1("SELECT COUNT(*) AS c FROM workspace_images")["c"]
        avg_tabs_per_lab = (total_tabs / total_labs) if total_labs else 0
    except Exception:
        total_tabs = None
        avg_tabs_per_lab = None

    # Shared labs + collaborators
    try:
        shared_labs = q1("SELECT COUNT(*) AS c FROM workspaces WHERE is_shared=1")["c"]
    except Exception:
        shared_labs = None

    try:
        total_collab_rows = q1("SELECT COUNT(*) AS c FROM workspace_collaborators")["c"]
        distinct_collaborators = q1("SELECT COUNT(DISTINCT user_id) AS c FROM workspace_collaborators")["c"]
    except Exception:
        total_collab_rows = None
        distinct_collaborators = None

    # History snapshots (Pro feature)
    try:
        total_snapshots = q1("SELECT COUNT(*) AS c FROM workspace_history")["c"]
        snapshots_last_30d = q1("""
            SELECT COUNT(*) AS c
            FROM workspace_history
            WHERE datetime(created_at) >= datetime('now','-30 days')
        """)["c"]
    except Exception:
        total_snapshots = None
        snapshots_last_30d = None

    # Pro users
    try:
        pro_users = q1("SELECT COUNT(*) AS c FROM users WHERE is_pro=1")["c"]
        total_users = q1("SELECT COUNT(*) AS c FROM users")["c"]
        pro_rate = (pro_users / total_users) * 100 if total_users else 0
    except Exception:
        pro_users = None
        total_users = None
        pro_rate = None

    # ---- Leaderboards / drilldowns ----
    top_lab_creators = qall("""
        SELECT u.username, u.email, COUNT(*) AS labs
        FROM workspaces w
        JOIN users u ON u.id = w.owner_id
        GROUP BY w.owner_id
        ORDER BY labs DESC
        LIMIT 15
    """)

    most_active_labs = qall("""
        SELECT w.id, w.title, u.username AS owner, w.updated_at
        FROM workspaces w
        JOIN users u ON u.id = w.owner_id
        ORDER BY datetime(w.updated_at) DESC
        LIMIT 20
    """)

    biggest_labs = []
    if total_tabs is not None:
        biggest_labs = qall("""
            SELECT w.id, w.title, u.username AS owner, COUNT(i.id) AS tabs
            FROM workspaces w
            JOIN users u ON u.id = w.owner_id
            LEFT JOIN workspace_images i ON i.workspace_id = w.id
            GROUP BY w.id
            ORDER BY tabs DESC
            LIMIT 20
        """)

    shared_labs_list = []
    if shared_labs is not None:
        shared_labs_list = qall("""
            SELECT w.id, w.title, u.username AS owner, w.updated_at
            FROM workspaces w
            JOIN users u ON u.id = w.owner_id
            WHERE w.is_shared=1
            ORDER BY datetime(w.updated_at) DESC
            LIMIT 20
        """)

    collab_heavy = []
    if total_collab_rows is not None:
        collab_heavy = qall("""
            SELECT w.id, w.title, u.username AS owner, COUNT(wc.id) AS collaborators
            FROM workspaces w
            JOIN users u ON u.id = w.owner_id
            LEFT JOIN workspace_collaborators wc ON wc.workspace_id = w.id
            GROUP BY w.id
            ORDER BY collaborators DESC
            LIMIT 20
        """)

    conn.close()

    return render_template(
        "admin_labs_analytics.html",
        user=user,

        # KPIs
        total_labs=total_labs,
        labs_last_7d=labs_last_7d,
        labs_last_30d=labs_last_30d,
        owners=owners,
        avg_labs_per_owner=avg_labs_per_owner,

        total_tabs=total_tabs,
        avg_tabs_per_lab=avg_tabs_per_lab,

        shared_labs=shared_labs,
        total_collab_rows=total_collab_rows,
        distinct_collaborators=distinct_collaborators,

        total_snapshots=total_snapshots,
        snapshots_last_30d=snapshots_last_30d,

        pro_users=pro_users,
        total_users=total_users,
        pro_rate=pro_rate,

        # Tables
        top_lab_creators=top_lab_creators,
        most_active_labs=most_active_labs,
        biggest_labs=biggest_labs,
        shared_labs_list=shared_labs_list,
        collab_heavy=collab_heavy,
    )

from cipher_tools.pro_analysis import *


import math
import re
from collections import Counter, defaultdict
from flask import jsonify, request, url_for

# English letter frequencies (A–Z) as proportions
_EN_FREQ = {
    "A": 0.08167, "B": 0.01492, "C": 0.02782, "D": 0.04253, "E": 0.12702,
    "F": 0.02228, "G": 0.02015, "H": 0.06094, "I": 0.06966, "J": 0.00153,
    "K": 0.00772, "L": 0.04025, "M": 0.02406, "N": 0.06749, "O": 0.07507,
    "P": 0.01929, "Q": 0.00095, "R": 0.05987, "S": 0.06327, "T": 0.09056,
    "U": 0.02758, "V": 0.00978, "W": 0.02360, "X": 0.00150, "Y": 0.01974, "Z": 0.00074
}
_ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
_VOWELS = set("AEIOUY")

def _safe_top(counter: Counter, n: int):
    return [(k, int(v)) for k, v in counter.most_common(n)]

def _ioc_from_counts(counts: Counter, n: int) -> float:
    if n <= 1:
        return 0.0
    num = sum(c * (c - 1) for c in counts.values())
    den = n * (n - 1)
    return num / den

def _shannon_entropy_from_counts(counts: Counter, n: int) -> float:
    if n <= 0:
        return 0.0
    ent = 0.0
    for c in counts.values():
        p = c / n
        if p > 0:
            ent -= p * math.log2(p)
    return ent

def _chisq_english(letter_counts: Counter, n: int) -> float:
    if n <= 0:
        return 0.0
    chi = 0.0
    for ch in _ALPHA:
        obs = letter_counts.get(ch, 0)
        exp = _EN_FREQ[ch] * n
        if exp > 0:
            chi += ((obs - exp) ** 2) / exp
    return chi

def _autocorr_shifts(alpha_only: str, max_shift: int = 20):
    """
    Returns matches and match-rate for shifts 1..max_shift.
    Useful for Vigenere-ish key length hints (peaks).
    """
    n = len(alpha_only)
    out = []
    if n < 2:
        return out
    for s in range(1, max_shift + 1):
        m = 0
        # compare x[i] to x[i+s]
        for i in range(n - s):
            if alpha_only[i] == alpha_only[i + s]:
                m += 1
        rate = (m / (n - s)) if (n - s) > 0 else 0.0
        out.append({"shift": s, "matches": m, "rate": round(rate, 6)})
    out.sort(key=lambda r: (r["rate"], r["matches"]), reverse=True)
    return out

def _kasiski(alpha_only: str, min_len: int = 3, max_len: int = 5, top_repeat: int = 8):
    """
    Very lightweight Kasiski: repeated ngrams -> distances -> factor counts.
    """
    n = len(alpha_only)
    if n < 20:
        return {
            "repeats": [],
            "distance_gcds": [],
            "factor_counts": []
        }

    repeats = []
    distance_counts = Counter()
    factor_counts = Counter()

    for L in range(min_len, max_len + 1):
        positions = defaultdict(list)
        for i in range(0, n - L + 1):
            ng = alpha_only[i:i+L]
            positions[ng].append(i)

        for ng, pos_list in positions.items():
            if len(pos_list) >= 2:
                # collect distances between consecutive repeats
                dists = []
                for j in range(1, len(pos_list)):
                    d = pos_list[j] - pos_list[j-1]
                    if d > 0:
                        dists.append(d)
                        distance_counts[d] += 1

                        # factors up to 20 (key length candidates)
                        for f in range(2, 21):
                            if d % f == 0:
                                factor_counts[f] += 1

                if dists:
                    repeats.append({
                        "ngram": ng,
                        "len": L,
                        "count": len(pos_list),
                        "distances": dists[:10]
                    })

    repeats.sort(key=lambda r: (r["count"], r["len"]), reverse=True)
    top_repeats = repeats[:top_repeat]

    # crude gcd suggestion: take gcd of the most common distances
    common_dists = [d for d, _c in distance_counts.most_common(10)]
    gcds = []
    for i in range(len(common_dists)):
        for j in range(i+1, len(common_dists)):
            g = math.gcd(common_dists[i], common_dists[j])
            if g >= 2 and g <= 20:
                gcds.append(g)
    gcd_counts = Counter(gcds).most_common(8)

    return {
        "repeats": top_repeats,
        "distance_gcds": [{"gcd": int(g), "count": int(c)} for g, c in gcd_counts],
        "factor_counts": [{"factor": int(f), "count": int(c)} for f, c in factor_counts.most_common(10)],
    }

def _friedman_keylen_estimate(ioc: float, n: int):
    """
    Classic Friedman estimate. Returns None if unstable.
    Uses common constants for English plaintext.
    """
    if n < 40:
        return None
    # Denominator can go near 0 or negative on weird inputs
    denom = ((n - 1) * ioc) - (0.038 * n) + 0.065
    if abs(denom) < 1e-9:
        return None
    k = (0.027 * n) / denom
    if k <= 0 or k > 40:
        return None
    return round(float(k), 2)

def _detect_encodings(raw: str):
    s = raw.strip()
    s_nospace = re.sub(r"\s+", "", s)

    # binary-ish: only 0/1 with spaces/newlines ok
    is_bin = bool(s) and bool(re.fullmatch(r"[01\s]+", s)) and (len(re.sub(r"\s+", "", s)) >= 16)

    # hex-ish: hex chars only (spaces ok)
    is_hex = bool(s) and bool(re.fullmatch(r"[0-9a-fA-F\s]+", s)) and (len(re.sub(r"\s+", "", s)) >= 16)

    # base64-ish: base64 alphabet plus = padding, length multiple of 4 is a good hint
    b64_ok = bool(re.fullmatch(r"[A-Za-z0-9+/=\s]+", s))
    b64_len = len(s_nospace)
    is_b64 = b64_ok and b64_len >= 16 and (b64_len % 4 == 0)

    return {
        "looks_binary": bool(is_bin),
        "looks_hex": bool(is_hex),
        "looks_base64": bool(is_b64),
        "base64_len_mod4": (b64_len % 4) if b64_len else None
    }

def _rank_cipher_types(features: dict):
    """
    Returns a ranked list of (label, score, reasons[]).
    This is heuristic — but it reads 'premium' and is useful.
    """
    ranks = []

    enc = features["encoding_hints"]
    ioc = features["ioc"]
    chi = features["chi_square_english"]
    ent = features["entropy_bits_per_char"]
    n_alpha = features["alpha_len"]
    autocorr = features["autocorr_top"]
    friedman = features["friedman_keylen"]

    def add(name, score, reasons):
        ranks.append({"name": name, "score": int(score), "reasons": reasons})

    # Encoding guesses (strong)
    if enc["looks_base64"]:
        add("Base64", 92, ["Valid Base64 charset", "Length multiple of 4", "High non-letter density expected"])
    if enc["looks_hex"]:
        add("Hex", 90, ["Hex charset only", "Often used to wrap bytes"])
    if enc["looks_binary"]:
        add("Binary", 88, ["Only 0/1 + whitespace"])

    # If mostly letters, do classical heuristics
    if n_alpha >= 30:
        # monoalphabetic-ish: IoC closer to English + chi-square reasonably low
        if ioc >= 0.055:
            score = 70
            reasons = [f"IoC is relatively high ({ioc:.4f}) → monoalphabetic-ish"]
            if chi > 0:
                if chi < 180:
                    score += 18
                    reasons.append(f"Chi-square vs English is low ({chi:.1f}) → distribution matches English-ish")
                else:
                    reasons.append(f"Chi-square vs English is high ({chi:.1f}) → may be substitution/transposition or short sample")
            add("Caesar / Affine / Simple Substitution", score, reasons)

        # polyalphabetic-ish: lower IoC, keylen hints
        if 0.035 <= ioc <= 0.055:
            score = 68
            reasons = [f"IoC is mid/low ({ioc:.4f}) → polyalphabetic or transposition possible"]
            if friedman:
                score += 12
                reasons.append(f"Friedman key length ≈ {friedman}")
            if autocorr:
                top = autocorr[0]
                if top["rate"] >= 0.055:
                    score += 10
                    reasons.append(f"Autocorrelation peak at shift {top['shift']} (rate {top['rate']})")
            add("Vigenère / Polyalphabetic", score, reasons)

        # transposition-ish: IoC can remain high-ish but chi-square can be worse; entropy near English-ish
        if ioc >= 0.05 and chi >= 180:
            add("Transposition (Columnar / Railfence)", 62, [
                f"IoC high-ish ({ioc:.4f}) but chi-square high ({chi:.1f})",
                "Transposition preserves single-letter counts but disrupts digrams"
            ])

        # random-ish / high entropy
        if ent >= 4.4:
            add("Compressed / Random / Modern cipher", 55, [
                f"Entropy is high ({ent:.2f} bits/char)",
                "Classical ciphers usually look less random"
            ])

    # sort and keep top
    ranks.sort(key=lambda r: r["score"], reverse=True)

    # de-dupe by name (encoding guesses might overlap)
    seen = set()
    out = []
    for r in ranks:
        if r["name"] in seen:
            continue
        seen.add(r["name"])
        out.append(r)
    return out[:6]
@app.route("/api/pro-analysis", methods=["POST"])
def api_pro_analysis():
    user = current_user()
    if not user:
        return jsonify({
            "ok": False,
            "error": "login required",
            "redirect": url_for("login", next=request.path, reason="pro_analysis")
        }), 401

    # 🔧 FIX: refresh user from DB so is_pro is accurate
    conn = get_db()
    fresh = conn.execute(
        "SELECT * FROM users WHERE id=?",
        (user["id"],)
    ).fetchone()
    conn.close()

    if not fresh:
        return jsonify({
            "ok": False,
            "error": "user not found"
        }), 401

    if not is_pro(fresh):
        return jsonify({
            "ok": False,
            "error": "Pro required to use Pro Analysis.",
            "upgrade_url": url_for("labs_pro_page"),
        }), 402

    data = request.get_json(silent=True) or {}
    raw = (data.get("text") or "").strip()

    # perf cap
    if len(raw) > 50000:
        raw = raw[:50000]

    total_len = len(raw)
    alpha_only = re.findall(r"[A-Z]", raw.upper())
    alpha_str = "".join(alpha_only)
    alpha_len = len(alpha_str)

    digits = sum(ch.isdigit() for ch in raw)
    whitespace = sum(ch.isspace() for ch in raw)
    punctuation = total_len - alpha_len - digits - whitespace

    letter_counts = Counter(alpha_str)
    ioc = _ioc_from_counts(letter_counts, alpha_len)
    chi = _chisq_english(letter_counts, alpha_len)

    raw_nowhite = re.sub(r"\s+", "", raw)
    sym_counts = Counter(raw_nowhite) if raw_nowhite else Counter()
    ent = _shannon_entropy_from_counts(sym_counts, sum(sym_counts.values()))

    vowels = sum(1 for ch in alpha_str if ch in _VOWELS)
    vowel_ratio = (vowels / alpha_len) if alpha_len else 0.0

    uni = Counter(alpha_str)
    bi = Counter(alpha_str[i:i+2] for i in range(max(0, alpha_len - 1)))
    tri = Counter(alpha_str[i:i+3] for i in range(max(0, alpha_len - 2)))

    repeated_bi = sum(1 for _k, v in bi.items() if v >= 2)
    repeated_tri = sum(1 for _k, v in tri.items() if v >= 2)

    encoding_hints = _detect_encodings(raw)

    friedman = _friedman_keylen_estimate(ioc, alpha_len)
    autocorr = _autocorr_shifts(alpha_str, max_shift=20)
    autocorr_top = autocorr[:6]

    kasiski = _kasiski(alpha_str, min_len=3, max_len=5, top_repeat=10)

    features = {
        "encoding_hints": encoding_hints,
        "ioc": float(ioc),
        "chi_square_english": float(chi),
        "entropy_bits_per_char": float(ent),
        "alpha_len": int(alpha_len),
        "friedman_keylen": friedman,
        "autocorr_top": autocorr_top,
    }
    ranking = _rank_cipher_types(features)

    steps = []
    if encoding_hints["looks_base64"]:
        steps.append("Try Base64 decode first.")
    if encoding_hints["looks_hex"]:
        steps.append("Try Hex decode.")
    if encoding_hints["looks_binary"]:
        steps.append("Try Binary decode.")
    if friedman:
        steps.append(f"Try Vigenère with key length around ~{friedman}.")
    if kasiski.get("factor_counts"):
        top_factor = kasiski["factor_counts"][0]["factor"]
        steps.append(f"Kasiski suggests factors like {top_factor}.")
    if ioc >= 0.055 and chi < 180:
        steps.append("Try Caesar/Affine first.")
    if ioc >= 0.05 and chi >= 180:
        steps.append("Try transposition ciphers.")

    return jsonify({
        "ok": True,
        "length": total_len,
        "alpha_len": alpha_len,
        "digit_len": digits,
        "whitespace_len": whitespace,
        "punct_len": punctuation,
        "unique_symbols": len(sym_counts),
        "ioc": round(float(ioc), 6),
        "chi_square_english": round(float(chi), 3),
        "entropy_bits_per_char": round(float(ent), 3),
        "vowel_ratio": round(float(vowel_ratio), 4),
        "encoding_hints": encoding_hints,
        "friedman_keylen": friedman,
        "autocorr_top": autocorr_top,
        "kasiski": kasiski,
        "repeated_bigrams": int(repeated_bi),
        "repeated_trigrams": int(repeated_tri),
        "top_letters": _safe_top(uni, 26),
        "top_bigrams": _safe_top(bi, 20),
        "top_trigrams": _safe_top(tri, 20),
        "ranking": ranking,
        "next_steps": steps[:8],
    })

# ------------------- Run -------------------


# ======================================================
# Currency preference (Hybrid Pricing)
# ======================================================
@app.route("/set-currency", methods=["POST"])
def set_currency_route():
    code = request.form.get("currency", "").upper().strip()
    nxt = (request.form.get("next") or request.referrer or url_for("labs_pro_page"))
    set_currency(code)
    return redirect(nxt)

@app.route("/set-currency/<code>")
def set_currency_route_get(code):
    nxt = (request.args.get("next") or request.referrer or url_for("labs_pro_page"))
    set_currency((code or "").upper().strip())
    return redirect(nxt)
print("GBP price:", os.environ.get("STRIPE_PRICE_PRO_GBP"))
print("EUR price:", os.environ.get("STRIPE_PRICE_PRO_EUR"))
print("USD price:", os.environ.get("STRIPE_PRICE_PRO_USD"))
print("old price:", os.environ.get("STRIPE_PRICE_ID_PRO_MONTHLY"))



from flask import Response

DOMAIN = "https://thecipherlab.org"

from flask import send_from_directory

@app.route("/robots.txt")
def robots_txt():
    return send_from_directory(app.static_folder, "robots.txt", mimetype="text/plain")


from flask import send_from_directory

@app.route("/sitemap.xml")
def sitemap_xml():
    return send_from_directory(
        app.static_folder,
        "sitemap.xml",
        mimetype="application/xml"
    )

# ------------------- About Page -------------------
@app.route("/about", methods=["GET"])
def about_page():
    return render_template("about.html", user=current_user())

app.add_url_rule("/about", endpoint="about", view_func=about_page)


from flask import abort, redirect, request, url_for, render_template

# One place to define your cipher pages (SEO content + links)
CIPHER_INFO = {

  # ============================================================
  # CAESAR
  # ============================================================
  "caesar": {
    "cipher_name": "Caesar Cipher",
    "page_title": "Caesar Cipher — Complete Guide, Examples, and How to Break It | The Cipher Lab",
    "meta_description": (
      "The most detailed Caesar cipher guide online: what it is, how it works, how to encode/decode, "
      "frequency analysis clues, brute-force cracking, common mistakes, variants like ROT13, and practice prompts."
    ),
    "page_blurb": "A classic substitution cipher that shifts letters by a fixed amount.",

    "cipher_family": "Substitution",
    "cipher_era": "Ancient Rome",
    "cipher_strength": "Very weak",

    "cipher_history": (
      "The Caesar cipher is one of the oldest and most famous encryption methods. It’s traditionally attributed "
      "to Julius Caesar, who reportedly used a shift of three for military correspondence. Historically, its value "
      "was practical: it prevented a casual reader from instantly understanding a message. Today, it is mainly used "
      "for learning, puzzle hunts, escape rooms, and as a building block for understanding stronger substitution systems.\n\n"
      "Modern cryptography considers Caesar completely insecure because the keyspace is tiny (26 possibilities) and "
      "because statistical fingerprints of the language survive encryption. Still, Caesar is *the* perfect cipher to "
      "learn first because it teaches: modular arithmetic, alphabet indexing, and how cryptanalysis (breaking ciphers) "
      "often starts with patterns and frequency."
    ),

    "what_it_is": (
      "The Caesar cipher is a monoalphabetic substitution cipher. Each plaintext letter is replaced with a ciphertext "
      "letter obtained by shifting a fixed number of positions through the alphabet. The shift is the key. "
      "Because the same substitution is applied everywhere, Caesar preserves the underlying structure of the language: "
      "common letters remain common, digrams remain relatively common, and the message still ‘looks like’ English—just shifted."
    ),

    "how_it_works": (
      "Pick an integer shift k from 0 to 25. Convert each letter into an index A=0, B=1, …, Z=25. "
      "To encode: add k (mod 26). To decode: subtract k (mod 26). Wrap-around happens automatically via mod 26: "
      "if shifting past Z, you continue from A.\n\n"
      "Most implementations leave punctuation, spaces, and digits unchanged, and only transform alphabetic characters. "
      "Some variants also shift lowercase separately (preserving case), while others normalize everything to uppercase."
    ),

    "core_rules": [
      "Only alphabetic letters are shifted; punctuation/spaces are usually unchanged.",
      "Wrap-around: Z shifted by +1 becomes A.",
      "Shift 0 is the identity (no change).",
      "If preserving case, lowercase stays lowercase and uppercase stays uppercase.",
      "If removing spaces/punctuation, ciphertext becomes a continuous block (common in puzzle variants).",
    ],

    "worked_example": (
      "Example 1 (classic):\n"
      "Plaintext:  ATTACK AT DAWN\n"
      "Shift:      3\n"
      "Ciphertext: DWWDFN DW GDZQ\n\n"
      "Example 2 (wrap-around):\n"
      "Plaintext:  XYZ\n"
      "Shift:      4\n"
      "Ciphertext: BCD"
    ),

    "encode_steps": [
      "Decide whether you’re preserving punctuation/spaces and case.",
      "Choose a shift k (0–25).",
      "For each letter: map A=0..Z=25, compute (index + k) mod 26, map back to a letter.",
      "Leave non-letters unchanged (typical behavior).",
      "Double-check wrap-around: near Z you should cycle back to A."
    ],

    "encoding_notes": (
      "If you’re debugging an implementation: test simple cases first like A→D at shift 3, "
      "and wrap-around cases like Z→C at shift 3. Most Caesar bugs are off-by-one indexing or wrap-around mistakes."
    ),

    "break_overview": (
      "Caesar is one of the easiest ciphers to break because the keyspace is tiny: only 26 shifts exist. "
      "A brute-force attack tries all shifts and picks the result that looks most like natural language. "
      "Even faster, frequency analysis often reveals the shift immediately by comparing the most common ciphertext letter "
      "to the most common English letters (E, T, A, O, I, N).\n\n"
      "Practical note: for short ciphertexts (like < 20 letters), brute force is more reliable than frequency guesses, "
      "because short samples can have misleading statistics."
    ),

    "break_steps": [
      "Method A — brute force (guaranteed): try all 26 shifts and inspect outputs.",
      "Method B — frequency shortcut: identify the most frequent ciphertext letter and assume it maps to E (or T).",
      "Method C — scoring: rank each brute-force output by English-likeness (dictionary hits, common bigrams, vowel ratio).",
      "Method D — crib-based: if you suspect a word (e.g., THE), try shifts that produce it and verify surrounding text."
    ],

    "frequency_summary": (
      "Caesar preserves letter frequency exactly—only shifted. This means a Caesar ciphertext has nearly the same profile "
      "as English, just rotated. A bar chart of letters still has a few dominant peaks; it does *not* look flat/random.\n\n"
      "Key signals:\n"
      "• Index of Coincidence (IoC) stays close to English (~0.066).\n"
      "• Common digrams (TH, HE, IN) remain common, just shifted.\n"
      "• The most frequent ciphertext letter often corresponds to E (but not always for short text)."
    ),

    "freq_hints": [
      "IoC is close to English; not close to random.",
      "One or two letters dominate frequency (shifted versions of E/T/A/O).",
      "Bigram frequency still has strong peaks (shifted TH/HE/IN patterns).",
      "Brute force outputs will ‘snap’ into readable English for the correct shift.",
    ],

    "freq_example": (
      "Suppose ciphertext letter frequency shows 'K' as most common.\n"
      "If plaintext most common letter is assumed 'E':\n"
      "Shift = (K - E) = (10 - 4) = 6.\n"
      "Try decoding with shift 6 and verify if common words appear."
    ),

    "pitfalls": [
      "Assuming Caesar always uses shift 3 (puzzles often vary).",
      "Forgetting wrap-around for letters near Z.",
      "Shifting punctuation/digits when you didn’t intend to (or not shifting them when a variant expects it).",
      "Not preserving case consistently (encode preserves case, decode doesn’t, etc.).",
      "Using frequency analysis on very short ciphertexts (statistics can lie).",
    ],

    "variants": [
      "ROT13: shift fixed at 13 (self-inverse, encode=decode).",
      "Shift with a custom alphabet: e.g., keyword alphabet or shuffled alphabet (becomes general substitution).",
      "Caesar on ASCII / printable characters (shifts beyond letters).",
      "Two-track Caesar: different shifts for vowels vs consonants (rare puzzle variant).",
    ],

    "practice_blurb": (
      "Best way to internalize Caesar: do a few by hand, then practice breaking unknown shifts using brute force. "
      "Try short messages (harder) and longer paragraphs (easier)."
    ),

    "practice_prompts": [
      "Encode: MEET ME AT MIDNIGHT with shift 5.",
      "Decode: YMJ VZNHP GWTBS KTC OZRUJI TAJW YMJ QFED ITL (hint: classic pangram).",
      "You find ciphertext: QEB NRFZH YOLTK CLU GRJMP LSBO QEB IXWV ALD. Identify the shift.",
      "Write a script that tries all shifts and ranks by dictionary hits.",
    ],

    "faq": [
      {"q": "How many possible keys does the Caesar cipher have?",
       "a": "Only 26 (shifts 0–25). That’s why brute forcing is instant."},
      {"q": "How do I know if my Caesar implementation is correct?",
       "a": "Test known examples: ATTACKATDAWN with shift 3 → DWWDFNDWGDZQ, and wrap-around like XYZ with shift 4 → BCD."},
      {"q": "Does Caesar preserve spaces and punctuation?",
       "a": "Most tools do (they only shift letters). Some puzzle variants remove spaces/punctuation first."},
      {"q": "Can frequency analysis always break Caesar?",
       "a": "For long enough text, usually yes. For very short text, brute force is safer."},
      {"q": "Is Caesar used in real security?",
       "a": "No. It’s educational and recreational only."},
    ],

    "related_ciphers": [
      {"name": "Affine Cipher", "url": "/ciphers/affine"},
      {"name": "Vigenère Cipher", "url": "/ciphers/vigenere"},
      {"name": "Substitution Cipher", "url": "/ciphers/substitution"},
    ],

    "try_encode_url": "/tools?cipher=caesar",
    "try_break_url": "/breaker?cipher=caesar",
    "tools_url": "/tools",
  },


  # ============================================================
  # VIGENERE
  # ============================================================
  "vigenere": {
    "cipher_name": "Vigenère Cipher",
    "page_title": "Vigenère Cipher — Full Guide, Examples, and How to Break It | The Cipher Lab",
    "meta_description": (
      "The ultimate Vigenère cipher guide: how it works, encoding/decoding with keywords, worked examples, "
      "frequency analysis, index of coincidence, Kasiski examination, column attacks, and practical breaking workflow."
    ),
    "page_blurb": "A polyalphabetic substitution cipher that uses a repeating keyword to change the shift per letter.",

    "cipher_family": "Polyalphabetic substitution",
    "cipher_era": "1500s–1800s (popularized in Renaissance Europe)",
    "cipher_strength": "Weak (by modern standards)",

    "cipher_history": (
      "The Vigenère cipher is a classical cipher designed to defeat simple frequency analysis. Instead of using one fixed "
      "substitution alphabet (like Caesar), it uses many—changing the Caesar shift with each character based on a keyword.\n\n"
      "It was historically considered strong enough to earn the nickname “le chiffre indéchiffrable” (“the indecipherable cipher”). "
      "However, it is breakable with classical methods once you have enough ciphertext. Key breakthroughs include the Kasiski examination "
      "and the index of coincidence, which let an attacker estimate the key length and then reduce the problem to multiple Caesar ciphers."
    ),

    "what_it_is": (
      "Vigenère is a repeating-key substitution cipher. The key is a word or phrase. Each key letter determines a Caesar shift. "
      "As the key repeats, each plaintext letter is encrypted using the shift from the corresponding key position."
    ),

    "how_it_works": (
      "Write the keyword repeatedly under the plaintext. Convert letters to indices (A=0..Z=25). "
      "To encode: C[i] = (P[i] + K[i]) mod 26. To decode: P[i] = (C[i] - K[i]) mod 26.\n\n"
      "Many implementations advance the keyword only when a plaintext/ciphertext letter is processed (skipping spaces/punctuation). "
      "This matters a lot when you’re trying to break a real puzzle—keyword alignment changes the result."
    ),

    "core_rules": [
      "Keyword letters map to shifts (A=0, B=1, …, Z=25).",
      "Keyword repeats to match message length (unless using a non-repeating variant).",
      "Non-letters may be left unchanged and may or may not advance the key depending on implementation.",
      "Case handling varies (some tools preserve case, others normalize).",
      "If the key is length 1, Vigenère reduces to Caesar.",
    ],

    "worked_example": (
      "Plaintext:  ATTACKATDAWN\n"
      "Keyword:    LEMONLEMONLE\n"
      "Indices:    L=11 E=4 M=12 O=14 N=13 ...\n"
      "Ciphertext: LXFOPVEFRNHR\n\n"
      "One character shown:\n"
      "A(0) + L(11) = 11 → L\n"
      "T(19) + E(4) = 23 → X"
    ),

    "encode_steps": [
      "Choose a keyword (letters only is safest).",
      "Normalize text and key consistently (uppercase/lowercase).",
      "Repeat the keyword to align with the message’s letters.",
      "For each letter, apply the key letter’s Caesar shift.",
      "Keep punctuation/spaces unchanged unless using a stripped variant."
    ],

    "encoding_notes": (
      "Security depends heavily on key length and repetition. Short repeating keys create patterns that attackers exploit. "
      "If you’re solving puzzles, short keys are *more common* than long random keys."
    ),

    "break_overview": (
      "Breaking Vigenère typically follows a structured workflow:\n"
      "1) Estimate the key length.\n"
      "2) Split the ciphertext into key-length columns.\n"
      "3) Solve each column as a Caesar cipher.\n"
      "4) Rebuild the keyword and decrypt.\n\n"
      "Two classic tools are Kasiski examination (find repeated chunks and factor spacings) and the index of coincidence (measure how English-like each column is)."
    ),

    "break_steps": [
      "Look for repeated sequences (3–5 letters) and record distances between repeats (Kasiski).",
      "Compute IoC for candidate key lengths and prefer those whose column IoCs look English-like.",
      "For each key position: treat letters at i, i+L, i+2L… as a Caesar cipher and solve via frequency scoring.",
      "Combine the best shifts to produce the keyword, then decrypt and sanity-check.",
      "If results are close-but-wrong: try nearby key lengths, handle punctuation alignment differences, or test alternate scoring.",
    ],

    "frequency_summary": (
      "Vigenère ‘smears’ frequency across multiple alphabets. Overall ciphertext frequency looks flatter than Caesar, "
      "but not fully random unless the key is long and non-repeating.\n\n"
      "The breakthrough is column analysis:\n"
      "If the key length is L, then every Lth letter was encrypted with the same shift. Each column is a Caesar cipher, "
      "so each column’s letter frequency resembles shifted English. This is why IoC and frequency analysis still work—just after splitting."
    ),

    "freq_hints": [
      "Overall frequency is flatter than Caesar, but still not random for short keys.",
      "Repeated trigrams/tetragrams often reappear because the same key alignment repeats.",
      "IoC for the full ciphertext is between English and random; IoC per correct column is close to English.",
      "If you guess the right key length, column frequency peaks become obvious and Caesar scoring works well.",
    ],

    "freq_example": (
      "If you test key length L=5:\n"
      "Split ciphertext into 5 columns by position mod 5.\n"
      "Compute IoC for each column. If average IoC is close to English (~0.066), L is plausible.\n"
      "Then solve each column as Caesar by testing shifts that maximize English frequency similarity."
    ),

    "pitfalls": [
      "Key alignment mismatch: does the key advance over punctuation/spaces or only over letters?",
      "Using too small a ciphertext sample: short text makes key-length estimation noisy.",
      "Assuming the key is a dictionary word (often yes in puzzles, not always).",
      "Forgetting that key length candidates can be multiples of the true length (e.g., 10 when true length is 5).",
      "Over-trusting a single technique—best results come from combining Kasiski + IoC + scoring.",
    ],

    "variants": [
      "Autokey Vigenère (key is seeded then continues with plaintext).",
      "Beaufort cipher (a related polyalphabetic cipher with different arithmetic).",
      "Gronsfeld cipher (numeric key, effectively Vigenère with digits).",
      "Running-key cipher (key is a long text like a book; much harder if truly non-repeating).",
    ],

    "practice_blurb": (
      "Practice breaking by starting with known small key lengths (3–6), then increase difficulty by hiding punctuation handling "
      "and using longer ciphertexts."
    ),

    "practice_prompts": [
      "Encrypt a paragraph with keyword LEMON and try to recover the key from ciphertext only.",
      "Take a Vigenère ciphertext and compute IoC for key lengths 1–12; pick the top candidates.",
      "Try Kasiski: find repeated 3–5 letter sequences and factor their spacing distances.",
      "Break Vigenère where key advances only on letters (ignore punctuation).",
    ],

    "faq": [
      {"q": "Why does Vigenère defeat simple frequency analysis?",
       "a": "Because the same plaintext letter can encrypt to different ciphertext letters depending on the keyword position, flattening overall frequency."},
      {"q": "How do I estimate the key length?",
       "a": "Use Kasiski examination (repeat distances) and/or index of coincidence scanning across candidate lengths."},
      {"q": "What if my decrypted text is almost readable but slightly wrong?",
       "a": "You may have the wrong key length (often a multiple), wrong punctuation/key-advance behavior, or one column shift mis-guessed."},
      {"q": "Does Vigenère encrypt spaces?",
       "a": "Usually no. Many implementations leave spaces/punctuation unchanged and do not advance the key for them—but some variants do."},
      {"q": "Is Vigenère secure today?",
       "a": "No. It’s breakable with classical methods given enough ciphertext, and it’s not used for real security."},
    ],

    "related_ciphers": [
      {"name": "Caesar Cipher", "url": "/ciphers/caesar"},
      {"name": "Affine Cipher", "url": "/ciphers/affine"},
      {"name": "Substitution Cipher", "url": "/ciphers/substitution"},
      {"name": "Columnar Transposition", "url": "/ciphers/columnar"},
    ],

    "try_encode_url": "/tools?cipher=vigenere",
    "try_break_url": "/breaker?cipher=vigenere",
    "tools_url": "/tools",
  },


  # ============================================================
  # AFFINE
  # ============================================================
  "affine": {
    "cipher_name": "Affine Cipher",
    "page_title": "Affine Cipher — Full Guide, Examples, and How to Break It | The Cipher Lab",
    "meta_description": (
      "Deep dive into the Affine cipher: how it works, valid keys, modular inverses, encoding/decoding, "
      "frequency analysis, and cracking methods."
    ),
    "page_blurb": "A mathematical substitution cipher defined by two numbers a and b (mod 26).",

    "cipher_family": "Substitution (mathematical)",
    "cipher_era": "Classical / early modern (education + puzzles)",
    "cipher_strength": "Weak",

    "cipher_history": (
      "The affine cipher generalizes Caesar by adding a multiplication step. Instead of shifting letters by a fixed amount, "
      "it multiplies the letter index by a and then adds b, all modulo 26. This creates a larger keyspace than Caesar, but "
      "it remains monoalphabetic substitution, so classical frequency analysis still breaks it quickly."
    ),

    "what_it_is": (
      "Affine is a monoalphabetic substitution cipher defined by a pair (a, b). Each plaintext letter x (0–25) maps to "
      "E(x) = (a*x + b) mod 26. Decoding requires the modular inverse of a modulo 26."
    ),

    "how_it_works": (
      "Convert letters to numbers A=0..Z=25. Choose parameters a and b. Compute ciphertext index as (a*x + b) mod 26. "
      "To decode, compute x = a^{-1} * (y - b) mod 26, where a^{-1} is the modular inverse of a modulo 26."
    ),

    "core_rules": [
      "a must be coprime with 26 (otherwise no inverse exists and decoding is impossible).",
      "Valid a values mod 26 are: 1,3,5,7,9,11,15,17,19,21,23,25.",
      "b can be any integer 0–25.",
      "Still monoalphabetic: one plaintext letter always maps to the same ciphertext letter for a given key."
    ],

    "worked_example": (
      "Let a=5, b=8.\n"
      "Plaintext:  AFFINE\n"
      "Ciphertext: IHHWVC\n\n"
      "Because: E(A=0) = (5*0+8)=8 → I\n"
      "E(F=5) = (5*5+8)=33 mod 26=7 → H"
    ),

    "encode_steps": [
      "Choose a and b (a must be coprime with 26).",
      "Map letters A=0..Z=25.",
      "Compute (a*x + b) mod 26 for each letter.",
      "Map result back to letters."
    ],

    "encoding_notes": (
      "If decoding fails, the most common cause is choosing an invalid a (not coprime with 26)."
    ),

    "break_overview": (
      "Affine is still a monoalphabetic substitution, so it is breakable via frequency analysis. "
      "Additionally, the keyspace is small enough to brute force: there are 12 valid a values and 26 b values, "
      "so only 312 possible keys."
    ),

    "break_steps": [
      "Brute force all valid (a,b) pairs (312 keys).",
      "Score outputs using English-likeness (dictionary hits, common words).",
      "Frequency analysis shortcut: map the most common ciphertext letter to E (and second-most to T) to solve for a and b.",
      "If you have a known plaintext fragment (crib), solve directly using two letter mappings."
    ],

    "frequency_summary": (
      "Affine preserves frequency distribution like Caesar because it is still monoalphabetic substitution. "
      "So ciphertext has strong peaks and IoC close to English. The difference is that the substitution is not a simple shift; "
      "it’s a permutation defined by the linear function."
    ),

    "freq_hints": [
      "IoC is close to English (~0.066).",
      "Single-letter frequencies remain strongly peaked.",
      "Brute force reveals readable output very quickly because the keyspace is tiny."
    ],

    "pitfalls": [
      "Using an invalid a (no modular inverse).",
      "Mixing up encode vs decode formula.",
      "Forgetting mod 26 wrap-around.",
      "Inconsistent handling of punctuation/case."
    ],

    "variants": [
      "Affine over different alphabets (e.g., including digits).",
      "Affine on ASCII ranges (rare).",
      "Multi-alphabet affine (becomes polyalphabetic, not standard)."
    ],

    "practice_blurb": "Try brute forcing Affine keys and compare scoring methods (word hits vs bigram scoring).",

    "practice_prompts": [
      "Encode HELLOWORLD with a=7, b=3.",
      "Given ciphertext and knowing it’s Affine, brute force all 312 keys and pick the best output.",
      "Try solving for a and b using assumptions about most common letters."
    ],

    "faq": [
      {"q": "Why must a be coprime with 26?",
       "a": "Because decoding needs a modular inverse of a modulo 26, which exists only if gcd(a,26)=1."},
      {"q": "Is Affine stronger than Caesar?",
       "a": "Slightly (bigger keyspace), but still monoalphabetic and easy to break."},
      {"q": "How many Affine keys are there?",
       "a": "312 total (12 valid a values × 26 b values)."},
    ],

    "related_ciphers": [
      {"name": "Caesar Cipher", "url": "/ciphers/caesar"},
      {"name": "Vigenère Cipher", "url": "/ciphers/vigenere"},
      {"name": "Substitution Cipher", "url": "/ciphers/substitution"},
    ],

    "try_encode_url": "/tools?cipher=affine",
    "try_break_url": "/breaker?cipher=affine",
    "tools_url": "/tools",
  },
    "substitution": {
    "cipher_name": "Substitution Cipher",
    "page_title": "Substitution Cipher — Complete Guide, Examples, and How to Break It | The Cipher Lab",
    "meta_description": (
      "A deep, practical guide to monoalphabetic substitution: what it is, how it works, how to encode/decode, "
      "how to break it with frequency + word patterns, common traps, and real puzzle workflows."
    ),
    "page_blurb": "A monoalphabetic cipher that swaps each letter for a different letter using a fixed mapping.",

    "cipher_family": "Substitution",
    "cipher_era": "Classical (popular in puzzles & historical variants)",
    "cipher_strength": "Weak (breakable with statistics + patterns)",

    "cipher_history": (
      "A substitution cipher is the natural “next step” after Caesar: instead of rotating the alphabet, you permute it. "
      "It shows up everywhere—historical ciphers, newspaper cryptograms, puzzle hunts, escape rooms—and is the backbone of "
      "many beginner cryptanalysis exercises.\n\n"
      "Its core weakness is that the substitution is consistent across the entire message. That consistency preserves the "
      "statistical fingerprint of the underlying language (letter frequencies, common digrams, repeated word shapes). "
      "Once you lock a few letters, the rest often collapses quickly."
    ),

    "what_it_is": (
      "A monoalphabetic substitution cipher replaces each plaintext letter with a ciphertext letter using one fixed "
      "one-to-one mapping (a permutation of the alphabet). If plaintext has E as the most common letter, ciphertext will also "
      "have one dominant most-common letter—just relabeled."
    ),

    "how_it_works": (
      "Choose a key alphabet: a shuffled version of A–Z (often built from a keyword, then the remaining letters). "
      "To encode, replace each plaintext letter with its mapped ciphertext letter. "
      "To decode, invert the mapping.\n\n"
      "Most puzzle implementations keep spaces/punctuation unchanged, which leaks word lengths and repeated patterns—"
      "making the cipher much easier to solve."
    ),

    "core_rules": [
      "One fixed mapping for the entire message (monoalphabetic).",
      "Mapping must be one-to-one (no two plaintext letters map to the same ciphertext letter).",
      "Spaces/punctuation are usually preserved (unless the variant strips them).",
      "Case may be preserved or normalized; tools should be consistent.",
      "If a keyword is used, duplicates are removed before building the keyed alphabet.",
    ],

    "worked_example": (
      "Example (illustrative mapping):\n"
      "Plain:  ABCDEFGHIJKLMNOPQRSTUVWXYZ\n"
      "Cipher: QWERTYUIOPASDFGHJKLZXCVBNM\n\n"
      "Plaintext:  HELLO WORLD\n"
      "Ciphertext: ITSSG VGKSR"
    ),

    "encode_steps": [
      "Pick a substitution key (either a random shuffled alphabet or a keyword-based alphabet).",
      "Write the plain alphabet and cipher alphabet aligned.",
      "Replace each plaintext letter with its partner from the cipher alphabet.",
      "Keep punctuation/spaces unchanged unless using a stripped variant.",
      "To decode, reverse the mapping (cipher → plain).",
    ],

    "encoding_notes": (
      "If you’re building a keyword alphabet: write the keyword (remove duplicates), then append the remaining letters "
      "A–Z that aren’t already used. Use that as your cipher alphabet."
    ),

    "break_overview": (
      "Breaking substitution is about combining three signals:\n"
      "1) **Frequency** (single letters + bigrams/trigrams),\n"
      "2) **word shapes** (pattern constraints like _H_ = THE), and\n"
      "3) **confirmation loops** (every solved letter makes the next guess easier).\n\n"
      "For typical puzzle texts, you rarely need “heavy” automation. A good workflow is: find THE/AND/OF/TO, lock letters, "
      "then iterate using common word fragments and digrams."
    ),

    "break_steps": [
      "Run frequency on ciphertext: guess likely E/T/A/O/I/N candidates.",
      "Use 1–3 letter words: A, I, AN, IN, OF, TO, THE, AND.",
      "Use word pattern constraints: repeated letters, apostrophes, common endings (-ING, -ED).",
      "Lock letters only when multiple clues agree; keep a pencil/temporary mapping for uncertain guesses.",
      "Iterate: each confirmed letter unlocks new readable fragments → confirm more letters.",
    ],

    "frequency_summary": (
      "Substitution preserves the **shape** of English frequency—just re-labels the peaks. "
      "So you’ll still see a small set of very common letters, a mid-tier, and many rare letters.\n\n"
      "Bigram/trigram statistics also remain English-like in structure (common pairs/triples still dominate), "
      "but with letters renamed."
    ),

    "freq_hints": [
      "IoC is close to English (not close to random).",
      "One ciphertext letter dominates (likely a relabeled E/T).",
      "Common double letters exist (LL, EE, SS, OO → relabeled).",
      "If spaces are preserved, common word lengths (3 for THE/AND) show up often.",
    ],

    "freq_example": (
      "If the most common ciphertext letter is 'X', it might be plaintext 'E' or 'T'.\n"
      "Try mapping X→E first, then look for patterns that could form THE/AND.\n"
      "If you see a repeated 3-letter word like 'XQX', it might be 'EVE', 'DAD', etc.—use context."
    ),

    "pitfalls": [
      "Over-committing to single-letter frequency on short ciphertexts.",
      "Forgetting that the most common letter might be T (not always E), especially in short texts.",
      "Ignoring spaces/punctuation leaks (they are huge clues).",
      "Treating guesses as facts—keep a tentative mapping until confirmed.",
      "Not using digrams/trigrams; they are often stronger than monograms.",
    ],

    "variants": [
      "Keyword substitution alphabet (common in puzzles).",
      "Homophonic substitution (letters map to multiple symbols; harder).",
      "Substitution with removed spaces/punctuation (harder but still solvable).",
      "Aristocrat/Patristocrat newspaper cryptogram styles.",
    ],

    "practice_blurb": (
      "Start with a ciphertext that keeps spaces and punctuation. Solve THE/AND first, then push outward. "
      "Once you can solve those reliably, try one where spaces are removed."
    ),

    "practice_prompts": [
      "Create a keyword alphabet from 'MONARCHY' and encode a paragraph.",
      "Solve a cryptogram where you know it contains the word 'THE' at least twice.",
      "Solve a substitution where spaces are removed; look for repeated trigrams.",
      "Try doing the first 6–10 letter mappings by hand before using tools.",
    ],

    "faq": [
      {"q": "Is a substitution cipher just Caesar with a bigger key?",
       "a": "Conceptually yes: Caesar is a special case where the key is a rotation. General substitution allows any permutation."},
      {"q": "What’s the fastest way to start breaking one?",
       "a": "Look for THE/AND/OF/TO using word shapes + frequency, then lock letters and iterate."},
      {"q": "Why does it still look “English-like” after encryption?",
       "a": "Because letter frequency and common patterns survive—only the labels change."},
    ],

    "related_ciphers": [
      {"name": "Caesar Cipher", "url": "/ciphers/caesar"},
      {"name": "Affine Cipher", "url": "/ciphers/affine"},
      {"name": "Vigenère Cipher", "url": "/ciphers/vigenere"},
    ],

    "try_encode_url": "/tools?cipher=substitution",
    "try_break_url": "/breaker?cipher=substitution",
    "tools_url": "/tools",
  },


  # ============================================================
  # TRANSPOSITION (GENERAL FAMILY)
  # ============================================================
  "transposition": {
    "cipher_name": "Transposition Ciphers",
    "page_title": "Transposition Ciphers — Complete Guide, Examples, and How to Break Them | The Cipher Lab",
    "meta_description": (
      "A detailed guide to transposition ciphers: what they are, how they work, how to encode/decode, "
      "how to detect them using frequency clues, and how to break common types like rail fence and columnar."
    ),
    "page_blurb": "Ciphers that scramble the order of characters without changing the characters themselves.",

    "cipher_family": "Transposition",
    "cipher_era": "Classical → modern puzzles (common variants in WWII-era systems and puzzle hunts)",
    "cipher_strength": "Weak–medium (variant dependent)",

    "cipher_history": (
      "Transposition is the second big idea in classical cryptography (alongside substitution). "
      "Instead of changing letters, you rearrange them. This preserves letter counts (and often vowel ratio) "
      "so the ciphertext can look deceptively “language-like” while still being unreadable.\n\n"
      "Historically, transpositions were frequently combined with substitution to increase strength. "
      "In puzzles, pure transposition appears a lot because it’s visually confusing but conceptually simple."
    ),

    "what_it_is": (
      "A transposition cipher permutes positions. The plaintext letters are the same letters in the ciphertext—"
      "just in a different order. Many transpositions are implemented by writing text into a grid or zig-zag, "
      "then reading out in a different order."
    ),

    "how_it_works": (
      "At a high level: choose a rule that maps plaintext positions → ciphertext positions. "
      "Common rules are based on grids (columnar), zig-zags (rail fence), or permutations (fixed position swaps).\n\n"
      "Because letters are not replaced, monogram frequencies and IoC tend to stay close to English, "
      "but bigrams/trigrams get disrupted because neighbors are no longer neighbors."
    ),

    "core_rules": [
      "Letters are preserved; only positions change.",
      "Monogram frequency looks “normal” (English-like) if the plaintext is English.",
      "Bigrams/trigrams are degraded (TH/HE/THE stop being dominant).",
      "Padding rules matter (X’s or nulls may be added).",
      "Some variants remove spaces before transposition.",
    ],

    "worked_example": (
      "Columnar-style concept (no key shown):\n"
      "Plaintext: WEAREDISCOVEREDRUN\n"
      "Write into rows of width 5, then read columns → scrambled output.\n\n"
      "Key idea: the letters are all still there, just reordered."
    ),

    "encode_steps": [
      "Choose a specific transposition scheme (rail fence / columnar / permutation).",
      "Normalize text (decide if you remove spaces/punctuation).",
      "Apply the position-reordering rule.",
      "If the scheme uses a grid, decide how to pad the final row (if needed).",
      "To decode, reverse the exact same rule (padding must match).",
    ],

    "encoding_notes": (
      "Most “my decode is almost right” bugs are padding/normalization mismatches: "
      "spaces removed vs preserved, or different filler characters at the end."
    ),

    "break_overview": (
      "Breaking a transposition is about finding the rearrangement rule. "
      "Because the letters are correct but order is wrong, you often see:\n"
      "• vowel ratio looks normal,\n"
      "• letter frequency looks normal,\n"
      "• but common words don’t appear.\n\n"
      "Practical workflow: decide which transposition family it resembles (rail vs columnar), "
      "then brute small parameters (rails/width) and score outputs for English."
    ),

    "break_steps": [
      "Confirm it’s likely transposition: English-like frequency + high IoC, but no readable brute shifts (Caesar/Affine).",
      "Try rail fence first with small rails (2–6) and score outputs.",
      "Try column widths (2–20) for simple grid transpositions; look for readable fragments.",
      "Use cribs: if you suspect 'THE' or 'FLAG{' etc., test placements that could create them.",
      "For keyed columnar: test short keywords, or use heuristic scoring if you have enough text.",
    ],

    "frequency_summary": (
      "Transposition keeps monogram frequency close to plaintext because it doesn’t change letters. "
      "So your frequency chart still has the typical English curve. The giveaway is that bigrams/trigrams "
      "that are normally dominant (TH, HE, THE, AND) are reduced because adjacency is destroyed."
    ),

    "freq_hints": [
      "IoC is often close to English.",
      "Monogram frequency looks English-like (peaks exist).",
      "But common bigrams/trigrams are unusually weak or scrambled.",
      "Vowel ratio often looks normal compared to random data.",
    ],

    "freq_example": (
      "If frequency looks English-like but brute-forcing Caesar gives nothing readable:\n"
      "→ suspect transposition.\n"
      "Then brute rails (2–6) or column widths (2–20) and score outputs for English."
    ),

    "pitfalls": [
      "Misclassifying as substitution just because frequency looks English-like.",
      "Ignoring padding (one missing/extra filler breaks decoding).",
      "Not normalizing the same way the encoder did (spaces removed vs kept).",
      "Assuming there is always a keyword; many transpositions are parameter-only (rails/width).",
    ],

    "variants": [
      "Rail Fence (zig-zag).",
      "Columnar (keyed column order).",
      "Permutation (fixed shuffle).",
      "Double transposition (apply two columnars; much harder).",
      "Route ciphers (spiral/diagonal read patterns in a grid).",
    ],

    "practice_blurb": (
      "Practice by encoding a message with rail fence (rails 3–5) and with columnar (short keyword), "
      "then try to recover the parameters from ciphertext only."
    ),

    "practice_prompts": [
      "Rail fence with rails=3: encode a sentence, then recover rails by brute force.",
      "Column width=7 grid transposition: recover the width by scoring outputs.",
      "Try a columnar keyword of length 5 and see how padding changes decoding.",
      "Take a ciphertext and decide substitution vs transposition using frequency + bigrams.",
    ],

    "faq": [
      {"q": "Why does transposition keep frequency “normal”?",
       "a": "Because letters aren’t substituted, only rearranged—counts don’t change."},
      {"q": "What’s the quickest first thing to brute force?",
       "a": "Rail fence rails 2–6, then simple grid widths 2–20."},
      {"q": "Why do bigrams/trigrams look worse than normal?",
       "a": "Because neighbors in plaintext aren’t neighbors in ciphertext anymore."},
    ],

    "related_ciphers": [
      {"name": "Rail Fence Cipher", "url": "/ciphers/railfence"},
      {"name": "Columnar Transposition", "url": "/ciphers/columnar"},
      {"name": "Vigenère Cipher", "url": "/ciphers/vigenere"},
    ],

    "try_encode_url": "/tools?cipher=railfence",
    "try_break_url": "/breaker?cipher=railfence",
    "tools_url": "/tools",
  },


  # ============================================================
  # PLAYFAIR
  # ============================================================
  "playfair": {
    "cipher_name": "Playfair Cipher",
    "page_title": "Playfair Cipher — Full Guide, 5×5 Square, Examples, and How to Break It | The Cipher Lab",
    "meta_description": (
      "An in-depth Playfair cipher guide: building the 5×5 key square, plaintext rules (digraphs, filler letters), "
      "worked examples, what frequency looks like, and practical breaking approaches."
    ),
    "page_blurb": "A digraph substitution cipher using a 5×5 key square (usually merging I/J).",

    "cipher_family": "Substitution (digraph / polygraphic)",
    "cipher_era": "1850s+ (Victorian era; military interest)",
    "cipher_strength": "Weak–medium (stronger than monoalphabetic, still breakable)",

    "cipher_history": (
      "Playfair was designed to be practical by hand while resisting single-letter frequency analysis. "
      "Because it encrypts pairs of letters (digraphs), it disrupts monogram patterns like 'E is most common'.\n\n"
      "It was historically attractive for field use because it’s faster than many manual systems and doesn’t require "
      "complex mathematics. In puzzle contexts, it’s common because the rules produce distinctive artifacts: "
      "no double letters in a pair, filler insertions, and a 5×5 square constraint."
    ),

    "what_it_is": (
      "Playfair encrypts text two letters at a time using a 5×5 grid built from a keyword. "
      "Each digraph is transformed based on whether the letters are in the same row, same column, or form a rectangle."
    ),

    "how_it_works": (
      "1) Build a 5×5 square from a keyword (remove duplicates), then fill remaining letters (often I/J combined).\n"
      "2) Prepare plaintext into digraphs: split into pairs; if a pair is double (LL), insert a filler (often X) between.\n"
      "3) Encrypt each pair:\n"
      "   • Same row → take letters to the right (wrap around)\n"
      "   • Same column → take letters below (wrap)\n"
      "   • Rectangle → swap columns (take the other corner in the same row)\n\n"
      "Decryption reverses the direction (left/up)."
    ),

    "core_rules": [
      "I/J are usually merged (implementation choice; sometimes Q omitted instead).",
      "Plaintext is split into digraphs; double letters in a pair are separated by a filler (often X).",
      "If plaintext length is odd, add a filler at the end.",
      "Same-row: shift right (encrypt); same-column: shift down (encrypt).",
      "Rectangle: swap columns (corners).",
    ],

    "worked_example": (
      "Keyword: MONARCHY (I/J merged)\n"
      "Square:\n"
      "M O N A R\n"
      "C H Y B D\n"
      "E F G I K\n"
      "L P Q S T\n"
      "U V W X Z\n\n"
      "Plaintext prep: HELLO → HE LX LO (insert X to split LL)\n"
      "Encrypt each pair using row/column/rectangle rules."
    ),

    "encode_steps": [
      "Choose a keyword; remove duplicate letters.",
      "Build the 5×5 square (merge I/J or use your tool’s rule).",
      "Normalize plaintext (typically letters only).",
      "Split into pairs; if a pair has double letters, insert filler (X) between them.",
      "Encrypt pairs using the three Playfair rules; pad last letter if needed.",
    ],

    "encoding_notes": (
      "Most Playfair confusion is plaintext preparation: the filler insertion and I/J merging rules. "
      "If your result differs from another tool, compare those two rules first."
    ),

    "break_overview": (
      "Playfair hides monogram frequency, but it leaks digraph structure and the constraints of the 5×5 square. "
      "Manual breaking is possible with cribs and digraph logic, but serious breaking often uses heuristic search "
      "(hill-climbing / simulated annealing) scored by English tetragrams.\n\n"
      "In puzzles, a shortcut is often: known keyword theme, or partial square given, or a crib like 'THE' aligned to pairs."
    ),

    "break_steps": [
      "Confirm it behaves like Playfair: digraph behavior, lack of obvious double letters, I/J style.",
      "Look for common digraph patterns and crib words; remember plaintext was modified (X inserted).",
      "If automated: use hill-climbing with tetragram scoring to recover the square.",
      "If crib-based: test square placements consistent with rectangle/row/column transformations.",
      "Validate by decrypting a longer chunk; Playfair solutions 'snap' into readable text when correct.",
    ],

    "frequency_summary": (
      "Because Playfair encrypts **pairs**, single-letter frequency is less directly useful. "
      "You’ll often see:\n"
      "• fewer clear monogram peaks,\n"
      "• digraph patterns dominate,\n"
      "• and characteristic artifacts like inserted X’s in plaintext (not visible in ciphertext, but affects structure)."
    ),

    "freq_hints": [
      "Monograms are less diagnostic than digraph/tetragram scoring.",
      "Common English digraphs (TH/HE/IN) don’t map cleanly—pairs are transformed.",
      "Ciphertext often lacks patterns you'd see in monoalphabetic substitution.",
      "If you decrypt with a near-correct square, English-like bigrams/tetragrams rapidly improve.",
    ],

    "freq_example": (
      "If your frequency tool says monograms are unhelpful but text is alphabetic and seems structured:\n"
      "Try Playfair heuristics: digraph-based cracking or hill-climb with tetragrams."
    ),

    "pitfalls": [
      "Not matching the same square rules (I/J merge vs Q omitted vs other).",
      "Forgetting filler insertion (LL → LX LO type transformations).",
      "Assuming ciphertext digraph boundaries match plaintext (they do, but plaintext was altered first).",
      "Comparing results across tools with different preprocessing rules.",
    ],

    "variants": [
      "Different merge rules (I/J or I/J/K etc.).",
      "Different filler letters (X, Q, Z).",
      "6×6 Playfair including digits (less common).",
    ],

    "practice_blurb": (
      "Practice by building a square from a keyword, encrypting a short message, and verifying digraph rules. "
      "Then try recovering the square using a crib or by recognizing a likely keyword theme."
    ),

    "practice_prompts": [
      "Build a Playfair square from the keyword 'MONARCHY' and encrypt 'HIDETHEGOLD'.",
      "Encrypt text with many doubles (BALLOON, HELLO) and observe filler behavior.",
      "Try decrypting with the wrong I/J rule and see how the output differs.",
      "Use a crib: assume plaintext contains 'THE' and test plausible square constraints.",
    ],

    "faq": [
      {"q": "Why does Playfair merge I and J?",
       "a": "A 5×5 grid only holds 25 letters, so one letter is merged/omitted. I/J is the most common convention."},
      {"q": "Why do we insert X between double letters?",
       "a": "Because Playfair encrypts digraphs and cannot encode a pair like 'LL' directly without ambiguity."},
      {"q": "Is Playfair stronger than substitution?",
       "a": "Yes against simple monogram frequency, but it’s still breakable with digraph/tetragram statistics and automation."},
    ],

    "related_ciphers": [
      {"name": "Substitution Cipher", "url": "/ciphers/substitution"},
      {"name": "Vigenère Cipher", "url": "/ciphers/vigenere"},
      {"name": "Hill Cipher", "url": "/ciphers/hill"},
    ],

    "try_encode_url": "/tools?cipher=playfair",
    "try_break_url": "/breaker?cipher=playfair",
    "tools_url": "/tools",
  },


  # ============================================================
  # HILL
  # ============================================================
  "hill": {
    "cipher_name": "Hill Cipher",
    "page_title": "Hill Cipher — Linear Algebra Encryption, Examples, and How to Break It | The Cipher Lab",
    "meta_description": (
      "The most practical Hill cipher guide: block encryption with matrices mod 26, invertibility requirements, "
      "worked examples, encoding/decoding workflow, and breaking via known-plaintext and scoring."
    ),
    "page_blurb": "A block cipher that encrypts letter vectors using matrix multiplication modulo 26.",

    "cipher_family": "Substitution (polygraphic / linear algebra)",
    "cipher_era": "1920s+ (classical academic cipher)",
    "cipher_strength": "Weak (against known plaintext); medium in puzzles",

    "cipher_history": (
      "The Hill cipher is famous because it brings linear algebra into cryptography. Instead of substituting letters one at a time, "
      "it encrypts blocks (pairs, triples, etc.), which can better obscure single-letter frequencies.\n\n"
      "Its key weakness is linearity: with enough known plaintext/ciphertext pairs, the key matrix can be solved directly. "
      "In puzzle settings, it’s still interesting because it produces ciphertext that looks structured but not easily solvable by "
      "basic frequency methods."
    ),

    "what_it_is": (
      "Hill encrypts blocks of size n. Each block is treated as a vector of numbers (A=0..Z=25), multiplied by an n×n key matrix K, "
      "all modulo 26. Decryption uses the modular inverse matrix K⁻¹."
    ),

    "how_it_works": (
      "1) Choose block size n (e.g., 2).\n"
      "2) Choose an invertible key matrix K modulo 26.\n"
      "3) Convert plaintext into vectors of length n.\n"
      "4) Encrypt: C = K·P (mod 26).\n"
      "5) Decrypt: P = K⁻¹·C (mod 26).\n\n"
      "Invertibility is crucial: det(K) must be coprime with 26 so that det(K) has a modular inverse."
    ),

    "core_rules": [
      "Work mod 26 (or mod m if using a different alphabet).",
      "Key matrix must be invertible mod 26 (det(K) must have an inverse).",
      "Plaintext is grouped into fixed-size blocks; padding may be added.",
      "Because it’s linear, known plaintext can reveal the key quickly.",
    ],

    "worked_example": (
      "Block size n=2\n"
      "Key K = [[3, 3], [2, 5]]\n"
      "Plaintext 'HI' → [7, 8]\n"
      "C = K·P mod 26\n"
      "C0 = 3*7 + 3*8 = 45 mod 26 = 19 → T\n"
      "C1 = 2*7 + 5*8 = 54 mod 26 = 2 → C\n"
      "Ciphertext: 'TC'"
    ),

    "encode_steps": [
      "Choose block size n (2 is common for puzzles).",
      "Pick an n×n key matrix K that is invertible mod 26.",
      "Normalize plaintext to letters (decide how to handle spaces/punctuation).",
      "Convert letters to numbers A=0..Z=25, group into blocks of n, pad if needed.",
      "Compute C = K·P (mod 26), convert back to letters.",
    ],

    "encoding_notes": (
      "If your decoder fails, the usual cause is a non-invertible matrix mod 26. "
      "Always verify det(K) is coprime with 26 before using it."
    ),

    "break_overview": (
      "Hill is vulnerable to known-plaintext attacks. If you know enough plaintext blocks and their corresponding ciphertext blocks, "
      "you can solve for K with linear algebra modulo 26.\n\n"
      "Without known plaintext, brute force is only feasible for tiny block sizes with small constrained key spaces. "
      "In practice, you’d use heuristic scoring or exploit puzzle constraints (e.g., known header, known word list)."
    ),

    "break_steps": [
      "If you have known plaintext/ciphertext: collect n blocks, set up equations, solve for K mod 26.",
      "Check invertibility and validate by encrypting/decrypting additional blocks.",
      "If no known plaintext: try guessing common cribs and solving for K.",
      "For puzzles: use scoring (tetragrams) across candidate keys if the search space is constrained.",
    ],

    "frequency_summary": (
      "Hill disrupts monogram frequency more than monoalphabetic ciphers because letters influence each other within a block. "
      "However, it is still structured: ciphertext remains alphabetic and often has more uniform-looking distributions than Caesar/Affine.\n\n"
      "Bigram/trigram patterns are not preserved in the same way as transposition; instead, blocks behave like mixed substitutions."
    ),

    "freq_hints": [
      "Monograms may look flatter than standard English.",
      "Text remains alphabetic and structured (unlike random bytes/encodings).",
      "If block size is small (2), some repeating patterns can still occur in ciphertext.",
      "Known-plaintext is the real killer; frequency alone won’t solve it.",
    ],

    "freq_example": (
      "If you suspect Hill with n=2 and you know plaintext contains 'TH' somewhere, "
      "and you can locate its ciphertext pair, you can derive constraints on K."
    ),

    "pitfalls": [
      "Using a matrix that isn’t invertible mod 26.",
      "Mixing different A=0 vs A=1 indexing conventions across tools.",
      "Forgetting padding rules (changes last block).",
      "Assuming spaces are included in the alphabet (most Hill implementations do letters-only).",
    ],

    "variants": [
      "Different modulus/alphabet sizes (include digits, punctuation).",
      "Block size 3 or more (harder to brute force).",
      "Affine Hill (adds a vector offset).",
    ],

    "practice_blurb": (
      "Practice with n=2 first: pick a valid matrix, encrypt a sentence, then try recovering the key from a few known blocks."
    ),

    "practice_prompts": [
      "Use K=[[3,3],[2,5]] to encrypt a short message and verify decoding.",
      "Given plaintext/ciphertext pairs of 2-letter blocks, solve for K mod 26.",
      "Try different padding letters and see how ciphertext changes.",
      "Try n=3 with a known invertible matrix and observe how much harder it looks.",
    ],

    "faq": [
      {"q": "Why must the key matrix be invertible mod 26?",
       "a": "Because decryption requires K⁻¹. If det(K) has no inverse mod 26, K⁻¹ doesn’t exist."},
      {"q": "Is Hill secure?",
       "a": "No. Its linear structure makes it vulnerable to known-plaintext and modern cryptanalysis."},
      {"q": "Why does Hill feel “mathy” compared to other ciphers?",
       "a": "Because it uses vector/matrix multiplication and modular inverses as the core mechanism."},
    ],

    "related_ciphers": [
      {"name": "Playfair Cipher", "url": "/ciphers/playfair"},
      {"name": "Affine Cipher", "url": "/ciphers/affine"},
      {"name": "Vigenère Cipher", "url": "/ciphers/vigenere"},
    ],

    "try_encode_url": "/tools?cipher=hill",
    "try_break_url": "/breaker?cipher=hill",
    "tools_url": "/tools",
  },


  # ============================================================
  # AUTOKEY
  # ============================================================
  "autokey": {
    "cipher_name": "Autokey Cipher",
    "page_title": "Autokey Cipher — Vigenère Variant, Examples, and How to Break It | The Cipher Lab",
    "meta_description": (
      "A detailed Autokey cipher guide: how it differs from Vigenère, how the keystream is formed, "
      "encoding/decoding examples, frequency clues, and practical breaking strategies using cribs."
    ),
    "page_blurb": "A Vigenère-style cipher where the key extends using plaintext (or ciphertext) rather than repeating.",

    "cipher_family": "Polyalphabetic substitution (Vigenère variant)",
    "cipher_era": "Classical (19th century variants; common in puzzles)",
    "cipher_strength": "Weak–medium (crib-sensitive)",

    "cipher_history": (
      "Autokey was designed to fix a major weakness of Vigenère: repeating keys create periodic patterns "
      "that reveal the key length (Kasiski/IoC). Autokey reduces repetition by extending the keystream using text itself.\n\n"
      "In puzzle cryptography, Autokey is popular because it’s one step harder than Vigenère but still crackable when you have "
      "a crib, a known header, or predictable plaintext structure."
    ),

    "what_it_is": (
      "Autokey starts with a short keyword (the seed), then appends plaintext (most common variant) to form the keystream. "
      "Each keystream letter acts like a Caesar shift (A=0..Z=25) just like Vigenère."
    ),

    "how_it_works": (
      "Plaintext-autokey (common):\n"
      "• Keystream = KEYWORD + PLAINTEXT (then truncated to message length)\n"
      "• Encrypt: C[i] = (P[i] + K[i]) mod 26\n"
      "• Decrypt: P[i] = (C[i] - K[i]) mod 26, but K after the seed depends on recovered plaintext\n\n"
      "This creates a feedback loop: once you recover some plaintext, you recover more of the keystream automatically."
    ),

    "core_rules": [
      "Seed keyword provides the first keystream letters.",
      "Keystream continues with plaintext (or sometimes ciphertext in another variant).",
      "Non-letters are usually skipped for keystream advancement (implementation dependent).",
      "If you recover a plaintext fragment, you can extend the keystream from it.",
    ],

    "worked_example": (
      "Seed key: KEY\n"
      "Plaintext: ATTACKATDAWN\n"
      "Keystream: KEYATTACKATDA (seed + plaintext, truncated)\n"
      "Encrypt using Vigenère arithmetic with this keystream."
    ),

    "encode_steps": [
      "Pick a seed keyword (letters only).",
      "Normalize plaintext/key rules (uppercase, letters-only advancement).",
      "Build keystream = seed + plaintext (truncate to length).",
      "Encrypt each letter like Vigenère using the matching keystream letter.",
      "Preserve or strip punctuation consistently with your chosen convention.",
    ],

    "encoding_notes": (
      "Autokey variants differ. The big question: does the keystream extend with plaintext or ciphertext, "
      "and does it advance over punctuation? Make sure your tool and your puzzle use the same convention."
    ),

    "break_overview": (
      "Autokey is harder than repeating-key Vigenère because the usual key-length attacks weaken. "
      "The most practical break is a **crib attack**: guess a likely plaintext word/phrase, then use it to bootstrap the keystream.\n\n"
      "Once the guess is correct, decryption rapidly becomes self-sustaining because recovered plaintext generates more keystream."
    ),

    "break_steps": [
      "Look for predictable structure: greetings, headers, 'THE', 'ATTACK', 'FLAG{', dates, etc.",
      "Guess a crib at a position; derive keystream letters for that region.",
      "Use derived keystream to decrypt forward; recovered plaintext extends the keystream.",
      "If output becomes increasingly readable, the crib is likely correct.",
      "If output collapses into nonsense quickly, try a different crib or alignment.",
    ],

    "frequency_summary": (
      "Autokey often looks less periodic than Vigenère because the keystream changes with plaintext. "
      "IoC and Kasiski can be less decisive. Frequency analysis is more of a triage tool here: "
      "it tells you it’s classical/polyalphabetic, but cribs do the heavy lifting."
    ),

    "freq_hints": [
      "Less clear repeating structure than Vigenère with short repeating key.",
      "Still alphabetic and language-linked (not random bytes).",
      "If you try Vigenère key-length scans and nothing clean appears, Autokey is a suspect.",
      "Crib success produces a strong ‘snowball’ effect in readability.",
    ],

    "freq_example": (
      "Try guessing the plaintext contains 'THE' near the start. "
      "If that guess produces readable continuation (not just a single word), you likely found the right alignment."
    ),

    "pitfalls": [
      "Using the wrong Autokey variant (plaintext-autokey vs ciphertext-autokey).",
      "Wrong key advancement rules over punctuation/spaces.",
      "Assuming you can estimate key length like standard Vigenère (often misleading).",
      "Not testing multiple crib alignments (off by 1–2 characters is common).",
    ],

    "variants": [
      "Plaintext Autokey (common).",
      "Ciphertext Autokey (keystream extends with ciphertext).",
      "Running-key cipher (keystream is long external text; cousin concept).",
    ],

    "practice_blurb": (
      "Practice by encrypting with a short seed like 'KEY', then try breaking it by guessing 'THE' or a known header near the start."
    ),

    "practice_prompts": [
      "Encrypt a paragraph with seed 'KEY' and try to recover plaintext using a crib.",
      "Try the same plaintext with different punctuation handling and see how breaks differ.",
      "Construct a ciphertext-autokey example and compare breaking difficulty.",
      "Use a known phrase like 'MEETAT' and test alignments.",
    ],

    "faq": [
      {"q": "Why is Autokey harder than Vigenère?",
       "a": "Because it reduces repeating-key periodicity, weakening key-length detection."},
      {"q": "What’s the best way to break it in puzzles?",
       "a": "Cribs. A correct guessed word can bootstrap the keystream and snowball into full recovery."},
      {"q": "Does Autokey keep spaces/punctuation?",
       "a": "Usually punctuation is preserved, but key advancement rules vary by implementation."},
    ],

    "related_ciphers": [
      {"name": "Vigenère Cipher", "url": "/ciphers/vigenere"},
      {"name": "Caesar Cipher", "url": "/ciphers/caesar"},
      {"name": "Substitution Cipher", "url": "/ciphers/substitution"},
    ],

    "try_encode_url": "/tools?cipher=autokey",
    "try_break_url": "/breaker?cipher=autokey",
    "tools_url": "/tools",
  },


  # ============================================================
  # BACON
  # ============================================================
  "bacon": {
    "cipher_name": "Bacon Cipher (Baconian)",
    "page_title": "Bacon Cipher — A/B Encoding, Hidden Messages, Examples, and How to Break It | The Cipher Lab",
    "meta_description": (
      "A complete Bacon cipher guide: A/B encoding, 5-bit groups, classic and modern variants, "
      "how to hide Baconian in formatting, and step-by-step decoding/breaking."
    ),
    "page_blurb": "A steganographic-style cipher that encodes letters as patterns of A and B (often hidden in text styling).",

    "cipher_family": "Encoding / Steganography (binary pattern mapping)",
    "cipher_era": "1600s (Francis Bacon), modern puzzle usage",
    "cipher_strength": "Weak (pattern extraction is the main challenge)",

    "cipher_history": (
      "Bacon’s cipher is historically famous because it’s as much about hiding a message as encrypting it. "
      "The classic idea is to encode letters using two symbols (A/B), often disguised as two text styles "
      "(uppercase/lowercase, bold/normal, serif/sans).\n\n"
      "In modern puzzles, the hardest part isn’t the substitution—it’s noticing the two-channel signal and extracting it cleanly."
    ),

    "what_it_is": (
      "Baconian encodes each plaintext letter as a 5-character pattern of A and B (like a 5-bit code). "
      "Once you have the A/B stream, decoding is straightforward: group into 5s and map to letters."
    ),

    "how_it_works": (
      "1) Decide which visible feature means A vs B (e.g., lowercase=A, uppercase=B).\n"
      "2) Read the cover text and convert each character into A or B.\n"
      "3) Group A/B into chunks of 5.\n"
      "4) Convert each chunk into a letter using the Baconian table.\n\n"
      "Classic tables often merge I/J and U/V, but modern variants may not."
    ),

    "core_rules": [
      "Two distinct symbols/styles represent A and B.",
      "Group into 5s (classic) to map to letters.",
      "Variant tables differ (I/J merge, U/V merge, or full 26 mapping).",
      "Extraction is the hard part: formatting can be lost in copy/paste.",
    ],

    "worked_example": (
      "A/B stream:\n"
      "AABAA AABAB ABBAB\n"
      "→ HELLO (example mapping; depends on table variant)\n\n"
      "If hiding in case:\n"
      "aAbAA aAbAb aBBaB\n"
      "Lowercase=A, Uppercase=B → same A/B stream."
    ),

    "encode_steps": [
      "Pick a Bacon table variant (classic vs full 26).",
      "Convert plaintext letters into A/B 5-tuples.",
      "Choose a carrier: text where you can encode A/B via styling (case/bold/font).",
      "Apply styling for each carrier letter to represent the next A/B symbol.",
      "Verify extraction survives the medium (screenshots/HTML preserve better than plain copy).",
    ],

    "encoding_notes": (
      "Bacon is often broken because formatting disappears. If you suspect Bacon, inspect the HTML/CSS, or use a screenshot, "
      "or look for consistent alternations like upper/lower patterns."
    ),

    "break_overview": (
      "Breaking Baconian is mostly: 1) detect the two-channel signal, 2) extract A/B reliably, 3) pick the correct table.\n\n"
      "Once extracted, try both A/B polarity assignments (swap A↔B) and try classic vs full-26 tables."
    ),

    "break_steps": [
      "Identify the two encodings (case, font weight, punctuation type, spacing, etc.).",
      "Map one style to A and the other to B (try both ways if unsure).",
      "Extract a continuous A/B stream and group into 5s.",
      "Decode with the Bacon table; if gibberish, swap polarity or switch table variant.",
      "If output is close-but-wrong, check grouping offset (start 1–4 symbols later).",
    ],

    "frequency_summary": (
      "Frequency analysis on letters isn’t the main tool—Bacon hides a binary stream. "
      "The tell is often *visual*: two styles appear with roughly balanced counts.\n\n"
      "After extraction, you’re effectively decoding 5-bit symbols, not cracking natural-language frequencies."
    ),

    "freq_hints": [
      "Look for two visual/textual states that alternate (case, boldness, font).",
      "A/B distribution often near-balanced over long text (not always).",
      "If copy/paste normalizes everything, the cipher ‘disappears’.",
      "Try shifting grouping alignment if the decode looks off by one.",
    ],

    "freq_example": (
      "If you extract: ABBAB AABAA ...\n"
      "Try decoding using classic Bacon mapping; if nonsense, swap A↔B and retry; "
      "then try a full 26-letter mapping."
    ),

    "pitfalls": [
      "Formatting destroyed by copy/paste (turns everything into one style).",
      "Wrong table variant (classic merges letters).",
      "Wrong A/B polarity assignment.",
      "Wrong grouping offset (start position).",
    ],

    "variants": [
      "Classic Bacon (I/J and U/V merged).",
      "Full 26 Bacon table (distinct I/J, U/V).",
      "Carrier variations: punctuation, whitespace width, emoji types, etc.",
    ],

    "practice_blurb": (
      "Practice by hiding a short secret in case (upper/lower) inside an innocent sentence, then try extracting it from different mediums."
    ),

    "practice_prompts": [
      "Hide 'HELLO' as A/B using uppercase/lowercase in a paragraph.",
      "Try extracting from rendered HTML vs copied text and note differences.",
      "Decode with both Bacon tables and compare outputs.",
      "Encode a longer message and see how easy it is to lose alignment.",
    ],

    "faq": [
      {"q": "Is Bacon a cipher or steganography?",
       "a": "It’s often treated as steganography because the message is hidden in an innocuous carrier."},
      {"q": "Why does copy/paste break Bacon?",
       "a": "Because many carriers rely on formatting that gets normalized when you copy as plain text."},
      {"q": "What if decoding gives gibberish?",
       "a": "Swap A/B polarity, try a different table variant, and check grouping offset."},
    ],

    "related_ciphers": [
      {"name": "Morse Encoding", "url": "/ciphers/morse"},
      {"name": "Substitution Cipher", "url": "/ciphers/substitution"},
      {"name": "Transposition Ciphers", "url": "/ciphers/transposition"},
    ],

    "try_encode_url": "/tools?cipher=bacon",
    "try_break_url": "/breaker?cipher=bacon",
    "tools_url": "/tools",
  },


  # ============================================================
  # MORSE (ENCODING) + ENIGMA (OVERVIEW PAGE)
  # ============================================================
  "morse": {
    "cipher_name": "Morse & Enigma",
    "page_title": "Morse Code and Enigma — Encoding vs Cipher, How to Decode, and How Enigma Worked | The Cipher Lab",
    "meta_description": (
      "A detailed overview of Morse code (encoding) and Enigma (rotor cipher): how Morse is decoded, spacing rules, "
      "and how Enigma’s rotors + plugboard created a changing substitution, plus high-level breaking concepts."
    ),
    "page_blurb": "Morse is an encoding (no secret key). Enigma is a rotor cipher (a real keyed system with changing substitution).",

    "cipher_family": "Encoding (Morse) + Rotor cipher (Enigma)",
    "cipher_era": "Morse: 1800s; Enigma: 1900s",
    "cipher_strength": "Morse: no secrecy; Enigma: strong historically, broken with constraints + automation",

    "cipher_history": (
      "Morse code is often misnamed as a “cipher,” but it’s an encoding: it converts letters into dots and dashes and can be reversed "
      "without a secret key. Its difficulty is operational (signal clarity, timing, spacing), not cryptographic secrecy.\n\n"
      "Enigma, by contrast, is a true cipher machine. It uses a plugboard and a stack of rotating rotors to produce a substitution "
      "that changes with every key press. Historically, it was defeated using a combination of cribs (guessed plaintext), "
      "mathematical constraints, and automation (bombes)."
    ),

    "what_it_is": (
      "Morse: a reversible representation of text as short/long signals.\n"
      "Enigma: a rotor-based polyalphabetic substitution system where the mapping changes each character."
    ),

    "how_it_works": (
      "Morse decoding basics:\n"
      "• Dots/dashes form letters.\n"
      "• Spacing matters: short gaps between elements, medium gaps between letters, longer gaps between words.\n\n"
      "Enigma basics:\n"
      "• Plugboard swaps pairs before/after rotors.\n"
      "• Rotors implement substitution and step (rotate) each key press.\n"
      "• A reflector sends the signal back through rotors, making encryption/decryption symmetric for the same settings."
    ),

    "core_rules": [
      "Morse has no secret key; Enigma absolutely does.",
      "Morse difficulty is spacing + noise; Enigma difficulty is huge key space + stepping.",
      "Enigma encryption is symmetric (same settings decrypt).",
      "Morse word spacing is critical to correct decoding.",
    ],

    "worked_example": (
      "Morse example:\n"
      "HELLO → •••• · ·−·· ·−·· −−−\n\n"
      "Enigma example (conceptual):\n"
      "Pressing the same letter twice produces different ciphertext letters because rotors step."
    ),

    "encode_steps": [
      "Morse: convert each letter to dots/dashes; preserve clear letter and word spacing.",
      "Enigma: choose rotor order, ring settings, start positions, and plugboard pairs; then type plaintext.",
    ],

    "encoding_notes": (
      "If you’re solving a puzzle and someone says “Morse cipher,” treat it as Morse encoding first—there’s no key to crack."
    ),

    "break_overview": (
      "Morse: you don’t “break” it—you decode it. The task is to parse dots/dashes and spacing correctly.\n\n"
      "Enigma: breaking historically relied on operational mistakes, message formats, repeated keys, and cribs. "
      "Modern hobby breaking usually assumes you know the machine model and uses software with constraints."
    ),

    "break_steps": [
      "Morse: identify dot/dash symbols and letter/word gaps; decode using a Morse table.",
      "If ambiguous, try alternate spacing segmentation.",
      "Enigma: find a crib (guessed plaintext) and use it to constrain rotor/plugboard settings.",
      "Use automation/solvers rather than manual search (keyspace is enormous).",
    ],

    "frequency_summary": (
      "Morse doesn’t preserve letter frequency in a helpful way because it’s not substitution—it's representation.\n"
      "Enigma output can look close to random because substitution changes each character."
    ),

    "freq_hints": [
      "If the text is dots/dashes, treat as encoding (Morse), not a cipher family.",
      "If the ciphertext is alphabetic but very “flat” and resists classical attacks, a rotor-like system may be involved.",
      "For Morse, look for separators or timing cues rather than frequencies.",
    ],

    "freq_example": (
      "If you see: •− ••• •−−− ...\n"
      "Try decoding with standard Morse. If there are no clear gaps, you may need to infer spacing from context."
    ),

    "pitfalls": [
      "Calling Morse a cipher and looking for a key that doesn’t exist.",
      "Losing Morse spacing information (turns a decode into a segmentation puzzle).",
      "Assuming Enigma can be brute-forced casually without constraints.",
    ],

    "variants": [
      "Morse variants: American vs International (most puzzles use International).",
      "Enigma variants: different rotor sets, reflectors, plugboard configurations.",
    ],

    "practice_blurb": (
      "Practice Morse by decoding short phrases with and without explicit spaces. For Enigma, practice the concept: "
      "stepping substitution and the idea of cribs."
    ),

    "practice_prompts": [
      "Decode: •••• · ·−·· ·−·· −−− (HELLO).",
      "Write MORSE in dots/dashes and share it without spaces—can you still decode it?",
      "Explain why Enigma encryption changes each key press (rotor stepping).",
      "Try an online Enigma simulator with known settings to see symmetry (same settings decrypt).",
    ],

    "faq": [
      {"q": "Is Morse code encryption?",
       "a": "Not in the secrecy sense—it's encoding. Anyone can decode it with the table."},
      {"q": "Why was Enigma hard to break?",
       "a": "Huge key space plus changing substitution each character—breaks relied on constraints, cribs, and automation."},
      {"q": "Why does Enigma decrypt with the same settings?",
       "a": "Because of the reflector design; the process is symmetric when configured identically."},
    ],

    "related_ciphers": [
      {"name": "Bacon Cipher", "url": "/ciphers/bacon"},
      {"name": "Vigenère Cipher", "url": "/ciphers/vigenere"},
      {"name": "Transposition Ciphers", "url": "/ciphers/transposition"},
    ],

    "try_encode_url": "/tools?cipher=morse",
    "try_break_url": "/breaker?cipher=morse",
    "tools_url": "/tools",
  },


}

@app.route("/ciphers/<slug>")
def cipher_info(slug):
    cfg = CIPHER_INFO.get(slug.lower())
    if not cfg:
        abort(404)

    user = current_user()  # if you want nav/login state
    return render_template(
        "cipher_info.html",
        user=user,
        canonical_url=request.base_url,
        **cfg
    )

import os

@app.route("/__admin/db-download/<token>")
@admin_required
def admin_db_download(token):
    user = current_user()
    
    if token != os.environ.get("DB_DL_SECRET"):
        abort(404)   # 404 hides existence

    return send_file(
        "cryptiq.db",
        as_attachment=True,
        download_name="cryptiq.db",
        mimetype="application/octet-stream"
    )


@app.get("/admin/labs/<int:ws_id>")
@admin_required
def admin_lab_view(ws_id):
    user = current_user()
    if not user or not is_admin(user):
        return redirect(url_for("home"))

    conn = get_db()
    row = conn.execute("""
        SELECT *
        FROM workspaces
        WHERE id=?
        LIMIT 1
    """, (ws_id,)).fetchone()

    if not row:
        conn.close()
        abort(404)

    ws = dict(row)

    # refresh user for pro flag correctness (keep consistent with rest of app)
    fresh_user = conn.execute("SELECT * FROM users WHERE id=? LIMIT 1", (user["id"],)).fetchone()
    fresh_user = dict(fresh_user) if fresh_user else user

    conn.close()

    # Admin should be able to VIEW any lab; keep it view-only in the UI
    return render_template(
        "workspace.html",
        user=fresh_user,
        ws=ws,
        is_owner=False,
        show_tour=False,
        viewer_role="admin",
        viewer_can_edit=False,
        viewer_is_pro=is_pro(fresh_user),
    )

if __name__ == "__main__":
    app.run(debug=True)
    
