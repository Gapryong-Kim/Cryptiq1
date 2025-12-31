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
from helpers import get_db, current_user

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
        body TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(post_id) REFERENCES posts(id),
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)
    conn.commit()
    conn.close()

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
    # CSP is powerful but easy to break; start basic:
    resp.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"
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

def migrate_labs_pro_fields():
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

init_db()
migrate_db()
ensure_admin_flag()
migrate_shared_labs()
migrate_labs_pro_fields()
# ----- Utility -----
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def is_admin(user):
    if not user:
        return False
    return (user.get("is_admin") == 1) or (user.get("email", "").lower() == ADMIN_EMAIL.lower())


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
                vigenere_part_one = vigenere_break_one(text)
                vigenere_part_two = vigenere_break_two(text)
                
                key, plaintext = final_sort(vigenere_part_one , vigenere_part_two)
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
                    max_restarts=2,
                    sa_steps=3000,
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
            c.body, 
            c.created_at,
            u.username
        FROM comments c
        LEFT JOIN users u ON c.user_id = u.id  -- ✅ LEFT JOIN keeps comments after deletion
        WHERE c.post_id = ?
        ORDER BY datetime(c.created_at) DESC
    """, (post_id,))
    rows = cur.fetchall()
    conn.close()

    # Convert sqlite3.Row to dict and handle deleted users
    comments = []
    for r in rows:
        username = r["username"] if r["username"] else "[Deleted User]"
        user_id = r["user_id"]
        comments.append({
            "id": r["id"],
            "post_id": r["post_id"],
            "user_id": user_id,
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
    else:
        post_id = request.form.get("post_id", type=int)
        body = (request.form.get("body") or "").strip()

    if not post_id or not body:
        return jsonify({"ok": False, "error": "post_id and body required"}), 400

    # Use your existing helper to fetch post (includes owner)
    post = fetch_post(post_id)
    if not post:
        return jsonify({"ok": False, "error": "post not found"}), 404

    post_owner_id = post["user_id"]  # may be NULL if owner deleted

    now = datetime.utcnow().isoformat()
    conn = get_db()
    cur = conn.cursor()

    # Insert comment
    cur.execute(
        "INSERT INTO comments (post_id, user_id, body, created_at) VALUES (?, ?, ?, ?)",
        (post_id, user["id"], body, now)
    )
    comment_id = cur.lastrowid

    # Fetch it back with username
    cur.execute("""
        SELECT c.id, c.post_id, c.user_id, c.body, c.created_at, u.username
        FROM comments c
        JOIN users u ON c.user_id = u.id
        WHERE c.id = ?
    """, (comment_id,))
    row = cur.fetchone()

    # Create notification for post owner (but not if they commented on their own post)
    if post_owner_id and post_owner_id != user["id"]:
        message = f"{user['username']} replied to your post"

        page = get_post_page(post_id)

        cur.execute("""
            INSERT INTO notifications (
                user_id, actor_id, post_id, comment_id, message, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (post_owner_id, user["id"], post_id, comment_id, message, now))


    conn.commit()
    conn.close()

    comment = {
        "id": row["id"],
        "post_id": row["post_id"],
        "user_id": row["user_id"],
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
    cur = conn.execute("SELECT user_id FROM comments WHERE id=?", (comment_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({"ok": False, "error": "comment not found"}), 404

    if (row["user_id"] != user["id"]) and (not is_admin(user)):
        conn.close()
        return jsonify({"ok": False, "error": "forbidden"}), 403

    conn.execute("DELETE FROM comments WHERE id=?", (comment_id,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})

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

        return redirect(url_for("posts_list"))

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
            "If an account with that email exists, a reset link has been sent.",
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

    old_pass = request.form.get("old_password", "")
    new_pass = request.form.get("new_password", "")
    confirm  = request.form.get("confirm_password", "")

    # Always send them back to the account security section (GET-safe)
    back = url_for("account") + "#security"

    if not old_pass or not new_pass or not confirm:
        flash("Please fill in all fields.", "error")
        return redirect(back)

    if old_pass == new_pass:
        flash("New password must be different from your current password.", "error")
        return redirect(back)

    if new_pass != confirm:
        flash("New passwords do not match.", "error")
        return redirect(back)

    if len(new_pass) < 8:
        flash("Password must be at least 8 characters.", "error")
        return redirect(back)

    conn = get_db()
    row = conn.execute(
        "SELECT password_hash FROM users WHERE id=?",
        (user["id"],)
    ).fetchone()

    if not row or not row["password_hash"]:
        conn.close()
        flash("Account error: password not found.", "error")
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
    cur = conn.execute("SELECT username, email, created_at FROM users WHERE id=?", (user["id"],))
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
    return render_template("account.html", user=user, user_info=user_info, posts=posts, leaderboard_data=leaderboard_data, posts_page=posts_page, posts_total_pages=posts_total_pages)


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
        posted_at TEXT NOT NULL
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
        INSERT INTO weekly_cipher (id, week_number, title, description, ciphertext, solution, hint, posted_at)
        VALUES (1, 1, 'Week #1 — Welcome Cipher',
                'Kickoff puzzle. Decrypt and submit the plaintext keyword.',
                'BJQHTRJ YT YMJ HNUMJW QFG!',  -- HELLO WORLD TEST!
                'WELCOME TO THE CIPHER LAB',
                'Think Caesar…', datetime('now'))
        """)
    conn.commit()
    conn.close()

def get_current_weekly():
    conn = get_db()
    cur = conn.execute("SELECT * FROM weekly_cipher WHERE id=1 LIMIT 1")
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None

init_weekly_tables()
migrate_weekly_tables()

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

    # Fetch latest cipher
    cur.execute("SELECT * FROM weekly_cipher ORDER BY week_number DESC LIMIT 1")
    wc = cur.fetchone()

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
        solved_score=user_score
    )

@app.route("/weekly/submit", methods=["POST"])
def weekly_submit():
    data = request.get_json(silent=True) or {}
    answer = (data.get("answer") or "").strip()
    wc = get_current_weekly()
    if not wc:
        return jsonify({"ok": False, "error": "Weekly cipher not found."}), 404

    user = current_user()
    now = datetime.utcnow()

    def normalize(text):
        return re.sub(r"[^A-Z0-9]", "", (text or "").upper())

    answer_clean = normalize(answer)
    solution_clean = normalize(wc["solution"])

    correct = 1 if answer_clean == solution_clean else 0
    score = 0
    solve_time_seconds = None

    # === Compute score only if correct ===
    if correct:
        try:
            posted_time = datetime.fromisoformat(wc["posted_at"])
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
            answer,
            correct,
            score,
            now.isoformat(),
            get_current_season(),
            solve_time_seconds,
        ),
    )
    conn.commit()
    conn.close()

    # === Always return a response ===
    return jsonify({
        "ok": True,
        "correct": bool(correct),
        "score": score
    })


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

        # --- Upsert into weekly_cipher ---
        conn.execute("""
            INSERT INTO weekly_cipher (id, week_number, title, description, ciphertext, solution, hint, posted_at)
            VALUES (1, ?, ?, ?, ?, ?, ?, datetime('now'))
            ON CONFLICT(id) DO UPDATE SET
                week_number=excluded.week_number,
                title=excluded.title,
                description=excluded.description,
                ciphertext=excluded.ciphertext,
                solution=excluded.solution,
                hint=excluded.hint,
                posted_at=excluded.posted_at
        """, (week_number, title, description, ciphertext, solution, hint))

        # --- Reset submissions only if needed ---
        if reset_needed:
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

# Call once on boot (near init_db/migrate_db)
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

@app.route("/workspaces/<int:ws_id>", methods=["GET"], endpoint="workspace_view")
def workspace_view(ws_id):
    user = current_user()
    if not user:
        flash("Please log in.", "warning")
        return redirect(url_for("login"))

    conn = get_db()
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
        show_tour = (not fresh_user.get("labs_tour_seen")),
        viewer_role=("owner" if is_owner else (role or "viewer")),
        viewer_can_edit=viewer_can_edit,
        viewer_is_pro=is_pro(fresh_user),
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
    if not allowed_file(img.filename):
        return jsonify({"ok": False, "error": "unsupported file type"}), 400

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

    return render_template(
        "labs_pro.html",
        user=user,
        viewer_is_pro=viewer_is_pro
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
        return redirect(url_for("login", next=request.path))

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
            "redirect": url_for("login", next=request.path)
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




# ------------------- Run -------------------
if __name__ == "__main__":
    app.run(debug=True)
 