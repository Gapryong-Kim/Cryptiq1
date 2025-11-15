from cipher_tools.breakers import (
    atbash_break,
    base64_break,
    hex_break,
    binary_break,
    baconian_break
)

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
from cipher_tools.vigenere import vigenere_break
from cipher_tools.caesar import caesar_break
from cipher_tools.permutation import permutation_break
from cipher_tools.columnar_transposition import columnar_break
from cipher_tools.frequency_analyser import analyse
from cipher_tools.affine import affine_break
from cipher_tools.amsco import amsco_break
from cipher_tools.railfence import railfence_break
from cipher_tools.polybius_square import *
from utility.unique import unique
from cipher_tools.replace import replace


from datetime import datetime
from cipher_tools.breakers import (
            atbash_break,
            base64_break,
            hex_break,
            binary_break,
            baconian_break
        )
from cipher_tools.auto_break import auto_break  # ✅ new auto detector





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



def get_current_season():
    """Returns the current season number, starting at 1 from November 2025."""
    start = datetime(2025, 11, 1)  # site launch / first season start
    now = datetime.utcnow()
    months_since = (now.year - start.year) * 12 + (now.month - start.month)
    season = (months_since // 2) + 1  # one season = 2 months
    return max(1, season)



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
app.config["MAIL_PASSWORD"] = "xryonkhnboapnuwt"         # 16-char App Password
app.config["MAIL_DEFAULT_SENDER"] = ("The Cipher Lab Support", "thecipherlab@gmail.com")

mail = Mail(app)

app.secret_key = os.environ.get("CRYPTIQ_SECRET") or "dev-secret-key"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 6 * 1024 * 1024  # 6 MB upload limit

# Token generator for password resets
serializer = URLSafeTimedSerializer(app.secret_key)

# ----- Database helpers -----
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

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

# ----- Utility -----
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def current_user():
    if "user_id" in session:
        conn = get_db()
        cur = conn.execute(
            "SELECT id, username, email, is_admin, banned FROM users WHERE id = ?",
            (session["user_id"],)
        )
        row = cur.fetchone()
        conn.close()
        return dict(row) if row else None
    return None


def is_admin(user):
    if not user:
        return False
    return (user.get("is_admin") == 1) or (user.get("email", "").lower() == ADMIN_EMAIL.lower())

def fetch_post(post_id):
    conn = get_db()
    cur = conn.execute("""
        SELECT p.*, u.username AS author
        FROM posts p
        JOIN users u ON p.user_id = u.id
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
        SELECT p.id, p.title, p.body, p.created_at, u.username AS author
        FROM posts p
        JOIN users u ON p.user_id = u.id
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
                key, plaintext = vigenere_break(text)
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
                        sa_steps=2500,
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
                    max_restarts=4,
                    sa_steps=2750,
                    seed=42,
                    time_limit_seconds=13,
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

    conn = get_db()

    # --- Main posts query (LEFT JOIN keeps posts even if user deleted) ---
    cur = conn.execute("""
        SELECT 
            posts.id,
            posts.user_id AS owner_id,
            posts.title,
            posts.body,
            posts.image_filename,
            posts.created_at,
            posts.pinned,
            users.username,
            users.email,
            users.is_admin,
            users.banned
        FROM posts
        LEFT JOIN users ON posts.user_id = users.id
        ORDER BY posts.pinned DESC, datetime(posts.created_at) DESC
        LIMIT ? OFFSET ?
    """, (per_page, offset))
    rows = cur.fetchall()

    # --- Convert sqlite3.Row objects into mutable dicts ---
    posts = [dict(row) for row in rows]

    # --- Total count query ---
    cur = conn.execute("SELECT COUNT(*) AS total FROM posts")
    row = cur.fetchone()
    total_posts = row["total"] if row else 0
    conn.close()

    total_pages = max((total_posts + per_page - 1) // per_page, 1)

    # --- Replace missing usernames so templates don't break ---
    for p in posts:
        if not p.get("username"):
            p["username"] = "[Deleted User]"
            p["is_admin"] = 0
            p["banned"] = 0

    return render_template(
        "posts.html",
        posts=posts,
        user=user,
        user_is_admin=is_admin(user),
        page=page,
        total_pages=total_pages
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

    # ✍️ 3. Handle post creation
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        body = request.form.get("body", "").strip()
        image = request.files.get("image")
        image_filename = None
        pinned = 1 if (request.form.get("pinned") and is_admin(user)) else 0

        if not title or not body:
            flash("Title and body are required.", "error")
            return redirect(url_for("create_post"))

        if image and image.filename:
            if not allowed_file(image.filename):
                flash("Unsupported image type.", "error")
                return redirect(url_for("create_post"))
            filename = secure_filename(
                f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{image.filename}"
            )
            image.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
            image_filename = filename

        conn = get_db()
        conn.execute(
            """
            INSERT INTO posts (user_id, title, body, image_filename, pinned, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (user["id"], title, body, image_filename, pinned, datetime.utcnow().isoformat())
        )
        conn.commit()
        conn.close()
        print("DEBUG current_user:", user)

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
    user = current_user()
    if user and user.get("banned"):
        return jsonify({"ok": False, "error": "You are banned from posting or commenting."}), 403

    if not user:
        return jsonify({"ok": False, "error": "login required"}), 401

    if request.is_json:
        data = request.get_json(silent=True) or {}
        post_id = int(data.get("post_id") or 0)
        body = (data.get("body") or "").strip()
    else:
        post_id = request.form.get("post_id", type=int)
        body = (request.form.get("body") or "").strip()

    if not post_id or not body:
        return jsonify({"ok": False, "error": "post_id and body required"}), 400

    if not fetch_post(post_id):
        return jsonify({"ok": False, "error": "post not found"}), 404

    now = datetime.utcnow().isoformat()
    conn = get_db()
    conn.execute(
        "INSERT INTO comments (post_id, user_id, body, created_at) VALUES (?, ?, ?, ?)",
        (post_id, user["id"], body, now)
    )
    conn.commit()
    cur = conn.execute("""
        SELECT c.id, c.post_id, c.user_id, c.body, c.created_at, u.username
        FROM comments c
        JOIN users u ON c.user_id = u.id
        WHERE c.post_id=? AND c.user_id=? AND c.created_at=?
        ORDER BY c.id DESC LIMIT 1
    """, (post_id, user["id"], now))
    row = cur.fetchone()
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

@app.route("/login", methods=["GET", "POST"])
def login():
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
            return redirect(url_for("login"))

        if not check_password_hash(user["password_hash"], password):
            flash("Incorrect password.", "error")
            return redirect(url_for("login"))

        session["user_id"] = user["id"]
        flash(f"Welcome back, {user['username']}!", "success")
        return redirect(url_for("posts_list"))

    return render_template("login.html", user=current_user())

# ------------------- Forgot/Reset Password -------------------
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        if not email:
            flash("Please enter your email address.", "warning")
            return render_template("forgot_password.html", user=current_user())

        conn = get_db()
        cur = conn.execute("SELECT id, email FROM users WHERE lower(email)=?", (email,))
        user = cur.fetchone()
        conn.close()

        if not user:
            flash("No account found with that email.", "error")
            return render_template("forgot_password.html", user=current_user())

        # Generate token (valid 1 hour)
        token = serializer.dumps(email, salt="password-reset")
        reset_link = url_for("reset_password", token=token, _external=True)

        # --- Send Email ---
        msg = Message(
            subject="Password Reset — The Cipher Lab",
            recipients=[email],
            html=f"""
            <h2 style="color:#00ffd5;font-weight:700;">Password Reset Requested</h2>
            <p>Hello,</p>
            <p>We received a request to reset your password for your Cipher Lab account.</p>
            <p>Click the link below to reset it:</p>
            <p><a href="{reset_link}" style="color:#00ffd5;">Reset your password</a></p>
            <p>This link will expire in 1 hour.</p>
            <br><p style="color:#888;">– The Cipher Lab Team</p>
            """
        )
        try:
            mail.send(msg)
            flash("✅ Password reset email sent! Check your inbox for instructions.", "success")
        except Exception as e:
            flash("⚠️ Error sending email. Please try again later.", "error")
            print("MAIL ERROR:", e)

        # Re-render same page with message
        return render_template("forgot_password.html", user=current_user())

    return render_template("forgot_password.html", user=current_user())

@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    try:
        email = serializer.loads(token, salt="password-reset", max_age=3600)
    except Exception:
        flash("Invalid or expired reset link.", "error")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        new_pass = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        if new_pass != confirm:
            flash("Passwords do not match.", "error")
            return redirect(url_for("reset_password", token=token))

        hashed = generate_password_hash(new_pass)
        conn = get_db()
        conn.execute("UPDATE users SET password_hash=? WHERE lower(email)=?", (hashed, email))
        conn.commit()
        conn.close()

        flash("🎉 Your password has been reset successfully! You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html", email=email)

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

    cur = conn.execute("""
        SELECT id, title, body, image_filename, created_at
        FROM posts
        WHERE user_id=?
        ORDER BY datetime(created_at) DESC
    """, (user["id"],))
    posts = cur.fetchall()

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
    return render_template("account.html", user=user, user_info=user_info, posts=posts, leaderboard_data=leaderboard_data)


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
    """Each season lasts 2 months, starting January."""
    now = datetime.utcnow()
    return ((now.month - 1) // 2) + 1 + (6 * (now.year - 2025))

@app.route("/leaderboard")
def leaderboard():
    user = current_user()  # ✅ Properly fetch logged-in user for navbar
    username = user["username"] if user else None

    conn = get_db()

    # === 1️⃣ All-Time Leaderboard ===
    all_time = conn.execute("""
        SELECT username,
               SUM(score) AS total_score,
               COUNT(DISTINCT cipher_week) AS weeks_played
        FROM cipher_submissions
        GROUP BY username
        ORDER BY total_score DESC
        LIMIT 50
    """).fetchall()

    # === 2️⃣ Current Season Leaderboard ===
    current_season = get_current_season()
    seasonal = conn.execute("""
        SELECT username,
               SUM(score) AS total_score,
               COUNT(DISTINCT cipher_week) AS weeks_played
        FROM cipher_submissions
        WHERE season=?
        GROUP BY username
        ORDER BY total_score DESC
        LIMIT 50
    """, (current_season,)).fetchall()

    # === 3️⃣ Weekly Fastest Solvers ===
    weekly = conn.execute("""
        SELECT username,
               MIN(solve_time_seconds) AS best_time,
               MAX(score) AS score
        FROM cipher_submissions
        WHERE DATE(created_at) >= DATE('now', '-7 days')
        GROUP BY username
        ORDER BY best_time ASC
        LIMIT 50
    """).fetchall()

    conn.close()

    # === Render the leaderboard page ===
    return render_template(
        "leaderboard.html",
        user=user,  # ✅ for base_nav.html
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
        if cipher == "railfence":
            rails = to_int(3)
            return func(text, rails)

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





# ------------------- Run -------------------
if __name__ == "__main__":
    app.run(debug=True)













