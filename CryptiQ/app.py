from flask import (
    Flask, request, jsonify, render_template, redirect,
    url_for, session, flash, send_from_directory, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os
from datetime import datetime

# --- Cipher tools (your existing imports) ---
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

# ----- Configuration -----
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
DB_PATH = os.path.join(BASE_DIR, "cryptiq.db")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}

# change this to your admin email
ADMIN_EMAIL = "jimcalstrom@gmail.com"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("CRYPTIQ_SECRET") or "dev-secret-key"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 6 * 1024 * 1024  # 6 MB upload limit

# ----- Database helpers -----
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Create tables if missing (idempotent)."""
    conn = get_db()
    cur = conn.cursor()
    # users (with email + is_admin)
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
    # posts
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
    # comments (new)
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
    """Add missing columns if the DB was created before (email, is_admin)."""
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

def ensure_admin_flag():
    """Mark the ADMIN_EMAIL (if present) as admin."""
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
    """Return the logged-in user as a plain dict (not sqlite3.Row)."""
    if "user_id" in session:
        conn = get_db()
        cur = conn.execute(
            "SELECT id, username, email, is_admin FROM users WHERE id = ?",
            (session["user_id"],)
        )
        row = cur.fetchone()
        conn.close()
        return dict(row) if row else None
    return None

def is_admin(user):
    """Admin if flagged in DB OR matches ADMIN_EMAIL."""
    if not user:
        return False
    return (user.get("is_admin") == 1) or (user.get("email", "").lower() == ADMIN_EMAIL.lower())

def fetch_post(post_id):
    conn = get_db()
    cur = conn.execute("SELECT * FROM posts WHERE id = ?", (post_id,))
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

# ------------------- Main Cipher Breaker -------------------
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        text = request.form.get("text", "")
        cipher_type = request.form.get("cipher_type", "vigenere").lower()
        known_plaintext = request.form.get("known_plaintext", "").strip()

        # --- Helper: parse "D=E,X=T,R=A" → {'D':'E','X':'T','R':'A'} ---
        fixed_map = None
        if known_plaintext:
            # detect pattern with '=' sign(s)
            if "=" in known_plaintext:
                fixed_map = {}
                pairs = [p.strip() for p in known_plaintext.replace(";", ",").split(",") if p.strip()]
                for pair in pairs:
                    if "=" in pair:
                        ciph, plain = pair.split("=", 1)
                        if ciph and plain:
                            fixed_map[ciph.strip().upper()] = plain.strip().upper()
            else:
                # treat as crib word (known word)
                # we’ll pass it later as None but you can extend your cipher solver to use it
                fixed_map = None

        # --- Cipher selection ---
        if cipher_type == "caesar":
            key, plaintext = caesar_break(text)
        elif cipher_type == "vigenere":
            key, plaintext = vigenere_break(text)
        elif cipher_type == "permutation":
            key, plaintext = permutation_break(text)
        elif cipher_type == "columnar":
            key, plaintext = columnar_break(text)
        elif cipher_type == "affine":
            key, plaintext = affine_break(text)
        elif cipher_type == "amsco":
            key, plaintext = amsco_break(text)
        elif cipher_type == "railfence":
            key, plaintext = railfence_break(text)
        elif cipher_type == "polybius":
            key, plaintext = substitution_break(
                polybius_standardize(text),
                max_restarts=16,
                sa_steps=6000,
                seed=42,
                time_limit_seconds=25,
                threads=None,
                fixed=fixed_map,
                verbose=True
            )
        elif cipher_type == "substitution":
            key, plaintext = substitution_break(
                text,
                max_restarts=16,
                sa_steps=6000,
                seed=42,
                time_limit_seconds=25,
                threads=None,
                fixed=fixed_map,   # ✅ apply the known plaintext map here
                verbose=True
            )
        else:
            key, plaintext = None, text

        return jsonify({"key": key, "text": plaintext})

    return render_template("index.html", user=current_user())


# ------------------- Tools Page -------------------
@app.route("/tools", methods=["GET"])
def tools_page():
    return render_template("tools.html", user=current_user())

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
        result_text = initial_text + "\n"
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
        def text_spacer(message, block_length):
            message = message.replace(' ', '')
            blocked = ""
            for index, ch in enumerate(message):
                if index % block_length == 0 and index != 0:
                    blocked += " "
                blocked += ch
            return blocked
        result_text = text_spacer(text, block_length)
    elif tool_type == "substitution":
        result_text = text.upper()
    else:
        result_text = "Unknown tool selected."

    return jsonify({"text": result_text})

# ------------------- Info Page -------------------
@app.route("/info", methods=["GET"])
def info_page():
    return render_template("info.html", user=current_user())

# ------------------- Posts -------------------
@app.route("/posts", methods=["GET"])
def posts_list():
    user = current_user()
    conn = get_db()
    cur = conn.execute("""
        SELECT posts.id,
               posts.user_id AS owner_id,
               posts.title,
               posts.body,
               posts.image_filename,
               posts.created_at,
               users.username
        FROM posts
        JOIN users ON posts.user_id = users.id
        ORDER BY posts.created_at DESC
    """)
    posts = cur.fetchall()
    conn.close()
    return render_template("posts.html", posts=posts, user=user, user_is_admin=is_admin(user))

@app.route("/posts/new", methods=["GET", "POST"])
def posts_new():
    user = current_user()
    if not user:
        flash("You must be logged in to create a post.", "warning")
        return redirect(url_for("login"))

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        body = request.form.get("body", "").strip()
        image = request.files.get("image")
        image_filename = None

        if not title or not body:
            flash("Title and body are required.", "danger")
            return redirect(url_for("posts_new"))

        if image and image.filename:
            if not allowed_file(image.filename):
                flash("Unsupported image type.", "danger")
                return redirect(url_for("posts_new"))
            filename = secure_filename(f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{image.filename}")
            image.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
            image_filename = filename

        conn = get_db()
        conn.execute(
            "INSERT INTO posts (user_id, title, body, image_filename, created_at) VALUES (?, ?, ?, ?, ?)",
            (user["id"], title, body, image_filename, datetime.utcnow().isoformat()),
        )
        conn.commit()
        conn.close()
        flash("Post created.", "success")
        return redirect(url_for("posts_list"))

    return render_template("new_post.html", user=user)

# ---- EDIT POST (owner or admin) ----
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
        flash("You can only edit your own post.", "danger")
        return redirect(url_for("posts_list"))

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        body = request.form.get("body", "").strip()
        delete_image = request.form.get("delete_image") == "true"  # hidden field from the bin overlay
        new_image = request.files.get("image")

        image_filename = post["image_filename"]

        if not title or not body:
            flash("Title and body are required.", "danger")
            return redirect(url_for("posts_edit", post_id=post_id))

        if delete_image and image_filename:
            delete_image_file(image_filename)
            image_filename = None

        if new_image and new_image.filename:
            if not allowed_file(new_image.filename):
                flash("Unsupported image type.", "danger")
                return redirect(url_for("posts_edit", post_id=post_id))
            if image_filename:
                delete_image_file(image_filename)
            filename = secure_filename(f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{new_image.filename}")
            new_image.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
            image_filename = filename

        conn = get_db()
        conn.execute(
            "UPDATE posts SET title=?, body=?, image_filename=? WHERE id=?",
            (title, body, image_filename, post_id),
        )
        conn.commit()
        conn.close()
        flash("Post updated.", "success")
        return redirect(url_for("posts_list"))

    return render_template("edit_post.html", post=post, user=user, user_is_admin=is_admin(user))

# ---- DELETE POST (owner or admin) ----
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
        flash("You can only delete your own post.", "danger")
        return redirect(url_for("posts_list"))

    # delete comments for the post, too (FK not declared ON DELETE)
    conn = get_db()
    conn.execute("DELETE FROM comments WHERE post_id=?", (post_id,))
    conn.commit()

    delete_image_file(post["image_filename"])
    conn.execute("DELETE FROM posts WHERE id=?", (post_id,))
    conn.commit()
    conn.close()
    flash("Post deleted.", "info")
    return redirect(url_for("posts_list"))

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
        SELECT c.id, c.post_id, c.user_id, c.body, c.created_at, u.username
        FROM comments c
        JOIN users u ON c.user_id = u.id
        WHERE c.post_id = ?
        ORDER BY c.created_at DESC
    """, (post_id,))
    rows = cur.fetchall()
    conn.close()

    comments = []
    for r in rows:
        comments.append({
            "id": r["id"],
            "post_id": r["post_id"],
            "user_id": r["user_id"],
            "username": r["username"],
            "body": r["body"],
            "created_at": r["created_at"],
            "can_delete": admin or (uid == r["user_id"])
        })

    return jsonify({"ok": True, "count": len(comments), "comments": comments})

@app.route("/comments/add", methods=["POST"])
def comments_add():
    user = current_user()
    if not user:
        return jsonify({"ok": False, "error": "login required"}), 401

    # Accept both JSON and form-encoded
    if request.is_json:
        data = request.get_json(silent=True) or {}
        post_id = int(data.get("post_id") or 0)
        body = (data.get("body") or "").strip()
    else:
        post_id = request.form.get("post_id", type=int)
        body = (request.form.get("body") or "").strip()

    if not post_id or not body:
        return jsonify({"ok": False, "error": "post_id and body required"}), 400

    # make sure post exists
    if not fetch_post(post_id):
        return jsonify({"ok": False, "error": "post not found"}), 404

    now = datetime.utcnow().isoformat()
    conn = get_db()
    conn.execute(
        "INSERT INTO comments (post_id, user_id, body, created_at) VALUES (?, ?, ?, ?)",
        (post_id, user["id"], body, now)
    )
    conn.commit()
    # Return the newly inserted comment
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
        "can_delete": True  # author can delete
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

        # Check if passwords match
        if password != confirm:
            flash("Passwords do not match.", "error")
            return render_template('register.html')

        # Check if email or username already exist
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM users WHERE email=? OR username=?", (email, username))
            existing_user = c.fetchone()

        if existing_user:
            flash("Email or username already exists.", "error")
            return render_template('register.html')

        # Hash password and store in 'password_hash' column
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
        identifier = (request.form.get("username") or "").strip()  # username or email
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
            flash("No account found with that username or email.", "danger")
            return redirect(url_for("login"))

        if not check_password_hash(user["password_hash"], password):
            flash("Incorrect password.", "danger")
            return redirect(url_for("login"))

        session["user_id"] = user["id"]
        flash(f"Welcome back, {user['username']}!", "success")
        return redirect(url_for("posts_list"))

    return render_template("login.html", user=current_user())

@app.route("/logout")
def logout():
    session.pop("user_id", None)
    flash("Logged out.", "info")
    return redirect(url_for("index"))

# ------------------- Run -------------------
if __name__ == "__main__":
    app.run(debug=True)
