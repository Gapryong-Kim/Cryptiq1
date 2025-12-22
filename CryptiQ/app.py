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

# PLAYFAIR_SCORE_FN, PLAYFAIR_USING_FILE = make_score_fn("english_tetragrams.txt")




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
            """
            SELECT id, username, email, is_admin, banned, labs_info_seen
            FROM users
            WHERE id = ?
            """,
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
    """Season 1 starts 2025-12-01 00:00 UTC. Each season is 2 calendar months."""
    start = datetime(2025, 12, 1, tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)

    months_since = (now.year - start.year) * 12 + (now.month - start.month)
    return max(1, (months_since // 2) + 1)

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


@app.route("/admin")
def admin_dashboard():
    user = current_user()

    # Only admins can access
    if not user or not is_admin(user):
        return redirect(url_for("home"))  # use "home" route

    # Fetch all users from SQLite
    conn = get_db()
    cur = conn.execute("""
        SELECT id, username, email, is_admin, banned, created_at, has_posted
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
    '''if not user:
        flash("Please log in.", "warning")
        return redirect(url_for("login"))'''
    if user:
        conn = get_db()
        rows = conn.execute("""
            SELECT id, title, cipher_text, notes, cipher_image_filename, created_at, updated_at
            FROM workspaces
            WHERE owner_id = ?
            ORDER BY order_index ASC, datetime(updated_at) DESC
        """, (user["id"],)).fetchall()
        conn.close()

        return render_template(
            "workspace_list.html",
            user=user,
            workspaces=[dict(r) for r in rows]
        )
    else:
        return render_template(
            "workspace_list.html",
            user=user,
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

    if request.method == "GET":
        return render_template("workspace_new.html", user=user)

    title = (request.form.get("title") or "Untitled Lab").strip() or "Untitled Lab"
    now = datetime.utcnow().isoformat()

    conn = get_db()
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
    row = conn.execute("""
        SELECT *
        FROM workspaces
        WHERE id = ? AND owner_id = ?
        LIMIT 1
    """, (ws_id, user["id"])).fetchone()
    conn.close()

    if not row:
        abort(404)

    return render_template("workspace.html", user=user, ws=dict(row))

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

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        UPDATE workspaces
        SET title = ?, notes = ?, cipher_text = ?, updated_at = ?
        WHERE id = ? AND owner_id = ?
    """, (title, notes, cipher_text, now, ws_id, user["id"]))
    conn.commit()
    changed = cur.rowcount
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
    if not _workspace_owned(conn, ws_id, user["id"]):
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
    if not _workspace_owned(conn, ws_id, user["id"]):
        conn.close()
        return jsonify({"ok": False, "error": "not found"}), 404

    # next sort index
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

    conn.execute("""
        UPDATE workspaces
        SET updated_at=?
        WHERE id=? AND owner_id=?
    """, (now, ws_id, user["id"]))

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
    if not _workspace_owned(conn, ws_id, user["id"]):
        conn.close()
        return jsonify({"ok": False, "error": "not found"}), 404

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
    conn.execute("""
        UPDATE workspaces
        SET updated_at=?
        WHERE id=? AND owner_id=?
    """, (now, ws_id, user["id"]))

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

    # optional: prevent stupid long names
    if len(label) > 60:
        label = label[:60].strip()

    conn = get_db()

    # verify workspace belongs to user
    ws = conn.execute(
        "SELECT id FROM workspaces WHERE id=? AND owner_id=? LIMIT 1",
        (ws_id, user["id"])
    ).fetchone()
    if not ws:
        conn.close()
        return jsonify({"ok": False, "error": "not found"}), 404

    # verify image belongs to workspace
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

    conn.execute("""
        UPDATE workspaces
        SET updated_at=?
        WHERE id=? AND owner_id=?
    """, (now, ws_id, user["id"]))

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

    # Build a clean title + notes for the lab
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

    conn = get_db()
    cur = conn.cursor()

    # Create workspace
    cur.execute("""
        INSERT INTO workspaces (owner_id, title, cipher_text, notes, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (user["id"], title, cipher_text, notes, now, now))

    ws_id = cur.lastrowid
    conn.commit()
    conn.close()

    return jsonify({"ok": True, "ws_id": ws_id})


# ------------------- Run -------------------
if __name__ == "__main__":
    app.run(debug=True)
