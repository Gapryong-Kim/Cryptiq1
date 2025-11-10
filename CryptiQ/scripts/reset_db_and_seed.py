import os
import sys
import sqlite3
from datetime import datetime
from werkzeug.security import generate_password_hash

# === Paths & Admin Defaults ===
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "cryptiq.db")

ADMIN_EMAIL = "jimcalstrom@gmail.com"
ADMIN_USER  = sys.argv[1] if len(sys.argv) > 1 else "Merlin"
ADMIN_PASS  = sys.argv[2] if len(sys.argv) > 2 else "doebeer8"

# --- Remove old DB ---
if os.path.exists(DB_PATH):
    os.remove(DB_PATH)

conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()

# Enable foreign key constraints
cur.execute("PRAGMA foreign_keys = ON;")

# === USERS TABLE ===
cur.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    banned INTEGER DEFAULT 0
)
""")

# === POSTS TABLE ===
cur.execute("""
CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,  -- ✅ allow NULL for deleted users
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    image_filename TEXT,
    created_at TEXT NOT NULL,
    pinned INTEGER DEFAULT 0,
    FOREIGN KEY(user_id) REFERENCES users(id)
        ON DELETE SET NULL
)
""")

# === COMMENTS TABLE ===
cur.execute("""
CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL,
    user_id INTEGER,  -- ✅ allow NULL for deleted users
    body TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(post_id) REFERENCES posts(id)
        ON DELETE CASCADE,
    FOREIGN KEY(user_id) REFERENCES users(id)
        ON DELETE SET NULL
)
""")

# === WEEKLY CIPHER TABLE ===
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

# === CIPHER SUBMISSIONS TABLE ===
cur.execute("""
CREATE TABLE IF NOT EXISTS cipher_submissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    username TEXT,
    cipher_week INTEGER,
    answer TEXT NOT NULL,
    is_correct INTEGER NOT NULL DEFAULT 0,
    score INTEGER DEFAULT 0,
    submitted_at TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    season INTEGER DEFAULT 1,
    solve_time_seconds INTEGER DEFAULT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
        ON DELETE SET NULL
)
""")

# --- Seed Admin ---
pw_hash = generate_password_hash(ADMIN_PASS)
cur.execute("""
INSERT INTO users (username, email, password_hash, is_admin, created_at)
VALUES (?, ?, ?, 1, ?)
""", (ADMIN_USER, ADMIN_EMAIL, pw_hash, datetime.utcnow().isoformat()))

# --- Default Weekly Cipher ---
cur.execute("""
INSERT INTO weekly_cipher (id, week_number, title, description, ciphertext, solution, hint, posted_at)
VALUES (
    1,
    1,
    'Week #1 — Welcome Cipher',
    'Kickoff puzzle. Decrypt and submit the plaintext keyword.',
    'BJQHTRJ YT YMJ HNUMJW QFG!',
    'WELCOME TO THE CIPHER LAB',
    'Think Caesar…',
    datetime('now')
)
""")

conn.commit()
conn.close()

print(f"✅ Database reset successfully!\n"
      f"Admin user created:\n"
      f"  Username: {ADMIN_USER}\n"
      f"  Email:    {ADMIN_EMAIL}\n"
      f"  Password: {ADMIN_PASS}\n"
      f"Posts and comments will now survive account deletions (user_id can be NULL).")
