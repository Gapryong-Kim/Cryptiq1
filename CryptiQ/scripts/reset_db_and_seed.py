# scripts/reset_db_and_seed.py
import os, sqlite3, sys
from datetime import datetime
from werkzeug.security import generate_password_hash

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "cryptiq.db")

ADMIN_EMAIL   = "jimcalstrom@gmail.com"
ADMIN_USER    = sys.argv[1] if len(sys.argv) > 1 else "admin"
ADMIN_PASS    = sys.argv[2] if len(sys.argv) > 2 else "doebeer8"

if os.path.exists(DB_PATH):
    os.remove(DB_PATH)

conn = sqlite3.connect(DB_PATH)
cur  = conn.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  username      TEXT UNIQUE NOT NULL,
  email         TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  is_admin      INTEGER NOT NULL DEFAULT 0,
  created_at    TEXT NOT NULL
)
""")

cur.execute("""
CREATE TABLE IF NOT EXISTS posts (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id       INTEGER NOT NULL,
  title         TEXT NOT NULL,
  body          TEXT NOT NULL,
  image_filename TEXT,
  created_at    TEXT NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id)
)
""")

pw_hash = generate_password_hash(ADMIN_PASS)
cur.execute("""
INSERT INTO users (username, email, password_hash, is_admin, created_at)
VALUES (?, ?, ?, 1, ?)
""", (ADMIN_USER, ADMIN_EMAIL, pw_hash, datetime.utcnow().isoformat()))

conn.commit()
conn.close()

print(f"DB reset. Admin user created:\n  username: {ADMIN_USER}\n  email:    {ADMIN_EMAIL}\n  password: {ADMIN_PASS}")
