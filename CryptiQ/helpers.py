# core.py
import sqlite3, os
from flask import session

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cryptiq.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def current_user():
    if "user_id" in session:
        conn = get_db()
        cur = conn.execute("""
            SELECT id, username, email, is_admin, banned, labs_info_seen, is_pro, stripe_customer_id,pro_current_period_end,pro_cancel_at_period_end
            FROM users
            WHERE id=?
        """, (session["user_id"],))
        row = cur.fetchone()
        conn.close()
        return dict(row) if row else None
    return None
