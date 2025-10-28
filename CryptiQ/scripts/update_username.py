import sqlite3

DB_PATH = "cryptiq.db"  # adjust if needed
EMAIL = "jimcalstrom@gmail.com"
NEW_USERNAME = "Merlin"  # <-- change this

conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()

cur.execute("UPDATE users SET username = ? WHERE lower(email) = lower(?)", (NEW_USERNAME, EMAIL))
conn.commit()

cur.execute("SELECT id, username, email, is_admin FROM users WHERE lower(email)=lower(?)", (EMAIL,))
print("✅ Updated record:", cur.fetchone())

conn.close()
