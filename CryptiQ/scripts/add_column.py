import sqlite3

conn = sqlite3.connect("cryptiq.db")
cur = conn.cursor()

try:
    cur.execute("ALTER TABLE cipher_submissions ADD COLUMN created_at TEXT DEFAULT (datetime('now'));")
    print("✅ Added column: created_at")
except Exception as e:
    print("⚠️ Skipped 'created_at':", e)

conn.commit()
conn.close()
print("✅ Migration complete.")
