import sqlite3

conn = sqlite3.connect("cryptiq.db")
cur = conn.cursor()

try:
    cur.execute("ALTER TABLE cipher_submissions ADD COLUMN season INTEGER DEFAULT 1;")
    print("✅ Added column: season")
except Exception as e:
    print("⚠️ Skipped 'season' column:", e)

try:
    cur.execute("ALTER TABLE cipher_submissions ADD COLUMN solve_time_seconds INTEGER;")
    print("✅ Added column: solve_time_seconds")
except Exception as e:
    print("⚠️ Skipped 'solve_time_seconds' column:", e)

conn.commit()
conn.close()
print("✅ Migration complete.")
