import sqlite3

conn = sqlite3.connect("cryptiq.db")
cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table';")
tables = [row[0] for row in cur.fetchall()]
conn.close()

print(tables)
