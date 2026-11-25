import sqlite3

conn = sqlite3.connect(":memory:")
cur = conn.cursor()

cur.execute(
    "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)"
)

cur.execute(
    "INSERT INTO users (name) VALUES (?)",
    ("Alice",)
)

user_input = "Robert'); DROP TABLE users;--"

cur.execute(
    "SELECT id, name FROM users WHERE name = ?",
    (user_input,)
)

print(cur.fetchall())

cur.execute(
    "SELECT name FROM sqlite_master WHERE type='table' AND name='users'"
)

table_check = cur.fetchone()

if table_check is None:
    raise RuntimeError(
        "The users table was unexpectedly removed."
    )

conn.close()
