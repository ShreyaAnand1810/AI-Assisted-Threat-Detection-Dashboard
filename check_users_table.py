import sqlite3

conn = sqlite3.connect("database/threat.db")
cursor = conn.cursor()

cursor.execute("PRAGMA table_info(users)")
columns = cursor.fetchall()

print("Users table columns:")
for col in columns:
    print(col)

conn.close()