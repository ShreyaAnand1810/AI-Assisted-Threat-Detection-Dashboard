import sqlite3

conn = get_connection()
cursor = conn.cursor()

cursor.execute("PRAGMA table_info(scans)")
columns = cursor.fetchall()

print("Columns in scans table:\n")

for col in columns:
    print(col)

conn.close()