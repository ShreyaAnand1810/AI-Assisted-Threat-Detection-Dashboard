import sqlite3

conn = get_connection()
cursor = conn.cursor()

cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
tables = cursor.fetchall()

print("Tables in database:")

if not tables:
    print("No tables found.")
else:
    for table in tables:
        print(table[0])

conn.close()