import sqlite3

conn = sqlite3.connect("database/threat.db")
cursor = conn.cursor()

cursor.execute("DROP TABLE IF EXISTS users")

conn.commit()
conn.close()

print("Users table deleted successfully.")