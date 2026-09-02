from database.db import get_connection

conn = get_connection()

cursor = conn.cursor()

cursor.execute("""

CREATE TABLE IF NOT EXISTS scans(

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    filename TEXT,

    filesize INTEGER,

    extension TEXT,

    entropy REAL,

    md5 TEXT,

    sha256 TEXT,

    prediction TEXT,

    confidence REAL,

    risk TEXT,

    recommendation TEXT,

    scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP

)

""")

conn.commit()

conn.close()

print("Database Created Successfully")