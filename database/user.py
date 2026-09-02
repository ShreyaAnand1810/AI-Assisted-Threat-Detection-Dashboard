from database.scan import get_connection
from werkzeug.security import generate_password_hash
def create_user_table():

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'User',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.commit()
    conn.close()

from werkzeug.security import generate_password_hash

def create_default_admin():

    conn = get_connection()
    cursor = conn.cursor()

    # Check if admin already exists
    cursor.execute(
        "SELECT * FROM users WHERE email=?",
        ("admin@cybershield.com",)
    )

    admin = cursor.fetchone()

    if admin is None:

        cursor.execute("""
        INSERT INTO users(username,email,password,role)
        VALUES(?,?,?,?)
        """, (
            "admin",
            "admin@cybershield.com",
            generate_password_hash("admin123"),
            "Admin"
        ))

        conn.commit()

    conn.close()