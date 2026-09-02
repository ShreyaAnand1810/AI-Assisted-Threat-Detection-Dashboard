import sqlite3
from datetime import datetime

DATABASE = "database/threat.db"


# ----------------------------------
# Database Connection
# ----------------------------------

def get_connection():
    print("Database Path:", DATABASE)

    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row

    return conn


# ----------------------------------
# Create Table
# ----------------------------------

def create_table():

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans(

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        filename TEXT,

        extension TEXT,

        filesize INTEGER,

        entropy REAL,

        md5 TEXT,

        sha256 TEXT,

        prediction TEXT,

        confidence REAL,

        risk TEXT,

        recommendation TEXT,

        scan_time TEXT

    )
    """)

    conn.commit()
    conn.close()


# ----------------------------------
# Save Scan
# ----------------------------------

def save_scan(filename, features, result):

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO scans(

        filename,
        extension,
        filesize,
        entropy,
        md5,
        sha256,
        prediction,
        confidence,
        risk,
        recommendation,
        scan_time

    )

    VALUES(?,?,?,?,?,?,?,?,?,?,?)
    """,

    (

        filename,

        str(features.get("extension","")),

        int(features.get("filesize",0)),

        float(features.get("entropy",0)),

        str(features.get("md5","")),

        str(features.get("sha256","")),

        str(result.get("prediction","Unknown")),

        float(result.get("confidence",0)),

        str(result.get("risk","Unknown")),

        str(result.get("recommendation","")),

        datetime.now().strftime("%d-%m-%Y %H:%M:%S")

    ))

    conn.commit()
    conn.close()


# ----------------------------------
# Dashboard Statistics
# ----------------------------------

def dashboard_stats():

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM scans")
    total = cursor.fetchone()[0]

    cursor.execute("""
    SELECT COUNT(*)
    FROM scans
    WHERE prediction='Safe'
    """)
    safe = cursor.fetchone()[0]

    cursor.execute("""
    SELECT COUNT(*)
    FROM scans
    WHERE prediction!='Safe'
    """)
    malicious = cursor.fetchone()[0]

    cursor.execute("""
    SELECT COUNT(*)
    FROM scans
    WHERE risk='Critical'
    """)
    critical = cursor.fetchone()[0]

    cursor.execute("""
    SELECT scan_time
    FROM scans
    ORDER BY id DESC
    LIMIT 1
    """)

    row = cursor.fetchone()

    last_scan = row["scan_time"] if row else "No Scan"

    conn.close()

    return {

        "total": total,

        "safe": safe,

        "malicious": malicious,

        "critical": critical,

        "last_scan": last_scan

    }


# ----------------------------------
# Scan History
# ----------------------------------

def get_all_scans():

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("""
    SELECT *
    FROM scans
    ORDER BY id DESC
    """)

    rows = cursor.fetchall()

    conn.close()

    return rows


# ----------------------------------
# Delete Scan
# ----------------------------------

def delete_scan(scan_id):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(
        "DELETE FROM scans WHERE id=?",
        (scan_id,)
    )

    conn.commit()

    conn.close()


# ----------------------------------
# Daily Scan Chart
# ----------------------------------

def scans_per_day():

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("""

    SELECT

    substr(scan_time,1,10) AS day,

    COUNT(*)

    FROM scans

    GROUP BY day

    ORDER BY day

    """)

    data = cursor.fetchall()

    conn.close()

    return data


# ----------------------------------
# Risk Chart
# ----------------------------------

def risk_distribution():

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("""

    SELECT

    risk,

    COUNT(*)

    FROM scans

    GROUP BY risk

    """)

    data = cursor.fetchall()

    conn.close()

    return data


# ----------------------------------
# Initialize Database
# ----------------------------------

def recent_scans(limit=5):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM scans
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))

    scans = cursor.fetchall()

    conn.close()

    return scans

def top_extensions():

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT extension,
               COUNT(*) as total
        FROM scans
        GROUP BY extension
        ORDER BY total DESC
        LIMIT 5
    """)

    data = cursor.fetchall()

    conn.close()

    return data
def monthly_scans():

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("""

        SELECT

        substr(scan_time,4,7) AS month,

        COUNT(*) AS total

        FROM scans

        GROUP BY month

        ORDER BY month

    """)

    data = cursor.fetchall()

    conn.close()

    return data
def detection_rate():

    stats = dashboard_stats()

    if stats["total"] == 0:
        return 0

    return round(
        (stats["malicious"] / stats["total"]) * 100,
        2
    )
def security_score():

    stats = dashboard_stats()

    if stats["total"] == 0:
        return 100

    score = 100 - (
        (stats["critical"] * 15)
        +
        (stats["malicious"] * 5)
    )

    return max(score,0)
def search_scans(filename="", prediction="", risk="", sort="DESC"):

    conn = get_connection()
    cursor = conn.cursor()

    query = """
        SELECT *
        FROM scans
        WHERE 1=1
    """

    params = []

    if filename:
        query += " AND filename LIKE ?"
        params.append(f"%{filename}%")

    if prediction:
        query += " AND prediction = ?"
        params.append(prediction)

    if risk:
        query += " AND risk = ?"
        params.append(risk)

    if sort == "ASC":
        query += " ORDER BY id ASC"
    else:
        query += " ORDER BY id DESC"

    cursor.execute(query, params)

    rows = cursor.fetchall()

    conn.close()

    return rows
def get_scans_paginated(page, per_page, search="", risk=""):
    conn = sqlite3.connect("database/threat.db")
    conn.row_factory = sqlite3.Row   # ✅ rows behave like dicts
    cursor = conn.cursor()

    query = "SELECT * FROM scans WHERE 1=1"
    params = []

    if search:
        query += " AND filename LIKE ?"
        params.append(f"%{search}%")

    if risk:
        query += " AND risk = ?"
        params.append(risk)

    query += " ORDER BY scan_time DESC LIMIT ? OFFSET ?"
    params.extend([per_page, (page - 1) * per_page])

    cursor.execute(query, params)
    rows = cursor.fetchall()

    # Convert to dicts so Jinja can use scan.entropy
    scans = [dict(row) for row in rows]

    count_query = "SELECT COUNT(*) FROM scans WHERE 1=1"
    count_params = []
    if search:
        count_query += " AND filename LIKE ?"
        count_params.append(f"%{search}%")
    if risk:
        count_query += " AND risk = ?"
        count_params.append(risk)

    cursor.execute(count_query, count_params)
    total = cursor.fetchone()[0]

    conn.close()
    return scans, total

# Backward compatibility
def add_scan(filename, features, result):
    return save_scan(filename, features, result)
create_table()