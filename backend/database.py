import sqlite3
from datetime import datetime

DB_NAME = "phishing_guard.db"


def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            result TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            reasons TEXT NOT NULL,
            scanned_at TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


def save_scan(url, result, risk_score, reasons):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO scans (url, result, risk_score, reasons, scanned_at)
        VALUES (?, ?, ?, ?, ?)
    """, (
        url,
        result,
        risk_score,
        ", ".join(reasons),
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    conn.commit()
    conn.close()


def get_history():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, url, result, risk_score, reasons, scanned_at
        FROM scans
        ORDER BY id DESC
        LIMIT 20
    """)

    rows = cursor.fetchall()
    conn.close()

    return [
        {
            "id": row[0],
            "url": row[1],
            "result": row[2],
            "risk_score": row[3],
            "reasons": row[4],
            "scanned_at": row[5]
        }
        for row in rows
    ]