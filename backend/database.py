# Import necessary modules
import sqlite3  # SQLite database module
from datetime import datetime  # For handling timestamps

# Define the database file name
DB_NAME = "phishing_guard.db"

# Function to initialize the database
def init_db():
    """
    Creates the 'scans' table in the database if it doesn't already exist.
    """
    conn = sqlite3.connect(DB_NAME)  # Connect to the SQLite database
    cursor = conn.cursor()  # Create a cursor object to execute SQL commands

    # Create the 'scans' table with the required columns
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,  -- Auto-incrementing ID
        url TEXT NOT NULL,  -- URL being scanned
        result TEXT NOT NULL,  -- Result of the scan
        risk_score INTEGER NOT NULL,  -- Risk score
        reasons TEXT NOT NULL,  -- Reasons
        scanned_at TEXT NOT NULL  -- Timestamp
    )
""")

    conn.commit()  # Commit the changes
    conn.close()  # Close the database connection

# Function to save a scan result to the database
def save_scan(url, result, risk_score, reasons):
    """
    Saves the result of a URL scan to the database.
    :param url: The URL that was scanned
    :param result: The result of the scan (e.g., safe, phishing)
    :param risk_score: The risk score of the URL
    :param reasons: The reasons for the risk score
    """
    conn = sqlite3.connect(DB_NAME)  # Connect to the SQLite database
    cursor = conn.cursor()  # Create a cursor object to execute SQL commands

    # Insert the scan result into the 'scans' table
    cursor.execute("""
        INSERT INTO scans (url, result, risk_score, reasons, scanned_at)
        VALUES (?, ?, ?, ?, ?)
    """, (
        url,  # URL being scanned
        result,  # Result of the scan
        risk_score,  # Risk score of the URL
        ", ".join(reasons),  # Join reasons into a single string
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Current timestamp
    ))

    conn.commit()  # Commit the changes
    conn.close()  # Close the database connection

# Function to retrieve the scan history
def get_history():
    """
    Retrieves the last 20 scan records from the database.
    :return: A list of dictionaries containing scan details
    """
    conn = sqlite3.connect(DB_NAME)  # Connect to the SQLite database
    cursor = conn.cursor()  # Create a cursor object to execute SQL commands

    # Select the last 20 scan records, ordered by ID in descending order
    cursor.execute("""
        SELECT id, url, result, risk_score, reasons, scanned_at
        FROM scans
        ORDER BY id DESC
        LIMIT 20
    """)

    rows = cursor.fetchall()  # Fetch all rows from the query result
    conn.close()  # Close the database connection

    # Convert the rows into a list of dictionaries
    return [
        {
            "id": row[0],  # Scan ID
            "url": row[1],  # URL scanned
            "result": row[2],  # Scan result
            "risk_score": row[3],  # Risk score
            "reasons": row[4],  # Reasons for the risk score
            "scanned_at": row[5]  # Timestamp of the scan
        }
        for row in rows
    ]

# Function to clear the scan history
def clear_history():
    """
    Deletes all scan records from the database.
    """
    conn = sqlite3.connect(DB_NAME)  # Connect to the SQLite database
    cursor = conn.cursor()  # Create a cursor object to execute SQL commands

    # Delete all records from the 'scans' table
    cursor.execute("DELETE FROM scans")

    conn.commit()  # Commit the changes
    conn.close()  # Close the database connection