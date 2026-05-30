import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "securevault.db"


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS files (
        file_id TEXT PRIMARY KEY,
        owner TEXT NOT NULL,
        original_filename TEXT NOT NULL,
        file_size INTEGER NOT NULL,
        chunk_size INTEGER NOT NULL,
        total_chunks INTEGER NOT NULL,
        salt TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        status TEXT DEFAULT 'uploading'
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS chunks (
        file_id TEXT NOT NULL,
        chunk_number INTEGER NOT NULL,
        nonce TEXT NOT NULL,
        hmac_hex TEXT NOT NULL,
        chunk_path TEXT NOT NULL,
        size INTEGER NOT NULL,
        uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (file_id, chunk_number),
        FOREIGN KEY (file_id) REFERENCES files(file_id)
    )
    """)
    conn.commit()
    conn.close()
