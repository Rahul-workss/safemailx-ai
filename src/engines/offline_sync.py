import sqlite3
import os
import hashlib
import logging

logger = logging.getLogger("OFFLINE_SYNC")

DB_PATH = os.path.join(os.path.dirname(__file__), "hash_prefixes.db")

def init_db():
    """Initialize the local SQLite database for hash prefixes."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS prefixes (
            prefix_hex TEXT PRIMARY KEY
        )
    ''')
    conn.commit()
    conn.close()

def sync_prefixes():
    """
    Simulate a background daemon syncing Google Safe Browsing 
    or OpenPhish 32-bit SHA-256 prefixes into the local SQLite DB.
    In production, this would hit an update endpoint and apply deltas.
    """
    logger.info("Starting background sync for malicious hash prefixes...")
    
    # Example known bad domains to simulate the sync
    known_bad = ["evil.com", "phish.com", "secure-update-paypa1.com"]
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    for domain in known_bad:
        # Calculate SHA-256 and take the first 8 hex characters (32 bits)
        full_hash = hashlib.sha256(domain.encode('utf-8')).hexdigest()
        prefix = full_hash[:8]
        cursor.execute('INSERT OR IGNORE INTO prefixes (prefix_hex) VALUES (?)', (prefix,))
        
    conn.commit()
    conn.close()
    logger.info("Background sync complete.")

def check_url_prefix(url: str) -> bool:
    """
    Check if the URL's domain hash prefix exists in our local SQLite database.
    Returns True if malicious, False otherwise.
    """
    from urllib.parse import urlparse
    parsed = urlparse(url)
    host = (parsed.hostname or parsed.netloc).lower()
    
    # Calculate prefix
    full_hash = hashlib.sha256(host.encode('utf-8')).hexdigest()
    prefix = full_hash[:8]
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT 1 FROM prefixes WHERE prefix_hex = ?', (prefix,))
    result = cursor.fetchone()
    conn.close()
    
    return bool(result)

# Initialize the database immediately when module is loaded
init_db()
