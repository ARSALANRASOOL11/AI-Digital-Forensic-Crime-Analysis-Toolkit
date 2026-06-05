# =============================================================================
#  modules/database.py  — Database initialisation, audit, custody helpers
# =============================================================================

import sqlite3, time, os
from modules.auth import hash_password

DB = "evidence.db"

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()

    # Evidence
    c.execute("""
    CREATE TABLE IF NOT EXISTS evidence (
        id                INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id           TEXT,
        filename          TEXT,
        path              TEXT,
        hash              TEXT,
        timestamp         TEXT,
        crime_type        TEXT DEFAULT 'Unclassified',
        evidence_category TEXT DEFAULT 'Unknown',
        virustotal_result TEXT DEFAULT ''
    )""")
    for col, dflt in [
        ("crime_type",        "'Unclassified'"),
        ("evidence_category", "'Unknown'"),
        ("virustotal_result", "''"),
    ]:
        try:
            c.execute(f"ALTER TABLE evidence ADD COLUMN {col} TEXT DEFAULT {dflt}")
        except Exception:
            pass

    # Users
    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        username      TEXT UNIQUE,
        password_hash TEXT,
        role          TEXT DEFAULT 'analyst',
        failed_logins INTEGER DEFAULT 0,
        locked_until  REAL    DEFAULT 0
    )""")
    for col, dflt in [("failed_logins", "0"), ("locked_until", "0")]:
        try:
            c.execute(f"ALTER TABLE users ADD COLUMN {col} {dflt.replace('0','INTEGER DEFAULT 0')}")
        except Exception:
            pass

    # Case notes
    c.execute("""
    CREATE TABLE IF NOT EXISTS case_notes (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id   TEXT,
        author    TEXT,
        note      TEXT,
        timestamp TEXT
    )""")

    # Chain of custody
    c.execute("""
    CREATE TABLE IF NOT EXISTS custody_log (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id   TEXT,
        filename  TEXT,
        action    TEXT,
        actor     TEXT,
        timestamp TEXT,
        detail    TEXT
    )""")

    # Audit trail
    c.execute("""
    CREATE TABLE IF NOT EXISTS audit_log (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        username  TEXT,
        event     TEXT,
        timestamp TEXT,
        ip        TEXT
    )""")

    # Seed users if empty
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        seed_users = [
            ("admin",        "Admin@123",    "administrator"),
            ("Arshu29",      "Arsh@123",     "forensic_analyst"),
            ("soc_analyst",  "SOC@analyst1", "soc_analyst"),
            ("red_operator", "RedTeam@99",   "red_team_operator"),
        ]
        for uname, pw, role in seed_users:
            c.execute(
                "INSERT INTO users(username,password_hash,role) VALUES(?,?,?)",
                (uname, hash_password(pw), role)
            )

    conn.commit()
    conn.close()


def log_audit(username: str, event: str, ip: str = ""):
    conn = get_db()
    conn.execute(
        "INSERT INTO audit_log(username,event,timestamp,ip) VALUES(?,?,?,?)",
        (username, event, str(time.time()), ip)
    )
    conn.commit()
    conn.close()


def log_custody(case_id: str, filename: str, action: str, actor: str, detail: str = ""):
    conn = get_db()
    conn.execute(
        "INSERT INTO custody_log(case_id,filename,action,actor,timestamp,detail) VALUES(?,?,?,?,?,?)",
        (case_id, filename, action, actor, str(time.time()), detail)
    )
    conn.commit()
    conn.close()


def new_case_id() -> str:
    conn = get_db()
    n = conn.execute("SELECT COALESCE(MAX(id),0) FROM evidence").fetchone()[0] + 1
    conn.close()
    return "CASE-" + str(n).zfill(4)
