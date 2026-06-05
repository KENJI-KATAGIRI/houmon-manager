import sqlite3, os

DB_PATH = os.path.join(os.path.dirname(__file__), "data", "houmon.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS offices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        office_name TEXT NOT NULL,
        email TEXT NOT NULL,
        pw_hash TEXT NOT NULL,
        pw_salt TEXT NOT NULL,
        plan TEXT DEFAULT 'trial',
        subscription_status TEXT DEFAULT 'trial',
        trial_end TEXT,
        created_at TEXT DEFAULT (datetime('now','localtime'))
    );

    CREATE TABLE IF NOT EXISTS clients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        office_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        kana TEXT,
        gender TEXT,
        birthdate TEXT,
        care_level INTEGER DEFAULT 1,
        address TEXT,
        phone TEXT,
        family_name TEXT,
        family_phone TEXT,
        family_relation TEXT,
        primary_helper_id INTEGER,
        care_manager TEXT,
        care_manager_phone TEXT,
        allergies TEXT,
        notes TEXT,
        is_active INTEGER DEFAULT 1,
        created_at TEXT DEFAULT (datetime('now','localtime')),
        FOREIGN KEY (office_id) REFERENCES offices(id)
    );

    CREATE TABLE IF NOT EXISTS helpers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        office_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        kana TEXT,
        phone TEXT,
        employment_type TEXT DEFAULT 'part',
        qualification TEXT DEFAULT 'helper2',
        area TEXT,
        notes TEXT,
        is_active INTEGER DEFAULT 1,
        created_at TEXT DEFAULT (datetime('now','localtime')),
        FOREIGN KEY (office_id) REFERENCES offices(id)
    );

    CREATE TABLE IF NOT EXISTS visit_plans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        office_id INTEGER NOT NULL,
        client_id INTEGER NOT NULL,
        helper_id INTEGER,
        plan_date TEXT NOT NULL,
        start_time TEXT NOT NULL,
        end_time TEXT NOT NULL,
        service_type TEXT DEFAULT 'body',
        notes TEXT,
        status TEXT DEFAULT 'planned',
        created_at TEXT DEFAULT (datetime('now','localtime')),
        FOREIGN KEY (office_id) REFERENCES offices(id),
        FOREIGN KEY (client_id) REFERENCES clients(id),
        FOREIGN KEY (helper_id) REFERENCES helpers(id)
    );

    CREATE TABLE IF NOT EXISTS visit_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        office_id INTEGER NOT NULL,
        visit_plan_id INTEGER,
        client_id INTEGER NOT NULL,
        helper_id INTEGER,
        visit_date TEXT NOT NULL,
        checkin_time TEXT,
        checkout_time TEXT,
        services TEXT,
        body_care TEXT,
        life_support TEXT,
        client_condition TEXT DEFAULT 'normal',
        notes TEXT,
        helper_notes TEXT,
        created_at TEXT DEFAULT (datetime('now','localtime')),
        FOREIGN KEY (office_id) REFERENCES offices(id),
        FOREIGN KEY (client_id) REFERENCES clients(id),
        FOREIGN KEY (helper_id) REFERENCES helpers(id)
    );

    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        office_id INTEGER NOT NULL,
        sender_type TEXT NOT NULL,
        sender_name TEXT NOT NULL,
        recipient_name TEXT,
        client_id INTEGER,
        content TEXT NOT NULL,
        priority TEXT DEFAULT 'normal',
        is_read INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now','localtime')),
        FOREIGN KEY (office_id) REFERENCES offices(id)
    );

    CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        office_id INTEGER NOT NULL,
        client_id INTEGER,
        incident_date TEXT NOT NULL,
        incident_time TEXT NOT NULL,
        helper_name TEXT,
        location TEXT,
        category TEXT,
        level TEXT DEFAULT 'hiyari',
        description TEXT NOT NULL,
        action_taken TEXT,
        followup TEXT,
        created_at TEXT DEFAULT (datetime('now','localtime')),
        FOREIGN KEY (office_id) REFERENCES offices(id)
    );
    """)
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS hq_accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        org_name TEXT NOT NULL,
        email TEXT NOT NULL,
        pw_hash TEXT NOT NULL,
        pw_salt TEXT NOT NULL,
        smtp_host TEXT DEFAULT '',
        smtp_port INTEGER DEFAULT 587,
        smtp_user TEXT DEFAULT '',
        smtp_pass TEXT DEFAULT '',
        created_at TEXT DEFAULT (datetime('now','localtime'))
    );
    CREATE TABLE IF NOT EXISTS hq_office_access (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hq_id INTEGER NOT NULL,
        office_id INTEGER NOT NULL,
        UNIQUE(hq_id, office_id),
        FOREIGN KEY (hq_id) REFERENCES hq_accounts(id),
        FOREIGN KEY (office_id) REFERENCES offices(id)
    );
    """)
    conn.commit()
    conn.close()
