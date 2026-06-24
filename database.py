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
    CREATE TABLE IF NOT EXISTS handovers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        office_id INTEGER NOT NULL,
        sender_name TEXT NOT NULL,
        content TEXT NOT NULL,
        category TEXT DEFAULT 'general',
        is_read INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now','localtime')),
        FOREIGN KEY (office_id) REFERENCES offices(id)
    );

    CREATE TABLE IF NOT EXISTS care_plans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        office_id INTEGER NOT NULL,
        client_id INTEGER NOT NULL UNIQUE,
        plan_created TEXT,
        careplan_updated TEXT,
        next_review TEXT,
        service_content TEXT,
        goals TEXT,
        notes TEXT,
        updated_at TEXT DEFAULT (datetime('now','localtime')),
        FOREIGN KEY (office_id) REFERENCES offices(id),
        FOREIGN KEY (client_id) REFERENCES clients(id)
    );

    CREATE TABLE IF NOT EXISTS helper_trainings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        office_id INTEGER NOT NULL,
        helper_id INTEGER,
        helper_name TEXT NOT NULL,
        training_type TEXT NOT NULL,
        plan_date TEXT,
        done_date TEXT,
        content TEXT,
        trainer TEXT,
        notes TEXT,
        created_at TEXT DEFAULT (datetime('now','localtime')),
        FOREIGN KEY (office_id) REFERENCES offices(id)
    );

    CREATE TABLE IF NOT EXISTS monthly_meetings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        office_id INTEGER NOT NULL,
        meeting_date TEXT NOT NULL,
        attendees TEXT,
        agenda TEXT,
        minutes TEXT,
        created_at TEXT DEFAULT (datetime('now','localtime')),
        FOREIGN KEY (office_id) REFERENCES offices(id)
    );

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
    CREATE TABLE IF NOT EXISTS kasan_settings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        office_id INTEGER NOT NULL,
        kasan_code TEXT NOT NULL,
        kasan_name TEXT NOT NULL,
        kasan_rate REAL DEFAULT 0,
        is_active INTEGER DEFAULT 1,
        notes TEXT DEFAULT '',
        created_at TEXT DEFAULT (datetime('now','localtime')),
        FOREIGN KEY (office_id) REFERENCES offices(id)
    );
    """)
    conn.commit()
    for col in ["jigyosho_no TEXT DEFAULT ''","pref_no TEXT DEFAULT ''","service_code TEXT DEFAULT ''",
                "units_per_visit INTEGER DEFAULT 254","tanka_unit INTEGER DEFAULT 1140","new_mode INTEGER DEFAULT 0",
                "service_code_life TEXT DEFAULT ''"]:
        try: conn.execute(f"ALTER TABLE offices ADD COLUMN {col}"); conn.commit()
        except: pass
    for col in ["jukyusha_no TEXT DEFAULT ''","jukyusha_valid_from TEXT DEFAULT ''",
                "jukyusha_valid_to TEXT DEFAULT ''","shikyu_visits INTEGER DEFAULT 26",
                "futan_jogen INTEGER DEFAULT 0"]:
        try: conn.execute(f"ALTER TABLE clients ADD COLUMN {col}"); conn.commit()
        except: pass
    conn.execute("""
    CREATE TABLE IF NOT EXISTS inspection_checks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        office_id INTEGER NOT NULL,
        item_key TEXT NOT NULL,
        status TEXT DEFAULT 'unchecked',
        note TEXT DEFAULT '',
        checked_at TEXT DEFAULT '',
        UNIQUE(office_id, item_key),
        FOREIGN KEY (office_id) REFERENCES offices(id)
    )"""); conn.commit()
    conn.execute("""CREATE TABLE IF NOT EXISTS meeting_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        entity_id INTEGER,
        target_name TEXT DEFAULT '',
        room_id TEXT NOT NULL,
        meeting_url TEXT NOT NULL,
        label TEXT DEFAULT '',
        created_by TEXT DEFAULT '',
        created_at TEXT DEFAULT (datetime('now','localtime'))
    )"""); conn.commit()

    # photo_url migration
    for _tbl in ["clients", "helpers"]:
        try:
            conn.execute(f"ALTER TABLE {_tbl} ADD COLUMN photo_url TEXT DEFAULT ''")
            conn.commit()
        except Exception:
            pass
    conn.close()
