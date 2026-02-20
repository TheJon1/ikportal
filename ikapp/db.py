#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sqlite3
import secrets
from werkzeug.security import generate_password_hash

from .config import DB_PATH, ROLE_OWNER
from .config import (
    ROLE_ACCOUNTING, ROLE_MANAGER, ROLE_PERSONNEL, ROLE_RESPONSIBLE, ROLE_IT
)

def db_connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def query_one(sql, params=()):
    conn = db_connect()
    cur = conn.execute(sql, params)
    row = cur.fetchone()
    conn.close()
    return row

def query_all(sql, params=()):
    conn = db_connect()
    cur = conn.execute(sql, params)
    rows = cur.fetchall()
    conn.close()
    return rows

def exec_sql(sql, params=()):
    conn = db_connect()
    cur = conn.execute(sql, params)
    conn.commit()
    last_id = cur.lastrowid
    conn.close()
    return last_id

def table_has_column(conn, table, col):
    cur = conn.execute(f"PRAGMA table_info({table})")
    cols = [r[1] for r in cur.fetchall()]
    return col in cols

def init_db():
    conn = db_connect()

    conn.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        full_name TEXT NOT NULL,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'personnel',
        is_active INTEGER NOT NULL DEFAULT 1,

        email TEXT,
        manager_id INTEGER,
        responsible_id INTEGER,

        hire_date TEXT,
        annual_leave_days INTEGER NOT NULL DEFAULT 14,

        can_qr INTEGER NOT NULL DEFAULT 0,
        qr_secret TEXT,

        FOREIGN KEY(manager_id) REFERENCES users(id),
        FOREIGN KEY(responsible_id) REFERENCES users(id)
    )
    """)

    conn.execute("""
    CREATE TABLE IF NOT EXISTS leave_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        start_date TEXT NOT NULL,
        end_date TEXT NOT NULL,
        leave_type TEXT NOT NULL DEFAULT 'Yillik',
        reason TEXT,
        status TEXT NOT NULL DEFAULT 'Beklemede',
        created_at TEXT NOT NULL,
        decided_at TEXT,
        decided_by INTEGER,

        pending_with INTEGER,
        stage TEXT,

        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(decided_by) REFERENCES users(id),
        FOREIGN KEY(pending_with) REFERENCES users(id)
    )
    """)

    conn.execute("""
    CREATE TABLE IF NOT EXISTS attendance (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        tarih TEXT NOT NULL,
        saat  TEXT NOT NULL,
        tur   TEXT NOT NULL,
        ip    TEXT,
        cihaz TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)

    conn.execute("""
    CREATE TABLE IF NOT EXISTS assets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        item_name TEXT NOT NULL,
        item_props TEXT,
        serial_no TEXT,
        assigned_at TEXT NOT NULL,
        assigned_by INTEGER,
        returned_at TEXT,
        returned_by INTEGER,
        note TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(assigned_by) REFERENCES users(id),
        FOREIGN KEY(returned_by) REFERENCES users(id)
    )
    """)

    conn.execute("""
    CREATE TABLE IF NOT EXISTS advances (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        amount REAL NOT NULL,
        reason TEXT,
        status TEXT NOT NULL DEFAULT 'Beklemede',
        created_at TEXT NOT NULL,
        decided_at TEXT,
        decided_by INTEGER,
        forwarded_at TEXT,
        forwarded_by INTEGER,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(decided_by) REFERENCES users(id),
        FOREIGN KEY(forwarded_by) REFERENCES users(id)
    )
    """)

    conn.execute("""
    CREATE TABLE IF NOT EXISTS it_tickets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,

        subject TEXT NOT NULL,
        description TEXT,
        priority TEXT NOT NULL DEFAULT 'Orta',

        status TEXT NOT NULL DEFAULT 'Açık',
        status_note TEXT,

        image_path TEXT,

        created_at TEXT NOT NULL,
        updated_at TEXT,
        closed_at TEXT,

        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)

    conn.execute("""
    CREATE TABLE IF NOT EXISTS it_ticket_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ticket_id INTEGER NOT NULL,
        author_id INTEGER NOT NULL,
        message TEXT NOT NULL,
        created_at TEXT NOT NULL,

        FOREIGN KEY(ticket_id) REFERENCES it_tickets(id),
        FOREIGN KEY(author_id) REFERENCES users(id)
    )
    """)

    # migrations (users)
    for col, ddl in [
        ("email", "ALTER TABLE users ADD COLUMN email TEXT"),
        ("manager_id", "ALTER TABLE users ADD COLUMN manager_id INTEGER"),
        ("responsible_id", "ALTER TABLE users ADD COLUMN responsible_id INTEGER"),
        ("hire_date", "ALTER TABLE users ADD COLUMN hire_date TEXT"),
        ("annual_leave_days", "ALTER TABLE users ADD COLUMN annual_leave_days INTEGER NOT NULL DEFAULT 14"),
        ("can_qr", "ALTER TABLE users ADD COLUMN can_qr INTEGER NOT NULL DEFAULT 0"),
        ("qr_secret", "ALTER TABLE users ADD COLUMN qr_secret TEXT"),
    ]:
        if not table_has_column(conn, "users", col):
            conn.execute(ddl)

    for col, ddl in [
        ("decided_at", "ALTER TABLE leave_requests ADD COLUMN decided_at TEXT"),
        ("decided_by", "ALTER TABLE leave_requests ADD COLUMN decided_by INTEGER"),
        ("pending_with", "ALTER TABLE leave_requests ADD COLUMN pending_with INTEGER"),
        ("stage", "ALTER TABLE leave_requests ADD COLUMN stage TEXT"),
    ]:
        if not table_has_column(conn, "leave_requests", col):
            conn.execute(ddl)

    # reminders
    conn.execute("""
    CREATE TABLE IF NOT EXISTS reminders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        due_date TEXT NOT NULL,
        remind_days TEXT NOT NULL DEFAULT '30,7,1,0',
        target_roles TEXT NOT NULL DEFAULT 'owner',
        target_emails TEXT,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL
    )
    """)

    conn.execute("""
    CREATE TABLE IF NOT EXISTS reminder_notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        reminder_id INTEGER NOT NULL,
        notify_date TEXT NOT NULL,
        sent_at TEXT,
        UNIQUE(reminder_id, notify_date)
    )
    """)

    try:
        conn.execute("ALTER TABLE reminders ADD COLUMN created_by INTEGER")
    except Exception:
        pass
    try:
        conn.execute("ALTER TABLE reminders ADD COLUMN scope TEXT NOT NULL DEFAULT 'private'")
    except Exception:
        pass

    conn.execute("""
    CREATE TABLE IF NOT EXISTS reminder_targets (
        reminder_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        UNIQUE(reminder_id, user_id)
    )
    """)

    conn.commit()
    conn.close()

def ensure_default_owner():
    row = query_one("SELECT COUNT(*) as c FROM users")
    if row and row["c"] == 0:
        owner_user = os.environ.get("IK_OWNER_USER", "admin")
        owner_pass = os.environ.get("IK_OWNER_PASS", "Admin123!")
        owner_name = os.environ.get("IK_OWNER_NAME", "Patron")
        owner_mail = os.environ.get("IK_OWNER_EMAIL", "")

        exec_sql("""
        INSERT INTO users (full_name, username, password_hash, role, is_active, email, annual_leave_days, can_qr, qr_secret)
        VALUES (?, ?, ?, ?, 1, ?, 14, 1, ?)
        """, (
            owner_name,
            owner_user.lower().strip(),
            generate_password_hash(owner_pass),
            ROLE_OWNER,
            owner_mail,
            secrets.token_hex(8)
        ))
