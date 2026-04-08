#!/usr/bin/env python3
"""
migrate.py — Run this ONCE to fix the database schema.
Adds any missing columns so the app works correctly.

Usage:  py migrate.py
"""
import sqlite3, os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get('DATA_DIR', BASE_DIR)
DB_PATH  = os.path.join(DATA_DIR, 'data', 'security.db')

if not os.path.exists(DB_PATH):
    print(f'  No database found at {DB_PATH}')
    print('  Start the server once first: py server.py')
    exit(1)

conn = sqlite3.connect(DB_PATH)

migrations = [
    ("guards",      "phone",         "ALTER TABLE guards ADD COLUMN phone TEXT DEFAULT ''"),
    ("guards",      "email",         "ALTER TABLE guards ADD COLUMN email TEXT DEFAULT ''"),
    ("guards",      "notes",         "ALTER TABLE guards ADD COLUMN notes TEXT DEFAULT ''"),
    ("sites",       "contact_name",  "ALTER TABLE sites ADD COLUMN contact_name TEXT DEFAULT ''"),
    ("sites",       "contact_phone", "ALTER TABLE sites ADD COLUMN contact_phone TEXT DEFAULT ''"),
    ("submissions", "admin_note",    "ALTER TABLE submissions ADD COLUMN admin_note TEXT DEFAULT ''"),
    ("submissions", "reviewed_by",   "ALTER TABLE submissions ADD COLUMN reviewed_by TEXT DEFAULT ''"),
    ("admins",      "last_login",    "ALTER TABLE admins ADD COLUMN last_login TEXT"),
]

existing_cols = {}
fixed = 0
for table, col, sql in migrations:
    if table not in existing_cols:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
        existing_cols[table] = {r[1] for r in rows}
    if col not in existing_cols[table]:
        conn.execute(sql)
        existing_cols[table].add(col)
        print(f'  ✓ Added column: {table}.{col}')
        fixed += 1

conn.commit()

# Report current state
g = conn.execute('SELECT COUNT(*) FROM guards WHERE active=1').fetchone()[0]
s = conn.execute('SELECT COUNT(*) FROM sites  WHERE active=1').fetchone()[0]
conn.close()

print()
if fixed:
    print(f'  Migration complete — {fixed} column(s) added.')
else:
    print('  Database is already up to date.')
print(f'  Guards: {g}   Sites: {s}')
print()
print('  You can now run:  py server.py')
