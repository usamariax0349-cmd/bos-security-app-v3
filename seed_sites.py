#!/usr/bin/env python3
"""
Run this once to pre-load all Prime VIC sites into your database.
Usage:  py seed_sites.py
"""

import sqlite3, os, uuid

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH  = os.path.join(BASE_DIR, 'data', 'security.db')

SITES = [
    "Anglers Tavern",
    "Apollo Bay",
    "Ball Court Hotel",
    "Bearbrass",
    "Beer Deluxe Fed Square",
    "Blackbird Melbourne",
    "Byblós Melbourne",
    "Camden Hotel",
    "Chadstone Shopping Centre",
    "Cosy Corner Beach",
    "Crossguard - Three Blue Ducks, Melbourne",
    "Curtin House - The Toff",
    "Death & Co Melbourne",
    "Doutta Galla Hotel",
    "Eureka Hotel",
    "FiftyFive",
    "Gardiner Hotel",
    "Harvey's Sports Bar & Grill",
    "Hilton Melbourne Little Queen Street",
    "Holliava",
    "Hophaus",
    "Hopscotch",
    "Hotel Esplanade",
    "Kindred Studios",
    "Lakeside Pavilion",
    "Ludlow",
    "Melbourne Public",
    "PJ O'Brien's Southbank",
    "Perseverance",
    "Public House",
    "Quarterhouse",
    "RSL on Bell",
    "River's Edge",
    "State of Grace",
    "Studley Park Boathouse",
    "Swan Hotel",
    "Temperance",
    "Terminus Hotel - Abbotsford",
    "The Continental Sorrento",
    "The Esplanade",
    "The Exchange Hotel",
    "The Local Port",
    "The Lyall Hotel",
    "The Oxford Scholar",
    "The Prince Hotel",
    "The Provincial Hotel",
    "The Victoria Hotel Yarraville",
    "The Wild Geese Hotel",
    "The Windsor Alehouse",
    "Trinket Bar",
    "Turf Sports Bar",
    "Village Belle",
    "West Beach Pavilion",
    "Wharf Hotel",
    "Workshop Bar",
    "Yarra Botanica",
    "Yarra Valley Grand Hotel",
    "ZIMMERMANN Chadstone",
]

CLIENT = "Prime VIC"

os.makedirs(os.path.join(BASE_DIR, 'data'), exist_ok=True)
conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row

# Make sure table exists
conn.execute('''CREATE TABLE IF NOT EXISTS sites (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, client_name TEXT NOT NULL,
    address TEXT, default_rate REAL DEFAULT 0, active INTEGER DEFAULT 1,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
)''')

added = 0
skipped = 0
for name in SITES:
    existing = conn.execute(
        'SELECT id FROM sites WHERE name=? AND client_name=?', (name, CLIENT)
    ).fetchone()
    if existing:
        skipped += 1
    else:
        conn.execute(
            'INSERT INTO sites (id, name, client_name, address, default_rate) VALUES (?,?,?,?,?)',
            (str(uuid.uuid4()), name, CLIENT, '', 0.0)
        )
        added += 1

conn.commit()
conn.close()

print(f"\n  Done! Added {added} sites, skipped {skipped} already existing.")
print(f"  All {len(SITES)} Prime VIC sites are now in your database.")
print(f"\n  You can set rates per site in the admin dashboard under Rates.\n")
