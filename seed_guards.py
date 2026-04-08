#!/usr/bin/env python3
"""
Run this once to pre-load all guards into your database.
Usage:  py seed_guards.py
"""

import sqlite3, os, uuid

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH  = os.path.join(BASE_DIR, 'data', 'security.db')

GUARDS = [
    "Aaditya Sihag",
    "Aaliyan Mehmood",
    "Ahmed Khalid Ilyas",
    "Ahmet Oguzhan Uysal",
    "Aitazaz Ahsan",
    "Alan Doski",
    "Ali Hussaini",
    "Amaan Husaain",
    "Ammad Hassan",
    "Arjunveer Parmar",
    "Asad ullah Saleem",
    "Ashish Kumar",
    "Awis Kakar",
    "Azan Syed",
    "Chirag Mehta",
    "Chris Peniamina Kalauati",
    "Darooj Karmani",
    "David Alyas",
    "Elias Baghdan",
    "Faizan Ahmed",
    "Faizan Ahmed Tk",
    "Georges Zaya",
    "Georgyo Kouifatie",
    "Hajar Golzarmalake",
    "Hamza Rassy",
    "Harmanjot Singh",
    "Harshdeep Singh",
    "Hassan Amir",
    "Hilal Isik",
    "Huzaifa Qureshi",
    "Imran Eren",
    "Ishtiyaq Ahmed",
    "Israfil Sahin",
    "Jaiveer Bhullar",
    "Jamil Asraf Srabon",
    "Jansher Khan",
    "Jasvir Sarai",
    "Jitender Singh",
    "Jobaydur Rahman",
    "Joseph Greige",
    "Julius Malakha",
    "Justin L Elzaibak",
    "Kartikay Sharma",
    "MD Sabbir Hossain",
    "Maisam Akbari",
    "Maninderjeet Singh",
    "Mohamed Abdul-Kadir Hassan",
    "Mohammad Shafai",
    "Mohammad Sultan",
    "Mohammed Shayaq Ali Shahabaz",
    "Mudassar Habib",
    "Muhammad Ansari",
    "Muhammad Hamayoon",
    "Muhammad Shoaib Bin Zahid",
    "Muhammad Wasim Qureshi",
    "Muhammed Gun",
    "Murat Cosar",
    "Musa Kaya",
    "Nadeem Mohammed",
    "Nazhim Kalam",
    "Nikhil Goyal",
    "Noshad Muzaffar",
    "Nuthara Amarasingha",
    "Omar Khan",
    "Paras Nandal",
    "Pardeep Bawa",
    "Pardeep Kumar",
    "Pardeep Singh",
    "Parmeet Singh",
    "Parmjeet Chatrath",
    "Pratham Kaushal",
    "Qasim Rehan",
    "Qudsiya Malik",
    "Rahim Uddin",
    "Rahul Kumar",
    "Raja Noman",
    "Rajat Sharma",
    "Rakan Ali Alsaihati",
    "Rohaib Hassan Shah",
    "Rohit Mahindru",
    "Sadia Khandakar Eshita",
    "Sahil Sahil",
    "Sahil Z82-509-90S",
    "Saied Shohani",
    "Salvatore Francesico Ozzimo",
    "Satwinder Goraya",
    "Sehenur Shanto",
    "Sejal Wahi",
    "Shaheryar Shah",
    "Shahriyar Khan",
    "Shakir Sohail",
    "Sheraz Ahmed",
    "Sukhrajdeep Singh",
    "Surender Berwal",
    "Talha Kolcak",
    "Usama Iqbal",
    "Usama Riaz",
    "Usama arif Khan Niazi",
    "Vivek Shukla",
    "Yousif Abed",
    "Youssef Habib",
    "Yusuf Barwary",
    "Zacharia Najib",
    "Zaid Mohsin Mohammed",
    "Zamin Rezai",
    "Zubair Mohammed",
]

os.makedirs(os.path.join(BASE_DIR, 'data'), exist_ok=True)
conn = sqlite3.connect(DB_PATH)

conn.execute('''CREATE TABLE IF NOT EXISTS guards (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, license_number TEXT,
    license_expiry TEXT, base_rate REAL DEFAULT 0, active INTEGER DEFAULT 1,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
)''')

added = 0
skipped = 0
for name in GUARDS:
    existing = conn.execute('SELECT id FROM guards WHERE name=?', (name,)).fetchone()
    if existing:
        skipped += 1
    else:
        conn.execute(
            'INSERT INTO guards (id, name, license_number, license_expiry, base_rate) VALUES (?,?,?,?,?)',
            (str(uuid.uuid4()), name, '', '', 0.0)
        )
        added += 1

conn.commit()
conn.close()

print(f"\n  Done! Added {added} guards, skipped {skipped} already existing.")
print(f"  All {len(GUARDS)} guards are now in your database.")
print(f"\n  Tip: You can update each guard's license number and rate")
print(f"  in the admin dashboard under the Guards tab.\n")
