#!/usr/bin/env python3
"""
Brown Owl Security — Guard Management System
Production | Multi-Admin | Roles | Audit Log | v3.0
Run:  py server.py  →  http://localhost:5000
"""

import http.server, json, sqlite3, os, uuid, base64, re, io, csv, hashlib, secrets, math
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs

try:
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
    from openpyxl.utils import get_column_letter
    OPENPYXL_OK = True
except ImportError:
    OPENPYXL_OK = False

try:
    from PIL import Image as PILImage
    PIL_OK = True
except ImportError:
    PIL_OK = False

# ─── Config ───────────────────────────────────────────────────────────────────
PORT         = int(os.environ.get('PORT', 5000))
BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
DATA_DIR     = os.environ.get('DATA_DIR', BASE_DIR)
DB_PATH      = os.path.join(DATA_DIR, 'data', 'security.db')
UPLOADS_PATH = os.path.join(DATA_DIR, 'uploads')
PUBLIC_PATH  = os.path.join(BASE_DIR, 'public')
COMPANY_NAME = os.environ.get('COMPANY_NAME', 'Brown Owl Security (BOS)')
# Default superadmin — used only on first run when no admins exist
DEFAULT_ADMIN_EMAIL    = os.environ.get('ADMIN_EMAIL',    'usamariax0349@gmail.com')
DEFAULT_ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin123')
DEFAULT_ADMIN_NAME     = os.environ.get('ADMIN_NAME',     'Super Admin')
APP_URL      = os.environ.get('APP_URL', f'http://localhost:{int(os.environ.get("PORT", 5000))}')

# ─── SMTP (optional — set env vars to enable email notifications) ─────────────
SMTP_HOST = os.environ.get('SMTP_HOST', '')
SMTP_PORT = int(os.environ.get('SMTP_PORT', '587'))
SMTP_USER = os.environ.get('SMTP_USER', '')
SMTP_PASS = os.environ.get('SMTP_PASS', '')
SMTP_FROM = os.environ.get('SMTP_FROM', SMTP_USER)

os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
os.makedirs(UPLOADS_PATH, exist_ok=True)

sessions = {}   # token → {admin_id, role, name, email}

# ─── Password Hashing ─────────────────────────────────────────────────────────
def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100_000)
    return h.hex(), salt

def verify_password(password, stored_hash, salt):
    h, _ = hash_password(password, salt)
    return h == stored_hash

# ─── Geolocation ──────────────────────────────────────────────────────────────
def haversine_m(lat1, lng1, lat2, lng2):
    """Great-circle distance between two points in metres."""
    R = 6371000
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lng2 - lng1)
    a = math.sin(dp/2)**2 + math.cos(p1)*math.cos(p2)*math.sin(dl/2)**2
    return 2 * R * math.asin(math.sqrt(a))

# ─── Shift scheduling / live status ──────────────────────────────────────────
CLOCK_IN_GRACE_MINUTES = 30

def shift_status(row, now=None):
    """Computed live status for a scheduled shift — never stored, always derived."""
    now = now or datetime.now()
    if row.get('cancelled'):
        return 'cancelled'
    if row.get('clock_out_at'):
        return 'completed'
    if row.get('clock_in_at'):
        return 'in_progress'
    try:
        start_dt = datetime.strptime(f"{row['shift_date']} {row['start_time']}", '%Y-%m-%d %H:%M')
    except ValueError:
        return 'scheduled'
    if now > start_dt + timedelta(minutes=CLOCK_IN_GRACE_MINUTES):
        return 'missed'
    return 'scheduled'

def with_shift_status(rows):
    now = datetime.now()
    for r in rows:
        r['status'] = shift_status(r, now)
    return rows

# ─── Email ────────────────────────────────────────────────────────────────────
def send_email(to_email, subject, body_text):
    """Send a plain-text email via SMTP. Silently skips if SMTP is not configured."""
    if not SMTP_HOST or not SMTP_USER:
        print(f"  EMAIL: SMTP not configured — skipping notification to {to_email}")
        return False
    try:
        msg = MIMEText(body_text, 'plain')
        msg['Subject'] = subject
        msg['From']    = SMTP_FROM
        msg['To']      = to_email
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.ehlo()
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
        print(f"  EMAIL: Sent '{subject}' to {to_email}")
        return True
    except Exception as e:
        print(f"  EMAIL: Failed to send to {to_email}: {e}")
        return False

# ─── Database ─────────────────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.executescript('''
        CREATE TABLE IF NOT EXISTS admins (
            id           TEXT PRIMARY KEY,
            name         TEXT NOT NULL,
            email        TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            salt         TEXT NOT NULL,
            role                 TEXT DEFAULT 'manager',
            active               INTEGER DEFAULT 1,
            must_change_password INTEGER DEFAULT 0,
            last_login           TEXT,
            created_at           TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE UNIQUE INDEX IF NOT EXISTS admins_email ON admins(email);

        CREATE TABLE IF NOT EXISTS guards (
            id             TEXT PRIMARY KEY,
            name           TEXT NOT NULL,
            license_number TEXT,
            base_rate      REAL DEFAULT 0,
            phone          TEXT,
            email          TEXT,
            notes          TEXT,
            active         INTEGER DEFAULT 1,
            created_at     TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS sites (
            id            TEXT PRIMARY KEY,
            name          TEXT NOT NULL,
            client_name   TEXT NOT NULL,
            address       TEXT,
            default_rate  REAL DEFAULT 0,
            contact_name  TEXT,
            contact_phone TEXT,
            active        INTEGER DEFAULT 1,
            created_at    TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS rates (
            guard_id TEXT,
            site_id  TEXT,
            rate     REAL NOT NULL,
            PRIMARY KEY (guard_id, site_id)
        );

        CREATE TABLE IF NOT EXISTS submissions (
            id             TEXT PRIMARY KEY,
            guard_id       TEXT NOT NULL,
            site_id        TEXT NOT NULL,
            shift_date     TEXT NOT NULL,
            start_time     TEXT NOT NULL,
            end_time       TEXT NOT NULL,
            total_hours    REAL NOT NULL,
            notes          TEXT,
            photo_filename TEXT,
            status         TEXT DEFAULT 'pending',
            admin_note     TEXT,
            reviewed_by    TEXT,
            submitted_at   TEXT DEFAULT CURRENT_TIMESTAMP,
            reviewed_at    TEXT
        );

        CREATE TABLE IF NOT EXISTS reminders (
            id         TEXT PRIMARY KEY,
            guard_id   TEXT NOT NULL,
            message    TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            seen_at    TEXT
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id         TEXT PRIMARY KEY,
            admin_id   TEXT,
            admin_name TEXT,
            action     TEXT NOT NULL,
            details    TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS checkpoints (
            id         TEXT PRIMARY KEY,
            site_id    TEXT NOT NULL,
            name       TEXT NOT NULL,
            lat        REAL NOT NULL,
            lng        REAL NOT NULL,
            radius_m   INTEGER DEFAULT 40,
            sort_order INTEGER DEFAULT 0,
            active     INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS checkpoint_scans (
            id              TEXT PRIMARY KEY,
            checkpoint_id   TEXT NOT NULL,
            checkpoint_name TEXT,
            guard_id        TEXT NOT NULL,
            site_id         TEXT NOT NULL,
            lat             REAL,
            lng             REAL,
            distance_m      REAL,
            scanned_at      TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS incidents (
            id             TEXT PRIMARY KEY,
            guard_id       TEXT NOT NULL,
            site_id        TEXT NOT NULL,
            type           TEXT NOT NULL,
            description    TEXT,
            photo_filename TEXT,
            lat            REAL,
            lng            REAL,
            status         TEXT DEFAULT 'open',
            admin_note     TEXT,
            reviewed_by    TEXT,
            occurred_at    TEXT DEFAULT CURRENT_TIMESTAMP,
            reviewed_at    TEXT
        );

        CREATE TABLE IF NOT EXISTS client_sites (
            admin_id TEXT NOT NULL,
            site_id  TEXT NOT NULL,
            PRIMARY KEY (admin_id, site_id)
        );

        CREATE TABLE IF NOT EXISTS shifts (
            id                  TEXT PRIMARY KEY,
            guard_id            TEXT NOT NULL,
            site_id             TEXT NOT NULL,
            shift_date          TEXT NOT NULL,
            start_time          TEXT NOT NULL,
            end_time            TEXT NOT NULL,
            position            TEXT DEFAULT '',
            notes               TEXT DEFAULT '',
            clock_in_at         TEXT,
            clock_in_lat        REAL,
            clock_in_lng        REAL,
            clock_in_verified   INTEGER DEFAULT 0,
            clock_out_at        TEXT,
            clock_out_lat       REAL,
            clock_out_lng       REAL,
            clock_out_verified  INTEGER DEFAULT 0,
            submission_id       TEXT,
            cancelled           INTEGER DEFAULT 0,
            created_by          TEXT,
            created_at          TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS guard_site_prefs (
            guard_id TEXT NOT NULL,
            site_id  TEXT NOT NULL,
            pref     TEXT NOT NULL,
            PRIMARY KEY (guard_id, site_id)
        );

        CREATE TABLE IF NOT EXISTS compliance_items (
            id         TEXT PRIMARY KEY,
            name       TEXT NOT NULL,
            sort_order INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS guard_compliance (
            id               TEXT PRIMARY KEY,
            guard_id         TEXT NOT NULL,
            item_id          TEXT NOT NULL,
            checked          INTEGER DEFAULT 0,
            reference_no     TEXT DEFAULT '',
            expiry_date      TEXT,
            reminder_days    INTEGER DEFAULT 60,
            critical         INTEGER DEFAULT 0,
            file_filename    TEXT,
            show_to_customer INTEGER DEFAULT 0,
            UNIQUE(guard_id, item_id)
        );

        CREATE TABLE IF NOT EXISTS guard_leave (
            id         TEXT PRIMARY KEY,
            guard_id   TEXT NOT NULL,
            leave_type TEXT NOT NULL DEFAULT 'Fixed Leave',
            start_date TEXT NOT NULL,
            end_date   TEXT NOT NULL,
            notes      TEXT DEFAULT '',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
    ''')
    conn.commit()

    # Seed the standard compliance catalog once (id-based, so admins can't
    # accidentally duplicate it across restarts)
    COMPLIANCE_CATALOG = ['Covid-19 Vaccination','CPR Accreditation','Crowd Control Card',
        "Driver's Licence",'Firearms Licence','First Aid Certificate','Responsible Service of Alcohol',
        'VISA','White Card','Working With Children Check']
    if conn.execute('SELECT COUNT(*) FROM compliance_items').fetchone()[0] == 0:
        for i, name in enumerate(COMPLIANCE_CATALOG):
            conn.execute('INSERT INTO compliance_items (id,name,sort_order) VALUES (?,?,?)',
                         (str(uuid.uuid4()), name, i))
        conn.commit()

    # ── Schema migration: add any missing columns from older databases ──────────
    migrations = [
        # guards table new columns
        ("guards",      "phone",         "ALTER TABLE guards ADD COLUMN phone TEXT DEFAULT ''"),
        ("guards",      "email",         "ALTER TABLE guards ADD COLUMN email TEXT DEFAULT ''"),
        ("guards",      "notes",         "ALTER TABLE guards ADD COLUMN notes TEXT DEFAULT ''"),
        # sites table new columns
        ("sites",       "contact_name",  "ALTER TABLE sites ADD COLUMN contact_name TEXT DEFAULT ''"),
        ("sites",       "contact_phone", "ALTER TABLE sites ADD COLUMN contact_phone TEXT DEFAULT ''"),
        # submissions table new columns
        ("submissions", "admin_note",    "ALTER TABLE submissions ADD COLUMN admin_note TEXT DEFAULT ''"),
        ("submissions", "reviewed_by",   "ALTER TABLE submissions ADD COLUMN reviewed_by TEXT DEFAULT ''"),
        # admins table
        ("admins", "last_login",           "ALTER TABLE admins ADD COLUMN last_login TEXT"),
        ("admins", "must_change_password", "ALTER TABLE admins ADD COLUMN must_change_password INTEGER DEFAULT 0"),
        # sites table — geofence for GPS sign-in verification
        ("sites", "lat",             "ALTER TABLE sites ADD COLUMN lat REAL"),
        ("sites", "lng",             "ALTER TABLE sites ADD COLUMN lng REAL"),
        ("sites", "geofence_radius", "ALTER TABLE sites ADD COLUMN geofence_radius INTEGER DEFAULT 200"),
        # submissions table — captured sign-in location
        ("submissions", "lat",               "ALTER TABLE submissions ADD COLUMN lat REAL"),
        ("submissions", "lng",               "ALTER TABLE submissions ADD COLUMN lng REAL"),
        ("submissions", "distance_m",        "ALTER TABLE submissions ADD COLUMN distance_m REAL"),
        ("submissions", "location_verified", "ALTER TABLE submissions ADD COLUMN location_verified INTEGER DEFAULT 0"),
        # shifts table — draft/publish workflow for the roster grid.
        # DEFAULT 1 so shifts that already exist (and were already visible to
        # guards) stay visible; new shifts are inserted with published=0 explicitly.
        ("shifts", "published", "ALTER TABLE shifts ADD COLUMN published INTEGER DEFAULT 1"),
        # guards table — security licence detail + scheduling flags
        ("guards", "license_state",         "ALTER TABLE guards ADD COLUMN license_state TEXT DEFAULT ''"),
        ("guards", "license_expiry",        "ALTER TABLE guards ADD COLUMN license_expiry TEXT"),
        ("guards", "license_reminder_days", "ALTER TABLE guards ADD COLUMN license_reminder_days INTEGER DEFAULT 60"),
        ("guards", "license_critical",      "ALTER TABLE guards ADD COLUMN license_critical INTEGER DEFAULT 0"),
        ("guards", "license_file",          "ALTER TABLE guards ADD COLUMN license_file TEXT"),
        ("guards", "hide_on_schedule",      "ALTER TABLE guards ADD COLUMN hide_on_schedule INTEGER DEFAULT 0"),
        ("guards", "no_license_required",   "ALTER TABLE guards ADD COLUMN no_license_required INTEGER DEFAULT 0"),
    ]
    existing_cols = {}
    for table, col, sql in migrations:
        if table not in existing_cols:
            existing_cols[table] = {r[1] for r in conn.execute(f'PRAGMA table_info({table})').fetchall()}
        if col not in existing_cols[table]:
            conn.execute(sql)
            existing_cols[table].add(col)
            print(f'  Migrated: added {table}.{col}')
    conn.commit()

    # ── Roster seed for the week of 31 Aug – 6 Sep 2026 ──────────────────────
    # seed_data.py (run by the Procfile before this script, on every startup)
    # already loads the full 108-guard/60-site roster, including almost
    # everyone/everywhere below — so this only adds the names genuinely
    # missing from that master list, matched per-name (idempotent on every
    # restart), then the 2 shifts with a confirmed end time from the source
    # roster screenshots. A few names differ only by a middle name/initial
    # in seed_data.py's list (aliased below to the existing record instead
    # of creating a near-duplicate person).
    NAME_ALIASES = {
        'Ahmed Ilyas':        'Ahmed Khalid Ilyas',
        'Usama Khan Niazi':   'Usama arif Khan Niazi',
        'Justin Elzaibak':    'Justin L Elzaibak',
    }
    NEW_GUARDS = ['Abdullah Sajjad', 'Harman (BOS)', 'Shoaib Sherani', 'Faraz Ahmed Kazi',
                  'Sandeep Singh', 'Aman Verma', 'Vikramjeet Singh', 'Rohan Sharma']
    added_guards = 0
    for name in NEW_GUARDS:
        if not conn.execute('SELECT 1 FROM guards WHERE name=?', (name,)).fetchone():
            conn.execute('INSERT INTO guards (id,name) VALUES (?,?)', (str(uuid.uuid4()), name))
            added_guards += 1
    NEW_SITES = [('Skinny Dog Hotel', 'Prime VIC')]  # matches the client_name seed_data.py uses for its siblings
    added_sites = 0
    for name, client in NEW_SITES:
        if not conn.execute('SELECT 1 FROM sites WHERE name=?', (name,)).fetchone():
            conn.execute('INSERT INTO sites (id,name,client_name) VALUES (?,?,?)',
                         (str(uuid.uuid4()), name, client))
            added_sites += 1
    conn.commit()

    def _resolve_guard_id(name):
        row = conn.execute('SELECT id FROM guards WHERE name=?',
                            (NAME_ALIASES.get(name, name),)).fetchone()
        return row[0] if row else None
    def _resolve_site_id(name):
        row = conn.execute('SELECT id FROM sites WHERE name=?', (name,)).fetchone()
        return row[0] if row else None

    SEED_SHIFTS = [
        ('Usama Riaz',   'Anglers Tavern',   '2026-09-06', '06:30', '10:30'),
        ('Rohan Sharma', 'Skinny Dog Hotel', '2026-09-05', '19:00', '23:00'),
    ]
    seeded_shifts = 0
    for guard_name, site_name, d, st, et in SEED_SHIFTS:
        gid, sid = _resolve_guard_id(guard_name), _resolve_site_id(site_name)
        if not gid or not sid:
            print(f'  WARNING: could not seed shift for {guard_name} @ {site_name} — guard or site not found')
            continue
        if not conn.execute('''SELECT 1 FROM shifts WHERE guard_id=? AND site_id=?
                                AND shift_date=? AND start_time=?''', (gid, sid, d, st)).fetchone():
            # published=1: this reflects an already-existing roster guards already
            # know about, not a new draft needing Publish & Notify.
            conn.execute('''INSERT INTO shifts (id,guard_id,site_id,shift_date,start_time,end_time,published)
                            VALUES (?,?,?,?,?,?,1)''', (str(uuid.uuid4()), gid, sid, d, st, et))
            seeded_shifts += 1
    conn.commit()
    print(f'  Roster seed: {added_guards} new guards, {added_sites} new sites, {seeded_shifts} shifts added')

    # Always ensure the superadmin from env vars exists with correct password
    h, salt = hash_password(DEFAULT_ADMIN_PASSWORD)
    existing = conn.execute('SELECT id FROM admins WHERE email=?',
                            (DEFAULT_ADMIN_EMAIL.lower(),)).fetchone()
    if existing:
        conn.execute('''UPDATE admins SET password_hash=?, salt=?, role='superadmin', active=1
                        WHERE email=?''', (h, salt, DEFAULT_ADMIN_EMAIL.lower()))
        print(f'  Superadmin password synced: {DEFAULT_ADMIN_EMAIL}')
    else:
        conn.execute('''INSERT INTO admins (id,name,email,password_hash,salt,role)
                        VALUES (?,?,?,?,?,'superadmin')''',
                     (str(uuid.uuid4()), DEFAULT_ADMIN_NAME, DEFAULT_ADMIN_EMAIL.lower(), h, salt))
        print(f'  Superadmin created: {DEFAULT_ADMIN_EMAIL}')
    conn.commit()
    conn.close()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def R(row):  return dict(row) if row else None
def RL(rows): return [dict(r) for r in rows]

def audit(conn, session, action, details=''):
    conn.execute('INSERT INTO audit_log (id,admin_id,admin_name,action,details) VALUES (?,?,?,?,?)',
                 (str(uuid.uuid4()), session.get('admin_id',''), session.get('name',''),
                  action, details))

# ─── Invoice helpers ──────────────────────────────────────────────────────────
def invoice_query(qs):
    params, where = [], ["sub.status='approved'"]
    if qs.get('client_name'): where.append('s.client_name=?');    params.append(qs['client_name'][0])
    if qs.get('site_id'):     where.append('sub.site_id=?');       params.append(qs['site_id'][0])
    if qs.get('date_from'):   where.append('sub.shift_date>=?');   params.append(qs['date_from'][0])
    if qs.get('date_to'):     where.append('sub.shift_date<=?');   params.append(qs['date_to'][0])
    db   = get_db()
    rows = RL(db.execute(f'''
        SELECT sub.*, g.name as guard_name, s.name as site_name, s.client_name,
               COALESCE(r.rate, g.base_rate) as rate
        FROM submissions sub
        JOIN guards g ON g.id=sub.guard_id
        JOIN sites  s ON s.id=sub.site_id
        LEFT JOIN rates r ON r.guard_id=sub.guard_id AND r.site_id=sub.site_id
        WHERE {" AND ".join(where)}
        ORDER BY sub.shift_date ASC, g.name ASC
    ''', params).fetchall())
    db.close()
    for r in rows:
        r['amount'] = round(r['total_hours'] * r['rate'], 2)
    return rows, round(sum(r['amount'] for r in rows), 2)

# ─── PDF Generator ────────────────────────────────────────────────────────────
def make_pdf(rows, client_name, date_from, date_to, total):
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib import colors
    navy = colors.HexColor('#1a2744'); gold = colors.HexColor('#c9a84c')
    lg   = colors.HexColor('#f1f5f9')
    buf  = io.BytesIO()
    doc  = SimpleDocTemplate(buf, pagesize=A4, leftMargin=20*mm, rightMargin=20*mm,
                              topMargin=20*mm, bottomMargin=20*mm)
    ss   = getSampleStyleSheet()
    def P(txt, **kw): return Paragraph(txt, ParagraphStyle('x', parent=ss['Normal'], **kw))
    story = [
        P(COMPANY_NAME, fontSize=22, textColor=navy, fontName='Helvetica-Bold', spaceAfter=2),
        P('Security Services', fontSize=10, textColor=colors.HexColor('#64748b')),
        Spacer(1, 8*mm),
    ]
    inv_no = f"INV-{datetime.now().strftime('%Y%m%d%H%M')}"
    meta   = Table([['INVOICE', inv_no],['Date:', datetime.now().strftime('%d/%m/%Y')],
                    ['Period:', f"{date_from} — {date_to}"],['Bill To:', client_name]],
                   colWidths=[35*mm, 100*mm])
    meta.setStyle(TableStyle([
        ('FONTNAME',(0,0),(0,0),'Helvetica-Bold'),('FONTSIZE',(0,0),(0,0),14),
        ('TEXTCOLOR',(0,0),(0,0),navy),('FONTNAME',(1,0),(1,0),'Helvetica-Bold'),
        ('FONTSIZE',(1,0),(1,0),14),('TEXTCOLOR',(1,0),(1,0),gold),
        ('FONTNAME',(0,1),(0,-1),'Helvetica-Bold'),('FONTSIZE',(0,1),(0,-1),9),
        ('TEXTCOLOR',(0,1),(0,-1),colors.HexColor('#64748b')),
        ('FONTSIZE',(1,1),(1,-1),10),('TEXTCOLOR',(1,1),(1,-1),navy),
        ('BOTTOMPADDING',(0,0),(-1,-1),3),
    ]))
    story += [meta, Spacer(1,8*mm)]
    hdrs = ['Date','Guard','Site','Start','End','Hrs','Rate','Amount']
    td   = [hdrs] + [[r['shift_date'],r['guard_name'],r['site_name'],
                       r['start_time'],r['end_time'],f"{r['total_hours']:.2f}",
                       f"${r['rate']:.2f}",f"${r['amount']:.2f}"] for r in rows]
    cw   = [22*mm,35*mm,35*mm,16*mm,16*mm,14*mm,20*mm,22*mm]
    t    = Table(td, colWidths=cw, repeatRows=1)
    t.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0),navy),('TEXTCOLOR',(0,0),(-1,0),colors.white),
        ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),('FONTSIZE',(0,0),(-1,0),8),
        ('ALIGN',(0,0),(-1,0),'CENTER'),('BOTTOMPADDING',(0,0),(-1,0),6),
        ('TOPPADDING',(0,0),(-1,0),6),('FONTSIZE',(0,1),(-1,-1),8),
        ('TEXTCOLOR',(0,1),(-1,-1),colors.HexColor('#1e293b')),
        ('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,lg]),
        ('ALIGN',(5,1),(-1,-1),'RIGHT'),('BOTTOMPADDING',(0,1),(-1,-1),5),
        ('TOPPADDING',(0,1),(-1,-1),5),
        ('GRID',(0,0),(-1,-1),0.3,colors.HexColor('#e2e8f0')),
        ('LINEBELOW',(0,0),(-1,0),1,navy),
    ]))
    story += [t, Spacer(1,6*mm)]
    total_tbl = Table([['','','','','','','TOTAL HOURS:',f"{sum(r['total_hours'] for r in rows):.2f}"],
                        ['','','','','','','TOTAL DUE:',f'${total:.2f} AUD']],
                       colWidths=cw)
    total_tbl.setStyle(TableStyle([
        ('FONTNAME',(6,0),(7,1),'Helvetica-Bold'),('FONTSIZE',(6,0),(7,1),10),
        ('TEXTCOLOR',(6,0),(6,1),colors.HexColor('#64748b')),
        ('TEXTCOLOR',(7,0),(7,0),colors.HexColor('#1a2744')),
        ('TEXTCOLOR',(7,1),(7,1),navy),('FONTSIZE',(7,1),(7,1),12),
        ('ALIGN',(6,0),(7,1),'RIGHT'),
        ('LINEABOVE',(6,0),(7,1),1.5,navy),('TOPPADDING',(0,0),(-1,-1),4),
    ]))
    story += [total_tbl, Spacer(1,10*mm),
              P('Thank you for your business.', fontSize=10, textColor=colors.HexColor('#64748b')),
              P('Payment due within 30 days of invoice date.', fontSize=10,
                textColor=colors.HexColor('#64748b'))]
    doc.build(story)
    buf.seek(0)
    return buf.read()

# ─── Excel Generator ──────────────────────────────────────────────────────────
def make_xlsx(rows, client_name, date_from, date_to, total):
    wb   = Workbook()
    ws   = wb.active
    ws.title = 'Invoice'
    nvf  = PatternFill('solid', fgColor='1A2744')
    grf  = PatternFill('solid', fgColor='F1F5F9')
    whtF = Font(color='FFFFFF', bold=True, size=11)
    thin = Side(style='thin', color='CBD5E1')
    brd  = Border(left=thin, right=thin, top=thin, bottom=thin)
    ctr  = Alignment(horizontal='center', vertical='center')
    rgt  = Alignment(horizontal='right',  vertical='center')
    mid  = Alignment(vertical='center')
    def cell(r, c, val, font=None, fill=None, align=None, border=None):
        ce = ws.cell(r, c, val)
        if font:   ce.font   = font
        if fill:   ce.fill   = fill
        if align:  ce.alignment = align
        if border: ce.border = border
        return ce
    ws.merge_cells('A1:I1')
    cell(1,1, COMPANY_NAME, font=Font(color='1A2744',bold=True,size=16), align=ctr)
    ws.row_dimensions[1].height = 32
    ws.merge_cells('A2:I2')
    cell(2,1, 'Security Services Invoice', font=Font(color='64748B',size=11), align=ctr)
    ws.row_dimensions[2].height = 20
    ws.append([])
    inv_no = f"INV-{datetime.now().strftime('%Y%m%d%H%M')}"
    for la, va, le, ve in [('Invoice #:', inv_no, 'Date:', datetime.now().strftime('%d/%m/%Y')),
                            ('Period:', f"{date_from or '—'} — {date_to or '—'}",
                             'Bill To:', client_name or 'All Clients')]:
        ws.append([la, va, '', '', le, ve])
        r = ws.max_row
        for c, fnt in [(1, Font(color='64748B',bold=True,size=9)),
                       (2, Font(color='1A2744',size=10)),
                       (5, Font(color='64748B',bold=True,size=9)),
                       (6, Font(color='1A2744',size=10))]:
            ws.cell(r, c).font = fnt
    ws.append([])
    hdrs = ['Date','Guard','Site','Client','Start','End','Hours','Rate (AUD)','Amount (AUD)']
    ws.append(hdrs)
    hr = ws.max_row
    for c in range(1, len(hdrs)+1):
        ws.cell(hr,c).fill   = nvf
        ws.cell(hr,c).font   = whtF
        ws.cell(hr,c).alignment = ctr
        ws.cell(hr,c).border = brd
    ws.row_dimensions[hr].height = 22
    total_hrs = 0
    for i, r in enumerate(rows):
        ws.append([r['shift_date'],r['guard_name'],r['site_name'],r['client_name'],
                   r['start_time'],r['end_time'],
                   round(r['total_hours'],2), round(r['rate'],2), r['amount']])
        total_hrs += r['total_hours']
        dr = ws.max_row
        fl = grf if i % 2 == 1 else None
        for c in range(1, len(hdrs)+1):
            ce = ws.cell(dr, c)
            if fl: ce.fill = fl
            ce.border = brd
            ce.alignment = rgt if c >= 7 else mid
        ws.row_dimensions[dr].height = 18
    top_b = Border(top=Side(style='medium', color='1A2744'))
    for label, val in [('TOTAL HOURS:', f"{total_hrs:.2f}"), ('TOTAL DUE:', f'${total:,.2f} AUD')]:
        ws.append(['','','','','','','',label,val])
        r = ws.max_row
        ws.cell(r,8).font = Font(color='64748B',bold=True,size=11)
        ws.cell(r,9).font = Font(color='1A2744',bold=True,size=12)
        ws.cell(r,8).alignment = rgt; ws.cell(r,9).alignment = rgt
        ws.cell(r,8).border = top_b; ws.cell(r,9).border = top_b
        ws.row_dimensions[r].height = 22
    for c, w in enumerate([12,22,22,16,8,8,8,14,15], 1):
        ws.column_dimensions[get_column_letter(c)].width = w
    xb = io.BytesIO(); wb.save(xb); xb.seek(0)
    return xb.read()

# ─── Reports hub ──────────────────────────────────────────────────────────────
def rows_to_csv(headers, rows):
    buf = io.StringIO(); w = csv.writer(buf)
    w.writerow(headers)
    for r in rows: w.writerow(r)
    return ('\ufeff'+buf.getvalue()).encode('utf-8')

def rows_to_xlsx(headers, rows, title='Report'):
    wb = Workbook(); ws = wb.active; ws.title = (title[:31] or 'Report')
    navy = PatternFill('solid', fgColor='1A2744')
    white_bold = Font(color='FFFFFF', bold=True, size=11)
    ws.append(headers)
    for c in range(1, len(headers)+1):
        ce = ws.cell(1, c); ce.fill = navy; ce.font = white_bold
    for r in rows: ws.append(r)
    for i, h in enumerate(headers, 1):
        vals = [str(h)] + [str(r[i-1]) for r in rows]
        ws.column_dimensions[get_column_letter(i)].width = min(max(max(len(v) for v in vals)+2, 10), 40)
    buf = io.BytesIO(); wb.save(buf); buf.seek(0)
    return buf.read()

def _date_where(qs, col, where, params):
    if qs.get('date_from'): where.append(f'{col}>=?'); params.append(qs['date_from'][0])
    if qs.get('date_to'):   where.append(f'{col}<=?'); params.append(qs['date_to'][0])

def report_schedule_by_guard(qs):
    where, params = ['sh.cancelled=0'], []
    _date_where(qs, 'sh.shift_date', where, params)
    db = get_db()
    rows = with_shift_status(RL(db.execute(f'''
        SELECT sh.*, g.name as guard_name, s.name as site_name, s.client_name
        FROM shifts sh JOIN guards g ON g.id=sh.guard_id JOIN sites s ON s.id=sh.site_id
        WHERE {" AND ".join(where)} ORDER BY g.name, sh.shift_date, sh.start_time
    ''', params).fetchall()))
    db.close()
    headers = ['Guard','Site','Client','Date','Start','End','Position','Status']
    data = [[r['guard_name'],r['site_name'],r['client_name'],r['shift_date'],
             r['start_time'],r['end_time'],r['position'] or '—',r['status']] for r in rows]
    return headers, data

def report_schedule_by_site(qs):
    where, params = ['sh.cancelled=0'], []
    _date_where(qs, 'sh.shift_date', where, params)
    db = get_db()
    rows = with_shift_status(RL(db.execute(f'''
        SELECT sh.*, g.name as guard_name, s.name as site_name, s.client_name
        FROM shifts sh JOIN guards g ON g.id=sh.guard_id JOIN sites s ON s.id=sh.site_id
        WHERE {" AND ".join(where)} ORDER BY s.name, sh.shift_date, sh.start_time
    ''', params).fetchall()))
    db.close()
    headers = ['Site','Client','Guard','Date','Start','End','Position','Status']
    data = [[r['site_name'],r['client_name'],r['guard_name'],r['shift_date'],
             r['start_time'],r['end_time'],r['position'] or '—',r['status']] for r in rows]
    return headers, data

def report_timesheet_approved(qs):
    where, params = ["sub.status='approved'"], []
    _date_where(qs, 'sub.shift_date', where, params)
    db = get_db()
    rows = RL(db.execute(f'''
        SELECT sub.*, g.name as guard_name, g.license_number, s.name as site_name, s.client_name,
               COALESCE(r.rate, g.base_rate) as rate
        FROM submissions sub
        JOIN guards g ON g.id=sub.guard_id
        JOIN sites  s ON s.id=sub.site_id
        LEFT JOIN rates r ON r.guard_id=sub.guard_id AND r.site_id=sub.site_id
        WHERE {" AND ".join(where)} ORDER BY sub.shift_date, g.name
    ''', params).fetchall())
    db.close()
    headers = ['Date','Guard','Licence #','Site','Client','Start','End','Hours','Rate','Amount','Verified']
    data = [[r['shift_date'], r['guard_name'], r['license_number'] or '—', r['site_name'], r['client_name'],
             r['start_time'], r['end_time'], r['total_hours'], r['rate'],
             round(r['total_hours']*r['rate'],2), 'Yes' if r.get('location_verified') else 'No'] for r in rows]
    return headers, data

def report_timesheet_with_notes(qs):
    where, params = ["sub.status='approved'"], []
    _date_where(qs, 'sub.shift_date', where, params)
    db = get_db()
    rows = RL(db.execute(f'''
        SELECT sub.*, g.name as guard_name, s.name as site_name
        FROM submissions sub JOIN guards g ON g.id=sub.guard_id JOIN sites s ON s.id=sub.site_id
        WHERE {" AND ".join(where)} ORDER BY sub.shift_date, g.name
    ''', params).fetchall())
    db.close()
    headers = ['Date','Guard','Site','Start','End','Hours','Notes']
    data = [[r['shift_date'], r['guard_name'], r['site_name'], r['start_time'], r['end_time'],
             r['total_hours'], r['notes'] or ''] for r in rows]
    return headers, data

def report_activity_slip(qs):
    rows, total = invoice_query(qs)
    headers = ['Date','Guard','Site','Client','Start','End','Hours','Rate','Amount']
    data = [[r['shift_date'],r['guard_name'],r['site_name'],r['client_name'],
             r['start_time'],r['end_time'],r['total_hours'],r['rate'],r['amount']] for r in rows]
    data.append(['','','','','','','','TOTAL', round(total,2)])
    return headers, data

def report_live_operations(qs):
    today = datetime.now().strftime('%Y-%m-%d')
    where, params = ['sh.cancelled=0'], []
    where.append('sh.shift_date>=?'); params.append(qs.get('date_from',[today])[0])
    where.append('sh.shift_date<=?'); params.append(qs.get('date_to',[today])[0])
    db = get_db()
    rows = with_shift_status(RL(db.execute(f'''
        SELECT sh.*, g.name as guard_name, s.name as site_name, s.client_name
        FROM shifts sh JOIN guards g ON g.id=sh.guard_id JOIN sites s ON s.id=sh.site_id
        WHERE {" AND ".join(where)} ORDER BY sh.shift_date, sh.start_time
    ''', params).fetchall()))
    db.close()
    def verify_label(r):
        if r['status'] not in ('in_progress','completed'): return '—'
        ok = r.get('clock_in_verified') and (r['status']!='completed' or r.get('clock_out_verified'))
        return 'Verified' if ok else 'Unverified'
    headers = ['Site','Guard','Position','Status','Start Time','End Time','Verification']
    data = [[r['site_name'], r['guard_name'], r['position'] or '—', r['status'],
             r['clock_in_at'] or '—', r['clock_out_at'] or '—', verify_label(r)] for r in rows]
    return headers, data

def report_guard_listing(qs):
    db = get_db()
    rows = RL(db.execute('SELECT * FROM guards ORDER BY active DESC, name').fetchall())
    db.close()
    headers = ['Name','Licence #','Phone','Email','Base Rate','Status']
    data = [[r['name'], r['license_number'] or '—', r['phone'] or '—', r['email'] or '—',
             r['base_rate'], 'Active' if r['active'] else 'Inactive'] for r in rows]
    return headers, data

def report_licence(qs):
    db = get_db()
    rows = RL(db.execute('SELECT * FROM guards WHERE active=1 ORDER BY name').fetchall())
    db.close()
    headers = ['Name','Licence #','Phone','Licence On File']
    data = [[r['name'], r['license_number'] or '—', r['phone'] or '—',
             'Yes' if r['license_number'] else 'No'] for r in rows]
    return headers, data

def report_site_listing(qs):
    db = get_db()
    rows = RL(db.execute('SELECT * FROM sites ORDER BY active DESC, client_name, name').fetchall())
    db.close()
    headers = ['Site','Client','Address','Default Rate','Contact Name','Contact Phone','Status']
    data = [[r['name'], r['client_name'], r['address'] or '—', r['default_rate'],
             r['contact_name'] or '—', r['contact_phone'] or '—',
             'Active' if r['active'] else 'Inactive'] for r in rows]
    return headers, data

def report_checkpoints(qs):
    where, params = [], []
    _date_where(qs, 'cs.scanned_at', where, params)
    wc = ('WHERE '+' AND '.join(where)) if where else ''
    db = get_db()
    rows = RL(db.execute(f'''
        SELECT cs.*, g.name as guard_name, s.name as site_name
        FROM checkpoint_scans cs JOIN guards g ON g.id=cs.guard_id JOIN sites s ON s.id=cs.site_id
        {wc} ORDER BY cs.scanned_at DESC
    ''', params).fetchall())
    db.close()
    headers = ['Date/Time','Guard','Site','Checkpoint','Distance (m)']
    data = [[r['scanned_at'], r['guard_name'], r['site_name'], r['checkpoint_name'] or '—',
             round(r['distance_m']) if r['distance_m'] is not None else '—'] for r in rows]
    return headers, data

def report_incidents(qs):
    where, params = [], []
    _date_where(qs, 'i.occurred_at', where, params)
    wc = ('WHERE '+' AND '.join(where)) if where else ''
    db = get_db()
    rows = RL(db.execute(f'''
        SELECT i.*, g.name as guard_name, s.name as site_name
        FROM incidents i JOIN guards g ON g.id=i.guard_id JOIN sites s ON s.id=i.site_id
        {wc} ORDER BY i.occurred_at DESC
    ''', params).fetchall())
    db.close()
    headers = ['Date/Time','Guard','Site','Type','Description','Status']
    data = [[r['occurred_at'], r['guard_name'], r['site_name'], r['type'],
             (r['description'] or ''), r['status']] for r in rows]
    return headers, data

def report_audit(qs):
    where, params = [], []
    _date_where(qs, 'created_at', where, params)
    wc = ('WHERE '+' AND '.join(where)) if where else ''
    db = get_db()
    rows = RL(db.execute(f'SELECT * FROM audit_log {wc} ORDER BY created_at DESC LIMIT 1000', params).fetchall())
    db.close()
    headers = ['Date/Time','Admin','Action','Details']
    data = [[r['created_at'], r['admin_name'] or '—', r['action'], r['details'] or ''] for r in rows]
    return headers, data

REPORTS = {
    'schedule_by_guard': {'category':'Roster Reports','title':'Schedule By Guard',
        'desc':'Generate schedule grouped by guard','fn':report_schedule_by_guard},
    'schedule_by_site': {'category':'Roster Reports','title':'Schedule By Site',
        'desc':'Generate schedule grouped by site','fn':report_schedule_by_site},
    'timesheet_approved': {'category':'Timesheet Reports','title':'Approved Timesheet',
        'desc':'Generate a listing of approved timesheets with pay details','fn':report_timesheet_approved},
    'timesheet_notes': {'category':'Timesheet Reports','title':'Timesheet With Notes',
        'desc':'Generate a listing of approved timesheets including shift notes','fn':report_timesheet_with_notes},
    'activity_slip': {'category':'Activity Reports','title':'Activity Slip',
        'desc':'Generate approved shifts with pay details','fn':report_activity_slip},
    'live_operations': {'category':'Activity Reports','title':'Live Operations Report',
        'desc':'Generate a listing of shifts in the live operations dashboard','fn':report_live_operations},
    'guard_listing': {'category':'Staff Reports','title':'Staff Listing',
        'desc':'Generate a listing of all guards','fn':report_guard_listing},
    'licence': {'category':'Staff Reports','title':'Security Licence Report',
        'desc':'Generate a report for security licences on file','fn':report_licence},
    'site_listing': {'category':'Site Reports','title':'Site Listing',
        'desc':'Generate a listing of all sites and their contacts','fn':report_site_listing},
    'checkpoints': {'category':'Checkpoint Reports','title':'Checkpoint Report',
        'desc':'Generate a listing of all patrol checkpoint scans','fn':report_checkpoints},
    'incidents': {'category':'Incident Reports','title':'Incident Report',
        'desc':'Generate a listing of reported incidents','fn':report_incidents},
    'invoice_report': {'category':'Invoice Reports','title':'Invoice Report',
        'desc':'Generate invoice-ready billing details, optionally filtered by client','fn':report_activity_slip},
    'audit': {'category':'Audit Reports','title':'Audit Log',
        'desc':'Generate a listing of all admin actions','fn':report_audit},
}

# ─── Handler ──────────────────────────────────────────────────────────────────
class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def send_json(self, data, status=200):
        b = json.dumps(data).encode()
        self.send_response(status)
        self.send_header('Content-Type','application/json')
        self.send_header('Content-Length', len(b))
        self.end_headers(); self.wfile.write(b)

    def err(self, msg, status=400): self.send_json({'error': msg}, status)

    def read_json(self):
        n = int(self.headers.get('Content-Length', 0))
        return json.loads(self.rfile.read(n)) if n else {}

    def get_session(self):
        return sessions.get(self.headers.get('X-Auth-Token',''))

    def require_admin(self, min_role=None):
        s = self.get_session()
        if not s: self.err('Unauthorized', 401); return None
        # Client accounts are read-only, site-scoped, and never fall through to admin routes
        if s.get('role') == 'client':
            self.err('Insufficient permissions', 403); return None
        role_rank = {'viewer':0,'manager':1,'administrator':2,'superadmin':3}
        if min_role and role_rank.get(s.get('role',''),0) < role_rank.get(min_role,0):
            self.err('Insufficient permissions', 403); return None
        return s

    def require_client(self):
        s = self.get_session()
        if not s: self.err('Unauthorized', 401); return None
        if s.get('role') != 'client':
            self.err('Insufficient permissions', 403); return None
        if s.get('must_change_password'):
            self.err('Please set your password before continuing', 403); return None
        return s

    def client_site_ids(self, admin_id):
        db = get_db()
        ids = [r['site_id'] for r in db.execute(
            'SELECT site_id FROM client_sites WHERE admin_id=?', (admin_id,)).fetchall()]
        db.close(); return ids

    def serve_file(self, path, ct):
        if not os.path.exists(path):
            self.send_response(404); self.end_headers(); return
        with open(path,'rb') as f: data = f.read()
        self.send_response(200)
        self.send_header('Content-Type', ct)
        self.send_header('Content-Length', len(data))
        self.end_headers(); self.wfile.write(data)

    def send_download(self, data, ct, fname):
        self.send_response(200)
        self.send_header('Content-Type', ct)
        self.send_header('Content-Disposition', f'attachment; filename="{fname}"')
        self.send_header('Content-Length', len(data))
        self.end_headers(); self.wfile.write(data)

    # ── GET ────────────────────────────────────────────────────────────────────
    def do_GET(self):
        p = urlparse(self.path); path = p.path; qs = parse_qs(p.query)

        # ── Static ──
        if path in ('/','/index.html'):
            self.serve_file(os.path.join(PUBLIC_PATH,'index.html'),'text/html'); return
        if path == '/manifest.json':
            self.serve_file(os.path.join(PUBLIC_PATH,'manifest.json'),'application/manifest+json'); return
        if path == '/sw.js':
            self.serve_file(os.path.join(PUBLIC_PATH,'sw.js'),'application/javascript'); return
        if path == '/icon.svg':
            svg = '''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
<rect width="512" height="512" rx="100" fill="#1a2744"/>
<circle cx="256" cy="190" r="110" fill="#c9a84c" opacity="0.15"/>
<text x="256" y="245" font-family="Arial Black" font-weight="900" font-size="160" fill="#c9a84c" text-anchor="middle">B</text>
<text x="256" y="345" font-family="Arial" font-weight="700" font-size="60" fill="rgba(255,255,255,0.7)" text-anchor="middle" letter-spacing="8">OWL</text>
<text x="256" y="405" font-family="Arial" font-size="36" fill="rgba(255,255,255,0.35)" text-anchor="middle" letter-spacing="4">SECURITY</text>
</svg>'''
            b = svg.encode()
            self.send_response(200); self.send_header('Content-Type','image/svg+xml')
            self.send_header('Content-Length',len(b)); self.end_headers(); self.wfile.write(b); return
        if path.startswith('/uploads/'):
            fname = os.path.basename(path); fpath = os.path.join(UPLOADS_PATH,fname)
            ext = fname.rsplit('.',1)[-1].lower() if '.' in fname else 'jpg'
            ct  = {'jpg':'image/jpeg','jpeg':'image/jpeg','png':'image/png',
                   'gif':'image/gif','webp':'image/webp'}.get(ext,'application/octet-stream')
            self.serve_file(fpath, ct); return
        if path == '/logo':
            for ext in ['png','jpg','jpeg','gif','webp','svg']:
                fp = os.path.join(UPLOADS_PATH,f'company_logo.{ext}')
                if os.path.exists(fp):
                    ct = {'png':'image/png','jpg':'image/jpeg','jpeg':'image/jpeg',
                          'gif':'image/gif','webp':'image/webp','svg':'image/svg+xml'}.get(ext)
                    self.serve_file(fp, ct); return
            self.send_response(404); self.end_headers(); return

        # ── API ──
        if path == '/api/config':
            self.send_json({'company_name': COMPANY_NAME}); return

        if path == '/api/guards':
            db = get_db()
            self.send_json(RL(db.execute('SELECT * FROM guards WHERE active=1 ORDER BY name').fetchall()))
            db.close(); return

        if path == '/api/sites':
            db = get_db()
            self.send_json(RL(db.execute('SELECT * FROM sites WHERE active=1 ORDER BY client_name,name').fetchall()))
            db.close(); return

        if path == '/api/reminders':
            gid = qs.get('guard_id',[None])[0]
            if not gid: self.err('guard_id required'); return
            db = get_db()
            self.send_json(RL(db.execute(
                "SELECT * FROM reminders WHERE guard_id=? AND seen_at IS NULL ORDER BY created_at DESC",
                (gid,)).fetchall()))
            db.close(); return

        if path == '/api/checkpoints':
            site_id = qs.get('site_id',[None])[0]
            if not site_id: self.err('site_id required'); return
            db = get_db()
            self.send_json(RL(db.execute(
                'SELECT * FROM checkpoints WHERE site_id=? AND active=1 ORDER BY sort_order, name',
                (site_id,)).fetchall()))
            db.close(); return

        # ── Client portal (read-only, site-scoped) ──
        if path == '/api/client/me':
            s3 = self.require_client()
            if s3 is None: return
            sites = RL(get_db().execute('''
                SELECT s.* FROM sites s JOIN client_sites cs ON cs.site_id=s.id
                WHERE cs.admin_id=? ORDER BY s.name''', (s3['admin_id'],)).fetchall())
            self.send_json({'id':s3['admin_id'],'name':s3['name'],'email':s3['email'],'sites':sites}); return

        if path == '/api/client/activity':
            s3 = self.require_client()
            if s3 is None: return
            site_ids = self.client_site_ids(s3['admin_id'])
            if not site_ids: self.send_json([]); return
            ph = ','.join('?'*len(site_ids))
            db = get_db()
            scans = RL(db.execute(f'''
                SELECT 'checkpoint' as kind, cs.scanned_at as at, cs.checkpoint_name as label,
                       g.name as guard_name, s.name as site_name, cs.distance_m
                FROM checkpoint_scans cs
                JOIN guards g ON g.id=cs.guard_id
                JOIN sites s ON s.id=cs.site_id
                WHERE cs.site_id IN ({ph}) ORDER BY cs.scanned_at DESC LIMIT 100''', site_ids).fetchall())
            incidents = RL(db.execute(f'''
                SELECT 'incident' as kind, i.occurred_at as at, i.type as label,
                       g.name as guard_name, s.name as site_name, i.status
                FROM incidents i
                JOIN guards g ON g.id=i.guard_id
                JOIN sites s ON s.id=i.site_id
                WHERE i.site_id IN ({ph}) ORDER BY i.occurred_at DESC LIMIT 100''', site_ids).fetchall())
            db.close()
            feed = sorted(scans+incidents, key=lambda r:r['at'], reverse=True)[:100]
            self.send_json(feed); return

        if path == '/api/client/incidents':
            s3 = self.require_client()
            if s3 is None: return
            site_ids = self.client_site_ids(s3['admin_id'])
            if not site_ids: self.send_json([]); return
            ph = ','.join('?'*len(site_ids))
            db = get_db()
            rows = RL(db.execute(f'''
                SELECT i.*, g.name as guard_name, s.name as site_name
                FROM incidents i JOIN guards g ON g.id=i.guard_id JOIN sites s ON s.id=i.site_id
                WHERE i.site_id IN ({ph}) ORDER BY i.occurred_at DESC''', site_ids).fetchall())
            db.close(); self.send_json(rows); return

        if path == '/api/client/submissions':
            s3 = self.require_client()
            if s3 is None: return
            site_ids = self.client_site_ids(s3['admin_id'])
            if not site_ids: self.send_json([]); return
            ph = ','.join('?'*len(site_ids))
            db = get_db()
            rows = RL(db.execute(f'''
                SELECT sub.shift_date, sub.start_time, sub.end_time, sub.total_hours, sub.status,
                       sub.location_verified, g.name as guard_name, s.name as site_name
                FROM submissions sub JOIN guards g ON g.id=sub.guard_id JOIN sites s ON s.id=sub.site_id
                WHERE sub.site_id IN ({ph}) AND sub.status='approved'
                ORDER BY sub.shift_date DESC LIMIT 200''', site_ids).fetchall())
            db.close(); self.send_json(rows); return

        if path == '/api/submissions/mine':
            gid = qs.get('guard_id',[None])[0]
            if not gid: self.err('guard_id required'); return
            db = get_db()
            rows = RL(db.execute('''
                SELECT sub.shift_date, sub.start_time, sub.end_time, sub.total_hours,
                       sub.status, sub.submitted_at, s.name as site_name, s.client_name
                FROM submissions sub
                JOIN sites s ON s.id=sub.site_id
                WHERE sub.guard_id=?
                ORDER BY sub.submitted_at DESC LIMIT 8
            ''', (gid,)).fetchall())
            db.close(); self.send_json(rows); return

        # Guard's assigned shifts (roster) — no auth needed
        if path == '/api/shifts/mine':
            gid = qs.get('guard_id',[None])[0]
            if not gid: self.err('guard_id required'); return
            db = get_db()
            rows = RL(db.execute('''
                SELECT sh.*, s.name as site_name, s.client_name, s.address,
                       s.lat as site_lat, s.lng as site_lng, s.geofence_radius
                FROM shifts sh
                JOIN sites s ON s.id=sh.site_id
                WHERE sh.guard_id=? AND sh.shift_date >= date('now','-1 day')
                      AND sh.cancelled=0 AND sh.published=1
                ORDER BY sh.shift_date ASC, sh.start_time ASC LIMIT 30
            ''', (gid,)).fetchall())
            db.close(); self.send_json(with_shift_status(rows)); return

        # /api/me is available to any authenticated role, including 'client'
        if path == '/api/me':
            s0 = self.get_session()
            if not s0: self.err('Unauthorized', 401); return
            self.send_json({'id':s0['admin_id'],'name':s0['name'],'email':s0['email'],'role':s0['role'],
                            'must_change_password': s0.get('must_change_password', False)}); return

        # ── Admin-only below ──
        s = self.require_admin()
        if s is None: return

        # Block must_change_password sessions from all other admin GET endpoints
        if s.get('must_change_password'):
            self.err('Please set your password before continuing', 403); return

        if path == '/api/guards/all':
            db = get_db()
            rows = RL(db.execute('SELECT * FROM guards ORDER BY active DESC, name').fetchall())
            db.close(); self.send_json(rows); return

        m = re.match(r'^/api/guards/([^/]+)/site-prefs$', path)
        if m:
            db = get_db()
            rows = RL(db.execute('SELECT site_id, pref FROM guard_site_prefs WHERE guard_id=?',
                                  (m.group(1),)).fetchall())
            db.close(); self.send_json(rows); return

        m = re.match(r'^/api/guards/([^/]+)/compliance$', path)
        if m:
            db = get_db()
            rows = RL(db.execute('''
                SELECT ci.id as item_id, ci.name,
                       COALESCE(gc.checked,0) as checked, COALESCE(gc.reference_no,'') as reference_no,
                       gc.expiry_date, COALESCE(gc.reminder_days,60) as reminder_days,
                       COALESCE(gc.critical,0) as critical, gc.file_filename,
                       COALESCE(gc.show_to_customer,0) as show_to_customer
                FROM compliance_items ci
                LEFT JOIN guard_compliance gc ON gc.item_id=ci.id AND gc.guard_id=?
                ORDER BY ci.sort_order
            ''', (m.group(1),)).fetchall())
            db.close(); self.send_json(rows); return

        m = re.match(r'^/api/guards/([^/]+)/leave$', path)
        if m:
            db = get_db()
            rows = RL(db.execute('SELECT * FROM guard_leave WHERE guard_id=? ORDER BY start_date DESC',
                                  (m.group(1),)).fetchall())
            db.close(); self.send_json(rows); return

        if path == '/api/leave':
            # All guards' leave overlapping a date range — used by the weekly
            # availability view. Without a range, returns everything.
            date_from = qs.get('date_from',[None])[0]
            date_to   = qs.get('date_to',[None])[0]
            where, params = [], []
            if date_to:   where.append('gl.start_date<=?'); params.append(date_to)
            if date_from: where.append('gl.end_date>=?');   params.append(date_from)
            wc = ('WHERE '+' AND '.join(where)) if where else ''
            db = get_db()
            rows = RL(db.execute(f'''
                SELECT gl.*, g.name as guard_name
                FROM guard_leave gl JOIN guards g ON g.id=gl.guard_id
                {wc} ORDER BY gl.start_date
            ''', params).fetchall())
            db.close(); self.send_json(rows); return

        if path == '/api/dashboard':
            db = get_db()
            today = datetime.now().strftime('%Y-%m-%d')
            month_start = datetime.now().strftime('%Y-%m-01')
            pending  = db.execute("SELECT COUNT(*) FROM submissions WHERE status='pending'").fetchone()[0]
            approved_today = db.execute("SELECT COUNT(*) FROM submissions WHERE status='approved' AND DATE(reviewed_at)=?", (today,)).fetchone()[0]
            total_guards = db.execute("SELECT COUNT(*) FROM guards WHERE active=1").fetchone()[0]
            total_sites  = db.execute("SELECT COUNT(*) FROM sites WHERE active=1").fetchone()[0]
            rev_row = db.execute('''
                SELECT COALESCE(SUM(sub.total_hours * COALESCE(r.rate, g.base_rate)),0)
                FROM submissions sub
                JOIN guards g ON g.id=sub.guard_id
                LEFT JOIN rates r ON r.guard_id=sub.guard_id AND r.site_id=sub.site_id
                WHERE sub.status='approved' AND sub.shift_date >= ?
            ''', (month_start,)).fetchone()[0]
            recent = RL(db.execute('''
                SELECT sub.id, sub.shift_date, sub.total_hours, sub.status, sub.submitted_at,
                       g.name as guard_name, s.name as site_name, s.client_name
                FROM submissions sub
                JOIN guards g ON g.id=sub.guard_id
                JOIN sites  s ON s.id=sub.site_id
                ORDER BY sub.submitted_at DESC LIMIT 15
            ''').fetchall())
            db.close()
            self.send_json({'pending': pending, 'approved_today': approved_today,
                            'total_guards': total_guards, 'total_sites': total_sites,
                            'revenue_month': round(rev_row, 2), 'recent': recent}); return

        if path == '/api/submissions':
            db = get_db(); where=[]; params=[]
            s = sessions.get(self.headers.get('X-Auth-Token',''), {})
            if qs.get('status'):      where.append('sub.status=?');          params.append(qs['status'][0])
            if qs.get('guard_id'):    where.append('sub.guard_id=?');        params.append(qs['guard_id'][0])
            if qs.get('site_id'):     where.append('sub.site_id=?');         params.append(qs['site_id'][0])
            if qs.get('site_name'):   where.append('s.name LIKE ?');         params.append(f"%{qs['site_name'][0]}%")
            if qs.get('client_name'): where.append('s.client_name LIKE ?'); params.append(f"%{qs['client_name'][0]}%")
            if qs.get('date_from'):   where.append('sub.shift_date>=?');     params.append(qs['date_from'][0])
            if qs.get('date_to'):     where.append('sub.shift_date<=?');     params.append(qs['date_to'][0])
            wc = ('WHERE '+' AND '.join(where)) if where else ''
            rows = RL(db.execute(f'''
                SELECT sub.*, g.name as guard_name, g.license_number,
                       s.name as site_name, s.client_name
                FROM submissions sub
                JOIN guards g ON g.id=sub.guard_id
                JOIN sites  s ON s.id=sub.site_id
                {wc}
                ORDER BY sub.shift_date DESC, sub.submitted_at DESC
            ''', params).fetchall())
            db.close(); self.send_json(rows); return

        if path == '/api/rates':
            db = get_db()
            self.send_json(RL(db.execute('''
                SELECT r.*, g.name as guard_name, s.name as site_name, s.client_name
                FROM rates r
                JOIN guards g ON g.id=r.guard_id
                JOIN sites  s ON s.id=r.site_id
                ORDER BY g.name, s.name
            ''').fetchall()))
            db.close(); return

        if path == '/api/invoice':
            rows, total = invoice_query(qs)
            self.send_json({'rows': rows, 'total': total}); return

        if path == '/api/invoice/pdf':
            rows, total = invoice_query(qs)
            cn = qs.get('client_name',[''])[0]; df = qs.get('date_from',[''])[0]; dt = qs.get('date_to',[''])[0]
            try: data = make_pdf(rows, cn or 'All Clients', df or '—', dt or '—', total)
            except Exception as e:
                self.err(f'PDF failed: {e}. Run: py -m pip install reportlab', 500); return
            fn = f"BOS_invoice_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            db = get_db(); audit(db, s, 'INVOICE_PDF', f'client={cn} {df}~{dt}'); db.commit(); db.close()
            self.send_download(data, 'application/pdf', fn); return

        if path == '/api/invoice/xlsx':
            if not OPENPYXL_OK: self.err('Run: py -m pip install openpyxl', 500); return
            rows, total = invoice_query(qs)
            cn = qs.get('client_name',[''])[0]; df = qs.get('date_from',[''])[0]; dt = qs.get('date_to',[''])[0]
            data = make_xlsx(rows, cn or 'All Clients', df, dt, total)
            fn   = f"BOS_invoice_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
            db = get_db(); audit(db, s, 'INVOICE_XLSX', f'client={cn} {df}~{dt}'); db.commit(); db.close()
            self.send_download(data,
                'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', fn); return

        if path == '/api/invoice/csv':
            rows, total = invoice_query(qs)
            buf = io.StringIO(); w = csv.writer(buf)
            w.writerow(['Date','Guard','Site','Client','Start','End','Hours','Rate','Amount'])
            for r in rows:
                w.writerow([r['shift_date'],r['guard_name'],r['site_name'],r['client_name'],
                             r['start_time'],r['end_time'],r['total_hours'],r['rate'],r['amount']])
            w.writerow([]); w.writerow(['','','','','','','','TOTAL',round(total,2)])
            data = ('\ufeff'+buf.getvalue()).encode('utf-8')
            fn   = f"BOS_invoice_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            self.send_download(data,'text/csv; charset=utf-8', fn); return

        if path == '/api/reports/catalog':
            self.send_json([{'id':k,'category':v['category'],'title':v['title'],'desc':v['desc']}
                             for k,v in REPORTS.items()]); return

        if path == '/api/reports/run':
            rid = qs.get('report',[''])[0]
            entry = REPORTS.get(rid)
            if not entry: self.err('Unknown report'); return
            try:
                headers, data = entry['fn'](qs)
            except Exception as e:
                self.err(f'Report failed: {e}', 500); return
            fmt   = qs.get('format',['csv'])[0]
            stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            safe  = re.sub(r'[^A-Za-z0-9]+','_', entry['title']).strip('_')
            if fmt == 'xlsx':
                if not OPENPYXL_OK: self.err('Run: py -m pip install openpyxl', 500); return
                out = rows_to_xlsx(headers, data, entry['title'])
                db = get_db(); audit(db, s, 'REPORT_RUN', f"{entry['title']} xlsx"); db.commit(); db.close()
                self.send_download(out, 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                                    f'BOS_{safe}_{stamp}.xlsx'); return
            out = rows_to_csv(headers, data)
            db = get_db(); audit(db, s, 'REPORT_RUN', f"{entry['title']} csv"); db.commit(); db.close()
            self.send_download(out, 'text/csv; charset=utf-8', f'BOS_{safe}_{stamp}.csv'); return

        if path == '/api/reminders/all':
            db = get_db()
            self.send_json(RL(db.execute('''
                SELECT r.*, g.name as guard_name FROM reminders r
                LEFT JOIN guards g ON g.id=r.guard_id
                ORDER BY r.created_at DESC LIMIT 200
            ''').fetchall()))
            db.close(); return

        if path == '/api/admins':
            s2 = self.require_admin('administrator')
            if not s2: return
            db = get_db()
            rows = RL(db.execute(
                'SELECT id,name,email,role,active,last_login,created_at FROM admins ORDER BY created_at').fetchall())
            # Administrator cannot see superadmin accounts
            if s2.get('role') == 'administrator':
                rows = [r for r in rows if r.get('role') != 'superadmin']
            for r in rows:
                if r['role'] == 'client':
                    r['site_ids'] = self.client_site_ids(r['id'])
            db.close()
            self.send_json(rows); return

        if path == '/api/audit':
            db = get_db()
            self.send_json(RL(db.execute(
                'SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 300').fetchall()))
            db.close(); return

        if path == '/api/incidents':
            db = get_db(); where=[]; params=[]
            if qs.get('status'):  where.append('i.status=?');  params.append(qs['status'][0])
            if qs.get('site_id'): where.append('i.site_id=?'); params.append(qs['site_id'][0])
            wc = ('WHERE '+' AND '.join(where)) if where else ''
            rows = RL(db.execute(f'''
                SELECT i.*, g.name as guard_name, s.name as site_name, s.client_name
                FROM incidents i
                JOIN guards g ON g.id=i.guard_id
                JOIN sites  s ON s.id=i.site_id
                {wc} ORDER BY i.occurred_at DESC LIMIT 300''', params).fetchall())
            db.close(); self.send_json(rows); return

        if path == '/api/activity':
            db = get_db()
            scans = RL(db.execute('''
                SELECT 'checkpoint' as kind, cs.scanned_at as at, cs.checkpoint_name as label,
                       cs.distance_m, g.name as guard_name, s.name as site_name, s.id as site_id
                FROM checkpoint_scans cs
                JOIN guards g ON g.id=cs.guard_id
                JOIN sites  s ON s.id=cs.site_id
                ORDER BY cs.scanned_at DESC LIMIT 60''').fetchall())
            incidents = RL(db.execute('''
                SELECT 'incident' as kind, i.occurred_at as at, i.type as label,
                       i.status, g.name as guard_name, s.name as site_name, s.id as site_id
                FROM incidents i
                JOIN guards g ON g.id=i.guard_id
                JOIN sites  s ON s.id=i.site_id
                ORDER BY i.occurred_at DESC LIMIT 60''').fetchall())
            signins = RL(db.execute('''
                SELECT 'signin' as kind, sub.submitted_at as at, sub.location_verified,
                       sub.distance_m, g.name as guard_name, s.name as site_name, s.id as site_id
                FROM submissions sub
                JOIN guards g ON g.id=sub.guard_id
                JOIN sites  s ON s.id=sub.site_id
                ORDER BY sub.submitted_at DESC LIMIT 60''').fetchall())
            db.close()
            feed = sorted(scans+incidents+signins, key=lambda r:r['at'], reverse=True)[:80]
            self.send_json(feed); return

        if path == '/api/shifts':
            db = get_db(); where=[]; params=[]
            if qs.get('date_from'): where.append('sh.shift_date>=?'); params.append(qs['date_from'][0])
            if qs.get('date_to'):   where.append('sh.shift_date<=?'); params.append(qs['date_to'][0])
            if qs.get('guard_id'):  where.append('sh.guard_id=?');    params.append(qs['guard_id'][0])
            if qs.get('site_id'):   where.append('sh.site_id=?');     params.append(qs['site_id'][0])
            wc = ('WHERE '+' AND '.join(where)) if where else ''
            rows = RL(db.execute(f'''
                SELECT sh.*, g.name as guard_name, s.name as site_name, s.client_name
                FROM shifts sh
                JOIN guards g ON g.id=sh.guard_id
                JOIN sites  s ON s.id=sh.site_id
                {wc} ORDER BY sh.shift_date DESC, sh.start_time DESC LIMIT 500
            ''', params).fetchall())
            db.close()
            rows = with_shift_status(rows)
            status_f = qs.get('status',[None])[0]
            if status_f: rows = [r for r in rows if r['status']==status_f]
            self.send_json(rows); return

        if path == '/api/shifts/live':
            today = datetime.now().strftime('%Y-%m-%d')
            date_from = qs.get('date_from',[today])[0]
            date_to   = qs.get('date_to',[today])[0]
            db = get_db()
            rows = RL(db.execute('''
                SELECT sh.*, g.name as guard_name, s.name as site_name, s.client_name
                FROM shifts sh
                JOIN guards g ON g.id=sh.guard_id
                JOIN sites  s ON s.id=sh.site_id
                WHERE sh.shift_date>=? AND sh.shift_date<=? AND sh.cancelled=0
                ORDER BY sh.shift_date ASC, sh.start_time ASC
            ''', (date_from, date_to)).fetchall())
            db.close()
            rows = with_shift_status(rows)
            counts = {'scheduled':0,'missed':0,'in_progress':0,'completed':0}
            for r in rows: counts[r['status']] = counts.get(r['status'],0) + 1
            self.send_json({'shifts':rows, 'counts':counts, 'total':len(rows)}); return

        self.send_response(404); self.end_headers()

    # ── POST ───────────────────────────────────────────────────────────────────
    def do_POST(self):
        path = urlparse(self.path).path
        data = self.read_json()

        if path == '/api/login':
            db  = get_db()
            email_in = data.get('email','').strip().lower()
            row = R(db.execute('SELECT * FROM admins WHERE email=? AND active=1',
                               (email_in,)).fetchone())
            db.close()
            print(f"  LOGIN: email={email_in!r} found={'YES' if row else 'NO'}")
            if row:
                pw_ok = verify_password(data.get('password',''), row['password_hash'], row['salt'])
                print(f"  LOGIN: password_check={'PASS' if pw_ok else 'FAIL'} role={row.get('role')}")
                if not pw_ok:
                    self.err('Invalid email or password', 401); return
            else:
                # Show all admin emails in DB for diagnosis
                db2 = get_db()
                all_emails = [r['email'] for r in db2.execute('SELECT email FROM admins').fetchall()]
                db2.close()
                print(f"  LOGIN: admins in DB = {all_emails}")
                self.err('Invalid email or password', 401); return
            token = str(uuid.uuid4())
            must_change = bool(row.get('must_change_password', 0))
            sessions[token] = {'admin_id':row['id'],'name':row['name'],
                                'email':row['email'],'role':row['role'],
                                'must_change_password': must_change}
            # First-time login: force password change before granting full access
            if must_change:
                self.send_json({'force_password_change': True, 'token': token,
                                'name': row['name']}); return
            db = get_db()
            db.execute('UPDATE admins SET last_login=? WHERE id=?',
                       (datetime.now().isoformat(), row['id']))
            audit(db, sessions[token], 'LOGIN')
            db.commit(); db.close()
            self.send_json({'token':token,'id':row['id'],'name':row['name'],'role':row['role'],'company':COMPANY_NAME}); return

        if path == '/api/logout':
            s = sessions.pop(self.headers.get('X-Auth-Token',''), None)
            if s:
                db = get_db(); audit(db, s, 'LOGOUT'); db.commit(); db.close()
            self.send_json({'ok':True}); return

        # Guard submits shift — no auth needed
        if path == '/api/submissions':
            for f in ['guard_id','site_id','shift_date','start_time','end_time','total_hours']:
                if not data.get(f): self.err(f'{f} required'); return
            db = get_db()
            site = R(db.execute('SELECT lat,lng,geofence_radius,name FROM sites WHERE id=?',
                                (data['site_id'],)).fetchone())
            lat = lng = dist = None
            location_verified = 0
            if site and site.get('lat') is not None and site.get('lng') is not None:
                if data.get('lat') is None or data.get('lng') is None:
                    db.close()
                    self.err('Location access is required to sign in at this site. Please enable location and try again.', 403); return
                lat, lng = float(data['lat']), float(data['lng'])
                radius = site.get('geofence_radius') or 200
                dist = haversine_m(site['lat'], site['lng'], lat, lng)
                if dist > radius:
                    db.close()
                    self.err(f"You must be within {radius}m of {site['name']} to sign in. "
                             f"You are currently {int(dist)}m away — move closer and try again.", 403); return
                location_verified = 1
            photo = None
            if data.get('photo_b64') and data.get('photo_ext'):
                photo = f"{uuid.uuid4()}.{data['photo_ext']}"
                with open(os.path.join(UPLOADS_PATH, photo),'wb') as f:
                    f.write(base64.b64decode(data['photo_b64']))
            sid = str(uuid.uuid4())
            db.execute('''INSERT INTO submissions
                (id,guard_id,site_id,shift_date,start_time,end_time,total_hours,notes,photo_filename,
                 lat,lng,distance_m,location_verified)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                (sid,data['guard_id'],data['site_id'],data['shift_date'],
                 data['start_time'],data['end_time'],float(data['total_hours']),
                 data.get('notes',''), photo, lat, lng, dist, location_verified))
            db.commit(); db.close()
            self.send_json({'id':sid,'message':'Shift submitted successfully!'}, 201); return

        # Guard checks in at a patrol checkpoint — no auth needed, GPS-gated
        if path == '/api/checkpoints/scan':
            for f in ['checkpoint_id','guard_id','lat','lng']:
                if data.get(f) is None: self.err(f'{f} required'); return
            db = get_db()
            cp = R(db.execute('SELECT * FROM checkpoints WHERE id=? AND active=1',
                              (data['checkpoint_id'],)).fetchone())
            if not cp:
                db.close(); self.err('Checkpoint not found', 404); return
            lat, lng = float(data['lat']), float(data['lng'])
            dist = haversine_m(cp['lat'], cp['lng'], lat, lng)
            radius = cp.get('radius_m') or 40
            if dist > radius:
                db.close()
                self.err(f"You must be within {radius}m of '{cp['name']}' to check in. "
                         f"You are currently {int(dist)}m away.", 403); return
            scan_id = str(uuid.uuid4())
            db.execute('''INSERT INTO checkpoint_scans
                (id,checkpoint_id,checkpoint_name,guard_id,site_id,lat,lng,distance_m)
                VALUES (?,?,?,?,?,?,?,?)''',
                (scan_id, cp['id'], cp['name'], data['guard_id'], cp['site_id'], lat, lng, dist))
            db.commit(); db.close()
            self.send_json({'ok':True,'id':scan_id,'distance_m':round(dist,1)}, 201); return

        # Guard reports an incident — no auth needed
        if path == '/api/incidents':
            for f in ['guard_id','site_id','type']:
                if not data.get(f): self.err(f'{f} required'); return
            photo = None
            if data.get('photo_b64') and data.get('photo_ext'):
                photo = f"{uuid.uuid4()}.{data['photo_ext']}"
                with open(os.path.join(UPLOADS_PATH, photo),'wb') as f:
                    f.write(base64.b64decode(data['photo_b64']))
            iid = str(uuid.uuid4()); db = get_db()
            db.execute('''INSERT INTO incidents (id,guard_id,site_id,type,description,photo_filename,lat,lng)
                          VALUES (?,?,?,?,?,?,?,?)''',
                       (iid, data['guard_id'], data['site_id'], data['type'],
                        data.get('description',''), photo, data.get('lat'), data.get('lng')))
            db.commit(); db.close()
            self.send_json({'id':iid,'message':'Incident reported.'}, 201); return

        # Guard clocks in / out of a scheduled shift — no auth needed, GPS-gated
        m_ci = re.match(r'^/api/shifts/([^/]+)/clock-in$', path)
        if m_ci:
            db = get_db()
            sh = R(db.execute('''SELECT sh.*, s.lat as site_lat, s.lng as site_lng,
                                  s.geofence_radius, s.name as site_name
                                  FROM shifts sh JOIN sites s ON s.id=sh.site_id WHERE sh.id=?''',
                              (m_ci.group(1),)).fetchone())
            if not sh: db.close(); self.err('Shift not found', 404); return
            if sh['cancelled']: db.close(); self.err('This shift has been cancelled', 400); return
            if data.get('guard_id') != sh['guard_id']: db.close(); self.err('This shift is not assigned to you', 403); return
            if sh['clock_in_at']: db.close(); self.err('Already clocked in to this shift', 400); return
            lat = lng = dist = None
            verified = 0
            if sh['site_lat'] is not None and sh['site_lng'] is not None:
                if data.get('lat') is None or data.get('lng') is None:
                    db.close(); self.err('Location access is required to clock in at this site.', 403); return
                lat, lng = float(data['lat']), float(data['lng'])
                radius = sh['geofence_radius'] or 200
                dist = haversine_m(sh['site_lat'], sh['site_lng'], lat, lng)
                if dist > radius:
                    db.close()
                    self.err(f"You must be within {radius}m of {sh['site_name']} to clock in. "
                             f"You are currently {int(dist)}m away.", 403); return
                verified = 1
            db.execute('''UPDATE shifts SET clock_in_at=?, clock_in_lat=?, clock_in_lng=?, clock_in_verified=?
                          WHERE id=?''', (datetime.now().isoformat(), lat, lng, verified, m_ci.group(1)))
            db.commit()
            row = with_shift_status([R(db.execute('''SELECT sh.*, g.name as guard_name, s.name as site_name
                FROM shifts sh JOIN guards g ON g.id=sh.guard_id JOIN sites s ON s.id=sh.site_id
                WHERE sh.id=?''', (m_ci.group(1),)).fetchone())])[0]
            db.close(); self.send_json(row); return

        m_co = re.match(r'^/api/shifts/([^/]+)/clock-out$', path)
        if m_co:
            db = get_db()
            sh = R(db.execute('''SELECT sh.*, s.lat as site_lat, s.lng as site_lng,
                                  s.geofence_radius, s.name as site_name
                                  FROM shifts sh JOIN sites s ON s.id=sh.site_id WHERE sh.id=?''',
                              (m_co.group(1),)).fetchone())
            if not sh: db.close(); self.err('Shift not found', 404); return
            if data.get('guard_id') != sh['guard_id']: db.close(); self.err('This shift is not assigned to you', 403); return
            if not sh['clock_in_at']: db.close(); self.err('You have not clocked in to this shift yet', 400); return
            if sh['clock_out_at']: db.close(); self.err('Already clocked out of this shift', 400); return
            lat = lng = dist = None
            verified = 0
            if sh['site_lat'] is not None and sh['site_lng'] is not None:
                if data.get('lat') is None or data.get('lng') is None:
                    db.close(); self.err('Location access is required to clock out at this site.', 403); return
                lat, lng = float(data['lat']), float(data['lng'])
                radius = sh['geofence_radius'] or 200
                dist = haversine_m(sh['site_lat'], sh['site_lng'], lat, lng)
                if dist > radius:
                    db.close()
                    self.err(f"You must be within {radius}m of {sh['site_name']} to clock out. "
                             f"You are currently {int(dist)}m away.", 403); return
                verified = 1
            now = datetime.now()
            clock_in_dt = datetime.fromisoformat(sh['clock_in_at'])
            total_hours = round((now - clock_in_dt).total_seconds() / 3600, 2)
            photo = None
            if data.get('photo_b64') and data.get('photo_ext'):
                photo = f"{uuid.uuid4()}.{data['photo_ext']}"
                with open(os.path.join(UPLOADS_PATH, photo),'wb') as f:
                    f.write(base64.b64decode(data['photo_b64']))
            sub_id = str(uuid.uuid4())
            location_verified = 1 if (sh['clock_in_verified'] and verified) else 0
            db.execute('''INSERT INTO submissions
                (id,guard_id,site_id,shift_date,start_time,end_time,total_hours,notes,photo_filename,
                 lat,lng,distance_m,location_verified)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                (sub_id, sh['guard_id'], sh['site_id'], sh['shift_date'],
                 clock_in_dt.strftime('%H:%M'), now.strftime('%H:%M'), total_hours,
                 data.get('notes',''), photo, lat, lng, dist, location_verified))
            db.execute('''UPDATE shifts SET clock_out_at=?, clock_out_lat=?, clock_out_lng=?,
                          clock_out_verified=?, submission_id=? WHERE id=?''',
                       (now.isoformat(), lat, lng, verified, sub_id, m_co.group(1)))
            db.commit()
            row = with_shift_status([R(db.execute('''SELECT sh.*, g.name as guard_name, s.name as site_name
                FROM shifts sh JOIN guards g ON g.id=sh.guard_id JOIN sites s ON s.id=sh.site_id
                WHERE sh.id=?''', (m_co.group(1),)).fetchone())])[0]
            db.close(); self.send_json({**row, 'submission_id': sub_id, 'total_hours': total_hours}); return

        # Reminder seen — no auth
        if path == '/api/reminders/seen':
            rid = data.get('id')
            if rid:
                db = get_db()
                db.execute("UPDATE reminders SET seen_at=? WHERE id=?", (datetime.now().isoformat(),rid))
                db.commit(); db.close()
            self.send_json({'ok':True}); return

        # ── First-login password setup — available to any authenticated role ────
        if path == '/api/setup-password':
            s = self.get_session()
            if not s: self.err('Unauthorized', 401); return
            if not s.get('must_change_password'):
                self.err('No password change required for this session', 400); return
            new_pw  = data.get('new_password', '')
            conf_pw = data.get('confirm_password', '')
            if len(new_pw) < 6:
                self.err('Password must be at least 6 characters', 400); return
            if new_pw != conf_pw:
                self.err('Passwords do not match', 400); return
            h, salt = hash_password(new_pw)
            db = get_db()
            db.execute('UPDATE admins SET password_hash=?, salt=?, must_change_password=0 WHERE id=?',
                       (h, salt, s['admin_id']))
            audit(db, s, 'PASSWORD_SETUP_COMPLETE'); db.commit(); db.close()
            # Upgrade session to full access
            s['must_change_password'] = False
            db = get_db()
            db.execute('UPDATE admins SET last_login=? WHERE id=?',
                       (datetime.now().isoformat(), s['admin_id']))
            audit(db, s, 'LOGIN'); db.commit(); db.close()
            self.send_json({'token': self.headers.get('X-Auth-Token',''),
                            'id': s['admin_id'], 'name': s['name'],
                            'role': s['role'], 'company': COMPANY_NAME}); return

        # ── Admin-only below ──
        s = self.require_admin()
        if s is None: return

        # Block must_change_password sessions from all other admin POST endpoints
        if s.get('must_change_password'):
            self.err('Please set your password before continuing', 403); return

        m_rot = re.match(r'^/api/submissions/([^/]+)/rotate$', path)
        if m_rot:
            s2 = self.require_admin('manager')
            if not s2: return
            if not PIL_OK: self.err('Image rotation requires Pillow. Run: pip install Pillow', 500); return
            degrees = int(data.get('degrees', 90))
            if degrees not in (90, 180, 270): self.err('degrees must be 90, 180 or 270'); return
            db = get_db()
            row = R(db.execute('SELECT photo_filename FROM submissions WHERE id=?',
                               (m_rot.group(1),)).fetchone())
            if not row or not row['photo_filename']:
                db.close(); self.err('No photo for this submission'); return
            fpath = os.path.join(UPLOADS_PATH, row['photo_filename'])
            if not os.path.exists(fpath):
                db.close(); self.err('Photo file not found on server'); return
            try:
                img = PILImage.open(fpath)
                rotated = img.rotate(-degrees, expand=True)
                rotated.save(fpath)
                audit(db, s, 'PHOTO_ROTATED', f"sub={m_rot.group(1)} {degrees}deg")
                db.commit()
            except Exception as e:
                db.close(); self.err(f'Rotation failed: {e}', 500); return
            db.close()
            self.send_json({'ok': True, 'filename': row['photo_filename']}); return

        if path == '/api/guards':
            s2 = self.require_admin('manager')
            if not s2: return
            if not data.get('name'): self.err('Name required'); return
            gid = str(uuid.uuid4()); db = get_db()
            db.execute('''INSERT INTO guards (id,name,license_number,base_rate,phone,email,notes)
                          VALUES (?,?,?,?,?,?,?)''',
                       (gid,data['name'],data.get('license_number',''),
                        float(data.get('base_rate',0)),data.get('phone',''),
                        data.get('email',''),data.get('notes','')))
            db.commit()
            audit(db, s, 'GUARD_CREATE', data['name']); db.commit()
            g = R(db.execute('SELECT * FROM guards WHERE id=?',(gid,)).fetchone()); db.close()
            self.send_json(g, 201); return

        m = re.match(r'^/api/guards/([^/]+)/site-pref$', path)
        if m:
            s2 = self.require_admin('manager')
            if not s2: return
            site_id = data.get('site_id'); pref = data.get('pref') or ''
            if not site_id: self.err('site_id required'); return
            db = get_db()
            if pref in ('blacklist','preferred'):
                db.execute('''INSERT INTO guard_site_prefs (guard_id,site_id,pref) VALUES (?,?,?)
                              ON CONFLICT(guard_id,site_id) DO UPDATE SET pref=excluded.pref''',
                           (m.group(1), site_id, pref))
            else:
                db.execute('DELETE FROM guard_site_prefs WHERE guard_id=? AND site_id=?',
                           (m.group(1), site_id))
            audit(db, s, 'GUARD_SITE_PREF', f'{m.group(1)} site={site_id} pref={pref or "none"}')
            db.commit(); db.close()
            self.send_json({'ok':True}); return

        m = re.match(r'^/api/guards/([^/]+)/blacklist-all$', path)
        if m:
            s2 = self.require_admin('manager')
            if not s2: return
            db = get_db()
            site_ids = [r[0] for r in db.execute('SELECT id FROM sites WHERE active=1').fetchall()]
            for sid in site_ids:
                db.execute('''INSERT INTO guard_site_prefs (guard_id,site_id,pref) VALUES (?,?,'blacklist')
                              ON CONFLICT(guard_id,site_id) DO UPDATE SET pref='blacklist' ''',
                           (m.group(1), sid))
            audit(db, s, 'GUARD_BLACKLIST_ALL', m.group(1)); db.commit(); db.close()
            self.send_json({'ok':True, 'count':len(site_ids)}); return

        m = re.match(r'^/api/guards/([^/]+)/compliance/([^/]+)/file$', path)
        if m:
            s2 = self.require_admin('manager')
            if not s2: return
            if not data.get('file_b64'): self.err('file_b64 required'); return
            ext = re.sub(r'[^a-zA-Z0-9]', '', data.get('ext','dat'))[:6] or 'dat'
            fname = f"compliance_{uuid.uuid4().hex}.{ext}"
            with open(os.path.join(UPLOADS_PATH, fname), 'wb') as f:
                f.write(base64.b64decode(data['file_b64']))
            db = get_db()
            db.execute('''INSERT INTO guard_compliance (id,guard_id,item_id,file_filename) VALUES (?,?,?,?)
                          ON CONFLICT(guard_id,item_id) DO UPDATE SET file_filename=excluded.file_filename''',
                       (str(uuid.uuid4()), m.group(1), m.group(2), fname))
            audit(db, s, 'COMPLIANCE_FILE', f'{m.group(1)} item={m.group(2)}'); db.commit(); db.close()
            self.send_json({'ok':True, 'filename':fname}); return

        m = re.match(r'^/api/guards/([^/]+)/license-file$', path)
        if m:
            s2 = self.require_admin('manager')
            if not s2: return
            if not data.get('file_b64'): self.err('file_b64 required'); return
            ext = re.sub(r'[^a-zA-Z0-9]', '', data.get('ext','dat'))[:6] or 'dat'
            fname = f"license_{uuid.uuid4().hex}.{ext}"
            with open(os.path.join(UPLOADS_PATH, fname), 'wb') as f:
                f.write(base64.b64decode(data['file_b64']))
            db = get_db()
            db.execute('UPDATE guards SET license_file=? WHERE id=?', (fname, m.group(1)))
            audit(db, s, 'LICENSE_FILE', m.group(1)); db.commit(); db.close()
            self.send_json({'ok':True, 'filename':fname}); return

        m = re.match(r'^/api/guards/([^/]+)/leave$', path)
        if m:
            s2 = self.require_admin('manager')
            if not s2: return
            for f in ('start_date','end_date'):
                if not data.get(f): self.err(f'{f} required'); return
            lid = str(uuid.uuid4()); db = get_db()
            db.execute('''INSERT INTO guard_leave (id,guard_id,leave_type,start_date,end_date,notes)
                          VALUES (?,?,?,?,?,?)''',
                       (lid, m.group(1), data.get('leave_type','Fixed Leave'),
                        data['start_date'], data['end_date'], data.get('notes','')))
            audit(db, s, 'LEAVE_CREATE', f'{m.group(1)} {data["start_date"]}~{data["end_date"]}'); db.commit()
            row = R(db.execute('SELECT * FROM guard_leave WHERE id=?', (lid,)).fetchone())
            db.close(); self.send_json(row, 201); return

        if path == '/api/sites':
            s2 = self.require_admin('manager')
            if not s2: return
            if not data.get('name') or not data.get('client_name'):
                self.err('name and client_name required'); return
            sid = str(uuid.uuid4()); db = get_db()
            db.execute('''INSERT INTO sites
                (id,name,client_name,address,default_rate,contact_name,contact_phone,lat,lng,geofence_radius)
                VALUES (?,?,?,?,?,?,?,?,?,?)''',
                       (sid,data['name'],data['client_name'],data.get('address',''),
                        float(data.get('default_rate',0)),
                        data.get('contact_name',''),data.get('contact_phone',''),
                        data.get('lat'), data.get('lng'), int(data.get('geofence_radius') or 200)))
            db.commit()
            audit(db, s, 'SITE_CREATE', data['name']); db.commit()
            site = R(db.execute('SELECT * FROM sites WHERE id=?',(sid,)).fetchone()); db.close()
            self.send_json(site, 201); return

        if path == '/api/checkpoints':
            s2 = self.require_admin('manager')
            if not s2: return
            for f in ['site_id','name','lat','lng']:
                if data.get(f) is None: self.err(f'{f} required'); return
            cid = str(uuid.uuid4()); db = get_db()
            db.execute('''INSERT INTO checkpoints (id,site_id,name,lat,lng,radius_m,sort_order)
                          VALUES (?,?,?,?,?,?,?)''',
                       (cid, data['site_id'], data['name'], float(data['lat']), float(data['lng']),
                        int(data.get('radius_m') or 40), int(data.get('sort_order') or 0)))
            audit(db, s, 'CHECKPOINT_CREATE', f"{data['name']} (site={data['site_id']})"); db.commit()
            cp = R(db.execute('SELECT * FROM checkpoints WHERE id=?',(cid,)).fetchone()); db.close()
            self.send_json(cp, 201); return

        if path == '/api/shifts':
            s2 = self.require_admin('manager')
            if not s2: return
            for f in ['guard_id','site_id','shift_date','start_time','end_time']:
                if not data.get(f): self.err(f'{f} required'); return
            shid = str(uuid.uuid4()); db = get_db()
            db.execute('''INSERT INTO shifts (id,guard_id,site_id,shift_date,start_time,end_time,
                          position,notes,created_by,published) VALUES (?,?,?,?,?,?,?,?,?,0)''',
                       (shid, data['guard_id'], data['site_id'], data['shift_date'],
                        data['start_time'], data['end_time'], data.get('position',''),
                        data.get('notes',''), s['name']))
            audit(db, s, 'SHIFT_CREATE', f"{data['shift_date']} {data['start_time']}-{data['end_time']}"); db.commit()
            row = with_shift_status([R(db.execute('''SELECT sh.*, g.name as guard_name, s.name as site_name
                FROM shifts sh JOIN guards g ON g.id=sh.guard_id JOIN sites s ON s.id=sh.site_id
                WHERE sh.id=?''', (shid,)).fetchone())])[0]
            db.close(); self.send_json(row, 201); return

        if path == '/api/shifts/publish':
            s2 = self.require_admin('manager')
            if not s2: return
            date_from = data.get('date_from'); date_to = data.get('date_to')
            if not date_from or not date_to: self.err('date_from and date_to required'); return
            db = get_db()
            rows = RL(db.execute('''
                SELECT sh.*, g.name as guard_name, g.email as guard_email, s.name as site_name
                FROM shifts sh JOIN guards g ON g.id=sh.guard_id JOIN sites s ON s.id=sh.site_id
                WHERE sh.shift_date>=? AND sh.shift_date<=? AND sh.published=0 AND sh.cancelled=0
            ''', (date_from, date_to)).fetchall())
            if rows:
                db.execute('''UPDATE shifts SET published=1
                              WHERE shift_date>=? AND shift_date<=? AND published=0 AND cancelled=0''',
                           (date_from, date_to))
                audit(db, s, 'SHIFT_PUBLISH', f'{date_from}~{date_to} ({len(rows)} shifts)')
                db.commit()
            db.close()
            by_guard = {}
            for r in rows:
                by_guard.setdefault(r['guard_id'], {'name':r['guard_name'],'email':r['guard_email'],'shifts':[]})
                by_guard[r['guard_id']]['shifts'].append(r)
            notified = 0
            for g in by_guard.values():
                if not g['email']: continue
                lines = [f"- {sh['shift_date']} {sh['start_time']}-{sh['end_time']} at {sh['site_name']}"
                         for sh in g['shifts']]
                body = (f"Hi {g['name']},\n\nYour shifts for {date_from} to {date_to} have been "
                        f"published:\n\n" + "\n".join(lines) +
                        f"\n\nView your roster in the Guard Portal: {APP_URL}\n\n— {COMPANY_NAME}")
                if send_email(g['email'], f'{COMPANY_NAME}: New shifts published', body):
                    notified += 1
            self.send_json({'published': len(rows), 'notified': notified}); return

        if path == '/api/rates':
            s2 = self.require_admin('manager')
            if not s2: return
            if not data.get('guard_id') or not data.get('site_id'):
                self.err('guard_id and site_id required'); return
            db = get_db()
            db.execute('INSERT OR REPLACE INTO rates (guard_id,site_id,rate) VALUES (?,?,?)',
                       (data['guard_id'],data['site_id'],float(data.get('rate',0))))
            db.commit(); db.close(); self.send_json({'ok':True}); return

        if path == '/api/reminders':
            s2 = self.require_admin('manager')
            if not s2: return
            guard_ids = data.get('guard_ids',[])
            msg = data.get('message','Please submit your pending shift(s).')
            if not guard_ids: self.err('guard_ids required'); return
            db = get_db()
            for gid in guard_ids:
                db.execute('INSERT INTO reminders (id,guard_id,message) VALUES (?,?,?)',
                           (str(uuid.uuid4()),gid,msg))
            audit(db, s, 'REMINDERS_SENT', f'{len(guard_ids)} guards'); db.commit(); db.close()
            self.send_json({'ok':True,'sent':len(guard_ids)}); return

        if path == '/api/submissions/bulk':
            s2 = self.require_admin('manager')
            if not s2: return
            ids = data.get('ids',[]); action = data.get('action'); note = data.get('note','')
            if not ids or action not in ('approve','reject'):
                self.err('ids and action required'); return
            status = 'approved' if action == 'approve' else 'rejected'
            db = get_db()
            for sid in ids:
                db.execute('''UPDATE submissions SET status=?,admin_note=?,reviewed_by=?,reviewed_at=?
                              WHERE id=?''',
                           (status, note, s['name'], datetime.now().isoformat(), sid))
            audit(db, s, f'BULK_{action.upper()}', f'{len(ids)} submissions'); db.commit(); db.close()
            self.send_json({'ok':True,'updated':len(ids)}); return

        if path == '/api/logo':
            s2 = self.require_admin('manager')
            if not s2: return
            if not data.get('logo_b64') or not data.get('logo_ext'):
                self.err('logo_b64 and logo_ext required'); return
            ext = data['logo_ext'].lower().lstrip('.')
            if ext not in ['png','jpg','jpeg','gif','webp','svg']:
                self.err('Unsupported type'); return
            for oe in ['png','jpg','jpeg','gif','webp','svg']:
                op = os.path.join(UPLOADS_PATH,f'company_logo.{oe}')
                if os.path.exists(op): os.remove(op)
            with open(os.path.join(UPLOADS_PATH,f'company_logo.{ext}'),'wb') as f:
                f.write(base64.b64decode(data['logo_b64']))
            self.send_json({'ok':True}); return

        if path == '/api/admins':
            s2 = self.require_admin('administrator')
            if not s2: return
            requested_role = data.get('role','manager')
            # Administrator cannot create superadmin accounts
            if s2.get('role') == 'administrator' and requested_role == 'superadmin':
                self.err('Insufficient permissions to create superadmin', 403); return
            if not data.get('name') or not data.get('email') or not data.get('password'):
                self.err('name, email and password required'); return
            h, salt = hash_password(data['password'])
            aid = str(uuid.uuid4()); db = get_db()
            try:
                db.execute('''INSERT INTO admins (id,name,email,password_hash,salt,role,must_change_password)
                              VALUES (?,?,?,?,?,?,1)''',
                           (aid,data['name'],data['email'].lower(),h,salt,requested_role))
                if requested_role == 'client':
                    for site_id in (data.get('site_ids') or []):
                        db.execute('INSERT OR IGNORE INTO client_sites (admin_id,site_id) VALUES (?,?)',
                                   (aid, site_id))
                audit(db, s, 'ADMIN_CREATE', data['email']); db.commit()
                admin = R(db.execute(
                    'SELECT id,name,email,role,active,created_at FROM admins WHERE id=?',(aid,)).fetchone())
                db.close()
                # Send welcome email with temp credentials (optional — requires SMTP env vars)
                role_label = {'superadmin':'Super Admin','administrator':'Administrator',
                              'manager':'Manager','viewer':'Viewer'}.get(requested_role, requested_role)
                send_email(
                    data['email'].lower(),
                    f"Your {COMPANY_NAME} Account — Action Required",
                    f"Hi {data['name']},\n\n"
                    f"An admin account ({role_label}) has been created for you on the "
                    f"{COMPANY_NAME} Guard Management System.\n\n"
                    f"Login URL:          {APP_URL}\n"
                    f"Email:              {data['email']}\n"
                    f"Temporary password: {data['password']}\n\n"
                    f"IMPORTANT: You will be prompted to set your own password the first time you log in. "
                    f"Your temporary password will no longer work after that.\n\n"
                    f"— {COMPANY_NAME}"
                )
                self.send_json(admin, 201)
            except Exception as e:
                db.close(); self.err('Email already exists', 409)
            return

        if path == '/api/change-password':
            current = data.get('current_password','')
            new_pw  = data.get('new_password','')
            if not current or not new_pw: self.err('current and new password required'); return
            db = get_db()
            row = R(db.execute('SELECT * FROM admins WHERE id=?',(s['admin_id'],)).fetchone())
            if not verify_password(current, row['password_hash'], row['salt']):
                db.close(); self.err('Current password incorrect', 401); return
            h, salt = hash_password(new_pw)
            db.execute('UPDATE admins SET password_hash=?,salt=? WHERE id=?',
                       (h, salt, s['admin_id']))
            audit(db, s, 'PASSWORD_CHANGED'); db.commit(); db.close()
            self.send_json({'ok':True}); return

        self.send_response(404); self.end_headers()

    # ── PUT ────────────────────────────────────────────────────────────────────
    def do_PUT(self):
        path = urlparse(self.path).path
        data = self.read_json()

        # Reminder seen — no auth
        m = re.match(r'^/api/reminders/([^/]+)$', path)
        if m:
            db = get_db()
            db.execute("UPDATE reminders SET seen_at=? WHERE id=?",
                       (datetime.now().isoformat(), m.group(1)))
            db.commit(); db.close(); self.send_json({'ok':True}); return

        s = self.require_admin()
        if s is None: return
        if s.get('must_change_password'):
            self.err('Please set your password before continuing', 403); return

        m = re.match(r'^/api/submissions/([^/]+)$', path)
        if m:
            s2 = self.require_admin('manager')
            if not s2: return
            db = get_db()
            updates = []; params = []
            # Status change fields
            if 'status' in data:
                updates += ['status=?','reviewed_by=?','reviewed_at=?']
                params  += [data['status'], s['name'], datetime.now().isoformat()]
            if 'admin_note' in data:
                updates.append('admin_note=?'); params.append(data['admin_note'])
            # Editable hours fields (manager only)
            if 'total_hours' in data:
                updates.append('total_hours=?'); params.append(float(data['total_hours']))
            if 'start_time' in data:
                updates.append('start_time=?'); params.append(data['start_time'])
            if 'end_time' in data:
                updates.append('end_time=?'); params.append(data['end_time'])
            if 'shift_date' in data:
                updates.append('shift_date=?'); params.append(data['shift_date'])
            if 'notes' in data:
                updates.append('notes=?'); params.append(data['notes'])
            if updates:
                params.append(m.group(1))
                db.execute(f"UPDATE submissions SET {','.join(updates)} WHERE id=?", params)
                is_edit = any(k in data for k in ('total_hours','start_time','end_time','shift_date'))
                audit(db, s, 'SUB_EDITED' if is_edit else f"SUB_{data.get('status','UPDATED').upper()}", m.group(1))
                db.commit()
            row = R(db.execute('''SELECT sub.*,g.name as guard_name,s.name as site_name,s.client_name
                FROM submissions sub JOIN guards g ON g.id=sub.guard_id
                JOIN sites s ON s.id=sub.site_id WHERE sub.id=?''', (m.group(1),)).fetchone())
            db.close(); self.send_json(row); return

        m = re.match(r'^/api/guards/([^/]+)$', path)
        if m:
            s2 = self.require_admin('manager')
            if not s2: return
            db = get_db()
            updates=[]; params=[]
            for f in ('name','license_number','phone','email','notes','license_state',
                      'license_expiry'):
                if f in data: updates.append(f'{f}=?'); params.append(data[f])
            if 'base_rate' in data:
                updates.append('base_rate=?'); params.append(float(data['base_rate']))
            for f in ('active','hide_on_schedule','no_license_required',
                      'license_reminder_days','license_critical'):
                if f in data: updates.append(f'{f}=?'); params.append(int(data[f]))
            if updates:
                params.append(m.group(1))
                db.execute(f"UPDATE guards SET {','.join(updates)} WHERE id=?", params)
                audit(db, s, 'GUARD_UPDATE', m.group(1)); db.commit()
            g = R(db.execute('SELECT * FROM guards WHERE id=?',(m.group(1),)).fetchone())
            db.close(); self.send_json(g); return

        m = re.match(r'^/api/guards/([^/]+)/compliance/([^/]+)$', path)
        if m:
            s2 = self.require_admin('manager')
            if not s2: return
            guard_id, item_id = m.group(1), m.group(2)
            fields = {}
            if 'checked' in data:          fields['checked']          = int(data['checked'])
            if 'reference_no' in data:     fields['reference_no']     = data['reference_no']
            if 'expiry_date' in data:      fields['expiry_date']      = data['expiry_date'] or None
            if 'reminder_days' in data:    fields['reminder_days']    = int(data['reminder_days'] or 60)
            if 'critical' in data:         fields['critical']         = int(data['critical'])
            if 'show_to_customer' in data: fields['show_to_customer'] = int(data['show_to_customer'])
            if not fields: self.err('No fields to update'); return
            db = get_db()
            cols = ','.join(fields.keys()); qs_ = ','.join('?'*len(fields))
            upd  = ','.join(f'{k}=excluded.{k}' for k in fields)
            db.execute(f'''INSERT INTO guard_compliance (id,guard_id,item_id,{cols})
                          VALUES (?,?,?,{qs_})
                          ON CONFLICT(guard_id,item_id) DO UPDATE SET {upd}''',
                       [str(uuid.uuid4()), guard_id, item_id] + list(fields.values()))
            db.commit(); db.close()
            self.send_json({'ok':True}); return

        m = re.match(r'^/api/sites/([^/]+)$', path)
        if m:
            s2 = self.require_admin('manager')
            if not s2: return
            db = get_db()
            db.execute('''UPDATE sites SET name=?,client_name=?,address=?,default_rate=?,
                          contact_name=?,contact_phone=?,active=?,lat=?,lng=?,geofence_radius=? WHERE id=?''',
                       (data.get('name'),data.get('client_name'),data.get('address'),
                        float(data.get('default_rate',0)),data.get('contact_name'),
                        data.get('contact_phone'),int(data.get('active',1)),
                        data.get('lat'), data.get('lng'), int(data.get('geofence_radius') or 200),
                        m.group(1)))
            db.commit()
            audit(db, s, 'SITE_UPDATE', data.get('name','')); db.commit()
            site = R(db.execute('SELECT * FROM sites WHERE id=?',(m.group(1),)).fetchone())
            db.close(); self.send_json(site); return

        m = re.match(r'^/api/checkpoints/([^/]+)$', path)
        if m:
            s2 = self.require_admin('manager')
            if not s2: return
            db = get_db()
            db.execute('''UPDATE checkpoints SET name=?,lat=?,lng=?,radius_m=?,sort_order=?,active=?
                          WHERE id=?''',
                       (data.get('name'), float(data.get('lat',0)), float(data.get('lng',0)),
                        int(data.get('radius_m') or 40), int(data.get('sort_order') or 0),
                        int(data.get('active',1)), m.group(1)))
            db.commit()
            cp = R(db.execute('SELECT * FROM checkpoints WHERE id=?',(m.group(1),)).fetchone())
            db.close(); self.send_json(cp); return

        m = re.match(r'^/api/shifts/([^/]+)$', path)
        if m:
            s2 = self.require_admin('manager')
            if not s2: return
            db = get_db()
            updates=[]; params=[]
            for f in ('guard_id','site_id','shift_date','start_time','end_time','position','notes'):
                if f in data: updates.append(f'{f}=?'); params.append(data[f])
            if 'cancelled' in data: updates.append('cancelled=?'); params.append(int(data['cancelled']))
            if updates:
                params.append(m.group(1))
                db.execute(f"UPDATE shifts SET {','.join(updates)} WHERE id=?", params)
                audit(db, s, 'SHIFT_UPDATE', m.group(1)); db.commit()
            row = R(db.execute('''SELECT sh.*, g.name as guard_name, s.name as site_name
                FROM shifts sh JOIN guards g ON g.id=sh.guard_id JOIN sites s ON s.id=sh.site_id
                WHERE sh.id=?''', (m.group(1),)).fetchone())
            db.close()
            self.send_json(with_shift_status([row])[0] if row else None); return

        m = re.match(r'^/api/incidents/([^/]+)$', path)
        if m:
            s2 = self.require_admin('manager')
            if not s2: return
            db = get_db()
            updates=[]; params=[]
            if 'status' in data:
                updates += ['status=?','reviewed_by=?','reviewed_at=?']
                params  += [data['status'], s['name'], datetime.now().isoformat()]
            if 'admin_note' in data:
                updates.append('admin_note=?'); params.append(data['admin_note'])
            if updates:
                params.append(m.group(1))
                db.execute(f"UPDATE incidents SET {','.join(updates)} WHERE id=?", params)
                audit(db, s, 'INCIDENT_UPDATE', m.group(1)); db.commit()
            row = R(db.execute('''SELECT i.*,g.name as guard_name,s.name as site_name
                FROM incidents i JOIN guards g ON g.id=i.guard_id
                JOIN sites s ON s.id=i.site_id WHERE i.id=?''', (m.group(1),)).fetchone())
            db.close(); self.send_json(row); return

        m = re.match(r'^/api/admins/([^/]+)$', path)
        if m:
            s2 = self.require_admin('administrator')
            if not s2: return
            db = get_db()
            target = R(db.execute('SELECT role FROM admins WHERE id=?',(m.group(1),)).fetchone())
            # Administrator cannot modify superadmin accounts or assign superadmin role
            if s2.get('role') == 'administrator':
                if target and target.get('role') == 'superadmin':
                    db.close(); self.err('Insufficient permissions to modify superadmin', 403); return
                if data.get('role') == 'superadmin':
                    db.close(); self.err('Insufficient permissions to assign superadmin role', 403); return
            updates = []
            params  = []
            if 'role'   in data: updates.append('role=?');   params.append(data['role'])
            if 'active' in data: updates.append('active=?'); params.append(int(data['active']))
            if 'name'   in data: updates.append('name=?');   params.append(data['name'])
            if data.get('new_password'):
                h, salt = hash_password(data['new_password'])
                updates += ['password_hash=?','salt=?']; params += [h, salt]
            if updates:
                params.append(m.group(1))
                db.execute(f"UPDATE admins SET {','.join(updates)} WHERE id=?", params)
                audit(db, s, 'ADMIN_UPDATE', m.group(1)); db.commit()
            if 'site_ids' in data:
                db.execute('DELETE FROM client_sites WHERE admin_id=?', (m.group(1),))
                for site_id in (data.get('site_ids') or []):
                    db.execute('INSERT OR IGNORE INTO client_sites (admin_id,site_id) VALUES (?,?)',
                               (m.group(1), site_id))
                db.commit()
            row = R(db.execute(
                'SELECT id,name,email,role,active,last_login,created_at FROM admins WHERE id=?',
                (m.group(1),)).fetchone())
            if row and row['role'] == 'client':
                row['site_ids'] = self.client_site_ids(m.group(1))
            db.close(); self.send_json(row); return

        self.send_response(404); self.end_headers()

    # ── DELETE ─────────────────────────────────────────────────────────────────
    def do_DELETE(self):
        path = urlparse(self.path).path

        # Admin delete — superadmin only, cannot delete self
        m = re.match(r'^/api/admins/([^/]+)$', path)
        if m:
            s = self.require_admin('superadmin')
            if s is None: return
            if m.group(1) == s.get('admin_id'):
                self.err('Cannot delete your own account', 400); return
            db = get_db()
            target = R(db.execute('SELECT id,name FROM admins WHERE id=?',(m.group(1),)).fetchone())
            if not target:
                db.close(); self.err('Admin not found', 404); return
            db.execute('DELETE FROM admins WHERE id=?', (m.group(1),))
            audit(db, s, 'ADMIN_DELETE', target.get('name',m.group(1))); db.commit(); db.close()
            self.send_json({'ok':True}); return

        s = self.require_admin('manager')
        if s is None: return
        m = re.match(r'^/api/rates/([^/]+)/([^/]+)$', path)
        if m:
            db = get_db()
            db.execute('DELETE FROM rates WHERE guard_id=? AND site_id=?', (m.group(1),m.group(2)))
            db.commit(); db.close(); self.send_json({'ok':True}); return
        m = re.match(r'^/api/checkpoints/([^/]+)$', path)
        if m:
            db = get_db()
            db.execute('DELETE FROM checkpoints WHERE id=?', (m.group(1),))
            audit(db, s, 'CHECKPOINT_DELETE', m.group(1)); db.commit(); db.close()
            self.send_json({'ok':True}); return
        m = re.match(r'^/api/leave/([^/]+)$', path)
        if m:
            db = get_db()
            db.execute('DELETE FROM guard_leave WHERE id=?', (m.group(1),))
            audit(db, s, 'LEAVE_DELETE', m.group(1)); db.commit(); db.close()
            self.send_json({'ok':True}); return
        m = re.match(r'^/api/shifts/([^/]+)$', path)
        if m:
            db = get_db()
            db.execute('DELETE FROM shifts WHERE id=?', (m.group(1),))
            audit(db, s, 'SHIFT_DELETE', m.group(1)); db.commit(); db.close()
            self.send_json({'ok':True}); return
        self.send_response(404); self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin','*')
        self.send_header('Access-Control-Allow-Methods','GET,POST,PUT,DELETE,OPTIONS')
        self.send_header('Access-Control-Allow-Headers','Content-Type,X-Auth-Token')
        self.end_headers()

# ─── Main ─────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    init_db()
    print(f"\n{'='*55}")
    print(f"  {COMPANY_NAME}")
    print(f"  Guard Management System  v3.0")
    print(f"{'='*55}")
    print(f"\n  http://localhost:{PORT}")
    print(f"  Admin email:    {DEFAULT_ADMIN_EMAIL}")
    print(f"  Admin password: {DEFAULT_ADMIN_PASSWORD}")
    print(f"\n  Press Ctrl+C to stop\n{'='*55}\n")
    with http.server.HTTPServer(('', PORT), Handler) as srv:
        try: srv.serve_forever()
        except KeyboardInterrupt: print('\nStopped.')
