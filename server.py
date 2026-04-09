#!/usr/bin/env python3
"""
Brown Owl Security — Guard Management System
Production | Multi-Admin | Roles | Audit Log | v3.0
Run:  py server.py  →  http://localhost:5000
"""

import http.server, json, sqlite3, os, uuid, base64, re, io, csv, hashlib, secrets
from datetime import datetime
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
            role         TEXT DEFAULT 'manager',
            active       INTEGER DEFAULT 1,
            last_login   TEXT,
            created_at   TEXT DEFAULT CURRENT_TIMESTAMP
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
    ''')
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
        ("admins",      "last_login",    "ALTER TABLE admins ADD COLUMN last_login TEXT"),
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
        role_rank = {'viewer':0,'manager':1,'administrator':2,'superadmin':3}
        if min_role and role_rank.get(s.get('role',''),0) < role_rank.get(min_role,0):
            self.err('Insufficient permissions', 403); return None
        return s

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

        # ── Admin-only below ──
        s = self.require_admin()
        if s is None: return

        if path == '/api/me':
            self.send_json({'id':s['admin_id'],'name':s['name'],'email':s['email'],'role':s['role']}); return

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
            db.close()
            self.send_json(rows); return

        if path == '/api/audit':
            db = get_db()
            self.send_json(RL(db.execute(
                'SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 300').fetchall()))
            db.close(); return

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
            sessions[token] = {'admin_id':row['id'],'name':row['name'],
                                'email':row['email'],'role':row['role']}
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
            photo = None
            if data.get('photo_b64') and data.get('photo_ext'):
                photo = f"{uuid.uuid4()}.{data['photo_ext']}"
                with open(os.path.join(UPLOADS_PATH, photo),'wb') as f:
                    f.write(base64.b64decode(data['photo_b64']))
            sid = str(uuid.uuid4()); db = get_db()
            db.execute('''INSERT INTO submissions
                (id,guard_id,site_id,shift_date,start_time,end_time,total_hours,notes,photo_filename)
                VALUES (?,?,?,?,?,?,?,?,?)''',
                (sid,data['guard_id'],data['site_id'],data['shift_date'],
                 data['start_time'],data['end_time'],float(data['total_hours']),
                 data.get('notes',''), photo))
            db.commit(); db.close()
            self.send_json({'id':sid,'message':'Shift submitted successfully!'}, 201); return

        # Reminder seen — no auth
        if path == '/api/reminders/seen':
            rid = data.get('id')
            if rid:
                db = get_db()
                db.execute("UPDATE reminders SET seen_at=? WHERE id=?", (datetime.now().isoformat(),rid))
                db.commit(); db.close()
            self.send_json({'ok':True}); return

        # ── Admin-only below ──
        s = self.require_admin()
        if s is None: return

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

        if path == '/api/sites':
            s2 = self.require_admin('manager')
            if not s2: return
            if not data.get('name') or not data.get('client_name'):
                self.err('name and client_name required'); return
            sid = str(uuid.uuid4()); db = get_db()
            db.execute('''INSERT INTO sites (id,name,client_name,address,default_rate,contact_name,contact_phone)
                          VALUES (?,?,?,?,?,?,?)''',
                       (sid,data['name'],data['client_name'],data.get('address',''),
                        float(data.get('default_rate',0)),
                        data.get('contact_name',''),data.get('contact_phone','')))
            db.commit()
            audit(db, s, 'SITE_CREATE', data['name']); db.commit()
            site = R(db.execute('SELECT * FROM sites WHERE id=?',(sid,)).fetchone()); db.close()
            self.send_json(site, 201); return

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
                db.execute('''INSERT INTO admins (id,name,email,password_hash,salt,role)
                              VALUES (?,?,?,?,?,?)''',
                           (aid,data['name'],data['email'].lower(),h,salt,requested_role))
                audit(db, s, 'ADMIN_CREATE', data['email']); db.commit()
                admin = R(db.execute(
                    'SELECT id,name,email,role,active,created_at FROM admins WHERE id=?',(aid,)).fetchone())
                db.close(); self.send_json(admin, 201)
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
            db.execute('''UPDATE guards SET name=?,license_number=?,base_rate=?,
                          phone=?,email=?,notes=?,active=? WHERE id=?''',
                       (data.get('name'),data.get('license_number'),float(data.get('base_rate',0)),
                        data.get('phone'),data.get('email'),data.get('notes'),
                        int(data.get('active',1)), m.group(1)))
            db.commit()
            g = R(db.execute('SELECT * FROM guards WHERE id=?',(m.group(1),)).fetchone())
            db.close(); self.send_json(g); return

        m = re.match(r'^/api/sites/([^/]+)$', path)
        if m:
            s2 = self.require_admin('manager')
            if not s2: return
            db = get_db()
            db.execute('''UPDATE sites SET name=?,client_name=?,address=?,default_rate=?,
                          contact_name=?,contact_phone=?,active=? WHERE id=?''',
                       (data.get('name'),data.get('client_name'),data.get('address'),
                        float(data.get('default_rate',0)),data.get('contact_name'),
                        data.get('contact_phone'),int(data.get('active',1)), m.group(1)))
            db.commit()
            site = R(db.execute('SELECT * FROM sites WHERE id=?',(m.group(1),)).fetchone())
            db.close(); self.send_json(site); return

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
            row = R(db.execute(
                'SELECT id,name,email,role,active,last_login,created_at FROM admins WHERE id=?',
                (m.group(1),)).fetchone())
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
