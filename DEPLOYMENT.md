# Brown Owl Security — Deployment Guide
## GitHub + Railway · v3.0

---

## STEP 1 — Install packages on your computer (one time only)

Open Command Prompt and run:
```
py -m pip install reportlab openpyxl
```

---

## STEP 2 — Run locally first (test it works)

```
cd C:\Users\Bunny\Desktop\Project-X
py server.py
```

Open browser → http://localhost:5000

**Default admin login:**
- Email: admin@brownowlsecurity.com.au
- Password: admin123

---

## STEP 3 — Push to GitHub

### Option A: GitHub Desktop (easiest)
1. Open **GitHub Desktop**
2. Click **File → Add Local Repository**
3. Browse to `C:\Users\Bunny\Desktop\Project-X`
4. It will say "not a git repository" → click **Create a Repository**
5. Name it: `bos-security-app` → click **Create Repository**
6. You'll see all files listed → type a summary: `Project X v3.0`
7. Click **Commit to main**
8. Click **Publish repository** → uncheck "Keep private" if you want → **Publish**

### Option B: Command Prompt
```
cd C:\Users\Bunny\Desktop\Project-X
git init
git add .
git commit -m "Project X v3.0"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/bos-security-app.git
git push -u origin main
```

---

## STEP 4 — Deploy on Railway

1. Go to **https://railway.app** → log in
2. Click **New Project → Deploy from GitHub repo**
3. Select `bos-security-app`
4. Railway will start building automatically

---

## STEP 5 — Set Environment Variables on Railway

Click your service → **Variables** tab → Add these:

| Variable        | Value                                      |
|-----------------|--------------------------------------------|
| ADMIN_EMAIL     | admin@brownowlsecurity.com.au              |
| ADMIN_PASSWORD  | (choose a strong password)                 |
| COMPANY_NAME    | Brown Owl Security (BOS)                   |
| DATA_DIR        | /data                                      |

---

## STEP 6 — Add Persistent Volume (keeps your database safe)

1. In your Railway project canvas, right-click on empty space
2. Click **Add Volume** (or press Ctrl+K and search "volume")
3. Set **Mount Path** to: `/data`
4. Click Create

This ensures guards, sites and submissions are NOT deleted when Railway restarts.

---

## STEP 7 — Get your live URL

1. Click your service → **Settings** tab → **Domains**
2. Click **Generate Domain** (or add a custom domain)
3. You'll get a URL like: `https://bos-security-app.up.railway.app`
4. Share this URL with your guards

---

## STEP 8 — Seed guards and sites on the live server

After first deploy, click your Railway service → **Deploy** tab → open a **Terminal**:
```
python seed_guards.py
python seed_sites.py
```

This loads all 106 guards and 58 sites into the live database.

---

## STEP 9 — Install as app on phones (PWA)

**iPhone (Safari):**
1. Open the URL in Safari
2. Tap Share → **Add to Home Screen**
3. Tap Add

**Android (Chrome):**
1. Open the URL in Chrome
2. Tap the menu (3 dots) → **Add to Home Screen**
3. Tap Add

Guards will see it as a real app icon on their phone.

---

## PUSHING UPDATES IN THE FUTURE

After any changes to files in Project-X:

**GitHub Desktop:** Changes appear automatically → commit → push

**Command Prompt:**
```
cd C:\Users\Bunny\Desktop\Project-X
git add .
git commit -m "Description of changes"
git push
```

Railway detects the push and redeploys automatically within ~2 minutes.

---

## ADMIN ROLES

| Role        | What they can do                                               |
|-------------|----------------------------------------------------------------|
| Super Admin | Everything: manage guards, sites, rates, invoices, other admins|
| Manager     | Approve/reject shifts, manage guards/sites/rates, send reminders, invoices |
| Viewer      | Read-only: can view submissions and invoices, cannot approve   |

Add new admins in the admin portal under the **Admins** tab (Super Admin only).

---

## DEFAULT LOGIN CREDENTIALS

These are set via Railway environment variables.
Change ADMIN_PASSWORD to something strong before going live.

Email:    admin@brownowlsecurity.com.au
Password: admin123 (CHANGE THIS!)

---

## SUPPORT

If Railway shows a build error, check:
1. requirements.txt has `reportlab` and `openpyxl`
2. Procfile contains `web: python server.py`
3. DATA_DIR environment variable is set to `/data`
4. A volume is mounted at `/data`
