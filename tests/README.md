# Tests

A real regression suite, not a smoke check you throw away after one session.
Every test runs the actual `server.py` (as a subprocess, against a throwaway
`DATA_DIR`) and drives it the same way the real frontend does — either
through the HTTP API directly, or, for `test_ui_smoke.py`, through an actual
browser via Playwright. Nothing here mocks the app.

## Setup

```bash
pip install -r requirements.txt -r requirements-dev.txt
playwright install chromium
```

## Running

```bash
pytest tests/
```

Each test session starts one `server.py` process (scope="session" — shared
across all tests, not restarted per test) against a fresh temp SQLite DB,
and tears it down at the end. Tests that create data (a site, a guard) use
function-scoped fixtures with unique emails/names, so they don't collide
with each other even though they share one server and one DB.

## What's covered

- **`test_admin_api.py`** — admin login (success + wrong password), the
  dashboard's stats and trends endpoints, creating a site, and invoice
  export (PDF magic bytes, CSV).
- **`test_guard_flow.py`** — guard login, the full clock-in → clock-out →
  pending submission → admin-approves cycle, geofence enforcement (clocking
  in from 50km away is rejected), cross-guard isolation (a guard can't clock
  into another guard's shift even by calling the API directly), the panic
  alert flow, and incident reporting.
- **`test_ui_smoke.py`** — two browser-driven tests: the admin dashboard
  loads with no console errors, and a guard's slide-to-clock-on gesture
  (via its tap fallback, since simulating a pointer drag isn't worth the
  flakiness) through to clock-out works end-to-end in a real page, checked
  against the actual DB afterward (not just "no error was thrown").
- **`test_mfa.py`** — TOTP enrollment/confirm (with an independent
  RFC 6238 implementation, so this proves interop rather than the server
  checking its own math), wrong-code rejection, `mfa_required` on login for
  an enrolled account, pending 2FA sessions blocked from every other admin
  route, backup-code login (and that a code is single-use), and that
  regenerating backup codes or disabling MFA both require re-entering the
  password.
- **`test_session_persistence.py`** — kills and relaunches the actual
  `server.py` process (its own throwaway server, not the shared session
  fixture) to prove admin and guard sessions survive a restart — a Railway
  deploy or crash — and that a session removed by `/api/logout` stays gone
  after that restart rather than reappearing from a stale persisted row.
- **`test_privacy.py`** — the public `/privacy` policy page, a guard's
  self-service data export (`/api/guard/my-data`, and that it never leaks
  `password_hash`/`salt`), superadmin-only gating on the data retention
  tool, and the anonymize endpoint: rejecting an active guard, rejecting an
  inactive guard who's within the 7-year Fair Work retention window, and on
  an eligible guard clearing personal fields while keeping shift/pay history
  intact for compliance.
- **`test_messaging.py`** — a guard browsing the FAQ list (without seeing
  the internal keyword-matching fields), submitting a support ticket, and
  the reactive auto-reply that matches a free-text message against a FAQ
  keyword.
- **`test_feature_flags.py`** — superadmin-only CRUD on feature flags (a
  guard token gets 401, a manager gets 403), key-format and rollout-percent
  validation, a disabled flag reading as off for everyone, 100%/0% rollout
  being all-or-nothing, a partial rollout landing the same guard on the same
  side of it across five repeated calls (not a coin flip per request), and a
  deleted flag no longer appearing.

## What's deliberately not covered

This isn't full coverage — it's the golden paths that got hand-tested over
and over during this app's development (clock in/out, panic, invoices,
dashboard, MFA, retention). Notification delivery (push/email), the offline
IndexedDB queue, and every admin sub-tab are still manual-only. Worth
extending this suite rather than re-testing those by hand next time they
change.
