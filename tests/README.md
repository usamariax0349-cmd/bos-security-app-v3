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
  loads with no console errors, and a guard's hold-to-clock-in gesture
  through to clock-out works end-to-end in a real page, checked against the
  actual DB afterward (not just "no error was thrown").

## What's deliberately not covered

This isn't full coverage — it's the golden paths that got hand-tested over
and over during this app's development (clock in/out, panic, invoices,
dashboard). Notification delivery (push/email), the offline IndexedDB
queue, and every admin sub-tab are still manual-only. Worth extending this
suite rather than re-testing those by hand next time they change.
