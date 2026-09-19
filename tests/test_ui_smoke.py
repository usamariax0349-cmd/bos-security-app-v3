"""Browser-level smoke tests for the two golden paths every change this
session was manually re-verified against: the admin dashboard, and a guard's
full hold-to-clock-in / clock-out cycle. These catch what the API tests
can't — a broken selector, a JS exception, a button wired to the wrong
handler."""
from datetime import datetime


def _console_errors(page, bucket):
    page.on("console", lambda m: bucket.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: bucket.append(str(e)))


def test_admin_dashboard_loads_without_errors(browser, server, admin_token):
    from conftest import ADMIN_EMAIL, ADMIN_PASSWORD

    errors = []
    ctx = browser.new_context(viewport={"width": 1440, "height": 900})
    page = ctx.new_page()
    _console_errors(page, errors)

    page.goto(server, wait_until="networkidle")
    page.click("text=Admin Login")
    page.fill("#login-email", ADMIN_EMAIL)
    page.fill("#login-pass", ADMIN_PASSWORD)
    page.click('button[onclick="doLogin()"]')
    page.wait_for_timeout(1500)

    assert page.evaluate("!document.getElementById('admin-page').classList.contains('hidden')")
    assert page.inner_text("#s-guards") != "—"

    app_errors = [e for e in errors if "Failed to load resource" not in e and "ERR_" not in e]
    assert app_errors == [], app_errors
    ctx.close()


def test_guard_clock_in_out_cycle_via_ui(browser, server, api, admin_token, site, guard_with_password):
    guard_id, email, password = guard_with_password
    today = datetime.now().strftime("%Y-%m-%d")
    status, shift = api.call(
        "POST", "/api/shifts",
        {"guard_id": guard_id, "site_id": site["id"], "shift_date": today, "start_time": "08:00", "end_time": "16:00"},
        token=admin_token,
    )
    assert status in (200, 201), shift
    status, pub = api.call("POST", "/api/shifts/publish", {"date_from": today, "date_to": today}, token=admin_token)
    assert status == 200, pub

    errors = []
    ctx = browser.new_context(
        viewport={"width": 390, "height": 844},
        geolocation={"latitude": site["lat"], "longitude": site["lng"]},
        permissions=["geolocation"],
    )
    page = ctx.new_page()
    _console_errors(page, errors)

    page.goto(server, wait_until="networkidle")
    page.fill("#glogin-email", email)
    page.fill("#glogin-pass", password)
    page.click('button[onclick="guardDoLogin()"]')
    page.wait_for_timeout(1200)

    # Login lands on the ID tab; the clock-in/out card lives on Shifts now.
    page.click('[data-gtab="shifts"]')
    page.wait_for_timeout(1000)

    # The slide-to-clock-on gesture needs a simulated drag; its always-present
    # tap fallback ("Can't slide? Tap to clock in instead") exercises the same
    # clockIn() call path without needing to fake pointer drag events.
    page.on("dialog", lambda dialog: dialog.accept())
    fallback = page.query_selector(".gid-slide-fallback")
    assert fallback is not None, "expected the tap-to-clock-in fallback on the Shifts tab"
    fallback.click()
    page.wait_for_timeout(1500)

    assert "ON SHIFT" in page.inner_text("#gh-clock-card") or page.query_selector(".gh-in-elapsed") is not None

    page.click("text=Clock out")
    page.wait_for_timeout(600)
    assert page.evaluate("!document.getElementById('step-clockout').classList.contains('hidden')")
    page.click("#co-submit-btn")
    page.wait_for_timeout(1200)

    app_errors = [e for e in errors if "Failed to load resource" not in e and "ERR_" not in e]
    assert app_errors == [], app_errors

    status, subs = api.call("GET", f"/api/submissions?guard_id={guard_id}", token=admin_token)
    assert status == 200
    assert any(s["shift_date"] == today for s in subs)
    ctx.close()
