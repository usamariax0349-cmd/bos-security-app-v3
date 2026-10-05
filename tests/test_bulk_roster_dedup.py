"""Re-uploading a roster (via either bulk-import tool) used to silently
double every row that had already been imported — POST /api/shifts has no
dedup of its own, and neither the paste-a-roster tool nor the OCR
screenshot importer checked for an existing shift before this.

test_duplicate_shift_still_creates_but_is_flagged covers the server-side
half (a direct POST still succeeds — a correction some admin genuinely
means to double up shouldn't be blocked outright — but the audit trail now
says so). The other two are browser-level: they exercise the actual
review-before-create UI both bulk tools share, the same way a real re-upload
would.
"""
from datetime import datetime, timedelta

from conftest import ADMIN_EMAIL, ADMIN_PASSWORD


def _future_date(days=3):
    return (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d")


def test_duplicate_shift_still_creates_but_is_flagged(api, admin_token, site, guard_with_password):
    guard_id, email, password = guard_with_password
    date = _future_date(3)
    body = {"guard_id": guard_id, "site_id": site["id"], "shift_date": date, "start_time": "08:00", "end_time": "16:00"}

    status, first = api.call("POST", "/api/shifts", body, token=admin_token)
    assert status in (200, 201), first

    status, second = api.call("POST", "/api/shifts", body, token=admin_token)
    assert status in (200, 201), second
    assert second["id"] != first["id"], "a second POST must still create its own row, not silently no-op"

    status, audit_rows = api.call("GET", "/api/audit?action=SHIFT_CREATE", token=admin_token)
    assert status == 200
    matching = [a for a in audit_rows if a["details"].startswith(date)]
    assert any("duplicate of an existing shift" in a["details"] for a in matching), (
        "the second create should be flagged in the audit log even though it wasn't blocked"
    )


def test_bulk_add_shifts_skips_an_already_scheduled_row_on_reupload(browser, server, admin_token, site, guard_with_password):
    guard_id, email, password = guard_with_password
    date = _future_date(4)  # distinct from the other tests in this file — "Test Guard"/"Test Site" aren't unique names, so a shared date could let one test's shift collide with another's fuzzy-matched row
    line = f"{site['name']}|{date}|08:00|16:00|Test Guard"

    ctx = browser.new_context(viewport={"width": 1440, "height": 900})
    page = ctx.new_page()
    page.goto(server, wait_until="networkidle")
    page.click("text=Admin Login")
    page.fill("#login-email", ADMIN_EMAIL)
    page.fill("#login-pass", ADMIN_PASSWORD)
    page.click('button[onclick="doLogin()"]')
    page.wait_for_timeout(1500)

    def upload():
        page.click('button[onclick="showTab(\'schedule\')"]')
        page.wait_for_timeout(400)
        page.click('button[onclick="openBulkAddShiftsModal()"]')
        page.wait_for_timeout(300)
        page.fill("#bas-textarea", line)
        page.click("#bas-check-btn")
        page.wait_for_timeout(600)
        checked = page.eval_on_selector_all(
            "#bas-review-tbody input[type=checkbox]", "els => els.filter(e => e.checked).length"
        )
        page.click("#bas-create-btn")
        page.wait_for_timeout(800)
        return checked

    first_checked = upload()
    assert first_checked == 1, "a brand-new shift line should auto-check on first upload"

    second_checked = upload()
    assert second_checked == 0, "re-uploading the identical line must default to unchecked, not re-create it"
    assert "Already scheduled" in page.inner_html("#bas-review-tbody")

    ctx.close()


def test_ocr_importer_shares_the_same_duplicate_check(browser, server, api, admin_token, site, guard_with_password):
    """Doesn't exercise actual OCR (no network access to the Tesseract CDN
    in CI, and it's not what this fix touched) — calls the same
    markRowsAlreadyScheduled()/renderOcrReviewTable() functions the real
    extraction path feeds into, with a hand-built row standing in for what
    runOcrExtraction() would have produced."""
    guard_id, email, password = guard_with_password
    date = _future_date(5)

    status, guards = api.call("GET", "/api/guards/all", token=admin_token)
    assert status == 200, guards
    guard = next(g for g in guards if g["id"] == guard_id)
    status, created = api.call(
        "POST", "/api/shifts",
        {"guard_id": guard_id, "site_id": site["id"], "shift_date": date, "start_time": "08:00", "end_time": "16:00"},
        token=admin_token,
    )
    assert status in (200, 201), created

    ctx = browser.new_context(viewport={"width": 1440, "height": 900})
    page = ctx.new_page()
    page.goto(server, wait_until="networkidle")
    page.click("text=Admin Login")
    page.fill("#login-email", ADMIN_EMAIL)
    page.fill("#login-pass", ADMIN_PASSWORD)
    page.click('button[onclick="doLogin()"]')
    page.wait_for_timeout(1500)

    page.evaluate(
        "(args) => { ocrParsedRows = [args.row]; document.getElementById('ocr-date').value = args.date; }",
        {"row": {"site_raw": site["name"], "name_raw": guard["name"], "start": "08:00", "end": "16:00",
                  "site_match": site, "guard_match": guard}, "date": date},
    )
    page.evaluate(
        "markRowsAlreadyScheduled(ocrParsedRows, () => document.getElementById('ocr-date').value, "
        "r => r.guard_match ? r.guard_match.id : null, r => r.site_match ? r.site_match.id : null)"
    )
    page.wait_for_timeout(500)
    assert page.evaluate("ocrParsedRows[0].alreadyScheduled") is True

    page.evaluate("renderOcrReviewTable()")
    assert page.eval_on_selector("#ocr-inc-0", "el => el.checked") is False
    assert "Already scheduled" in page.inner_html("#ocr-review-tbody")

    ctx.close()
