"""Privacy Act 1988 / Health Records Act 2001 (Vic) compliance features:
the public privacy policy page, guard self-service data access, and the
superadmin-only data retention (de-identification) tool.
"""
import sqlite3
import time
from datetime import datetime, timedelta

import pytest

from conftest import set_guard_password


def test_privacy_page_serves_html_shell(api):
    status, content, headers = api.call("GET", "/privacy", raw=True)
    assert status == 200
    assert b"privacy-page" in content


def test_guard_my_data_export(api, admin_token, guard_with_password, site):
    guard_id, email, password = guard_with_password
    today = datetime.now().strftime("%Y-%m-%d")
    api.call(
        "POST", "/api/shifts",
        {"guard_id": guard_id, "site_id": site["id"], "shift_date": today, "start_time": "08:00", "end_time": "16:00"},
        token=admin_token,
    )
    status, login = api.call("POST", "/api/guard/login", {"email": email, "password": password})
    guard_token = login["token"]

    status, mydata = api.call("GET", "/api/guard/my-data", token=guard_token)
    assert status == 200
    assert "password_hash" not in mydata["profile"]
    assert "salt" not in mydata["profile"]
    assert mydata["profile"]["name"] == "Test Guard"
    assert len(mydata["shifts"]) == 1


def test_guard_my_data_requires_auth(api):
    status, _ = api.call("GET", "/api/guard/my-data")
    assert status == 401


def test_retention_candidates_superadmin_only(api, admin_token, guard_with_password):
    guard_id, email, password = guard_with_password
    status, login = api.call("POST", "/api/guard/login", {"email": email, "password": password})
    status, err = api.call("GET", "/api/retention/candidates", token=login["token"])
    assert status == 401  # a guard token isn't even an admin session

    status, admin = api.call(
        "POST", "/api/admins",
        {"name": "Retention Test Manager", "email": f"ret-mgr-{time.time()}@bos-tests.local",
         "password": "TempPass123!", "role": "manager"},
        token=admin_token,
    )
    email2 = admin["email"]
    _, login2 = api.call("POST", "/api/login", {"email": email2, "password": "TempPass123!"})
    _, setup = api.call(
        "POST", "/api/setup-password",
        {"new_password": "RealPass123!", "confirm_password": "RealPass123!"}, token=login2["token"],
    )
    status, err = api.call("GET", "/api/retention/candidates", token=setup["token"])
    assert status == 403  # manager isn't enough — retention is superadmin-only

    status, ok = api.call("GET", "/api/retention/candidates", token=admin_token)
    assert status == 200
    assert ok["retention_years"] == 7


def test_anonymize_rejects_active_guard(api, admin_token, guard_with_password):
    guard_id, email, password = guard_with_password
    status, err = api.call("POST", f"/api/guards/{guard_id}/anonymize", token=admin_token)
    assert status == 400
    assert "active" in err.get("error", "").lower()


def test_anonymize_rejects_recently_active_inactive_guard(api, admin_token, guard_with_password, site):
    guard_id, email, password = guard_with_password
    today = datetime.now().strftime("%Y-%m-%d")
    api.call(
        "POST", "/api/shifts",
        {"guard_id": guard_id, "site_id": site["id"], "shift_date": today, "start_time": "08:00", "end_time": "16:00"},
        token=admin_token,
    )
    api.call("PUT", f"/api/guards/{guard_id}", {"active": False}, token=admin_token)

    status, candidates = api.call("GET", "/api/retention/candidates", token=admin_token)
    assert not any(c["id"] == guard_id for c in candidates["candidates"])

    status, err = api.call("POST", f"/api/guards/{guard_id}/anonymize", token=admin_token)
    assert status == 400


def test_anonymize_eligible_guard_deidentifies_but_keeps_shift_history(api, admin_token, guard_with_password, site, db_path):
    guard_id, email, password = guard_with_password
    api.call(
        "PUT", f"/api/guards/{guard_id}",
        {"blood_type": "O+", "next_of_kin_name": "Someone", "employee_no": "EMP123"}, token=admin_token,
    )
    old_date = (datetime.now() - timedelta(days=365 * 8)).strftime("%Y-%m-%d")
    api.call(
        "POST", "/api/shifts",
        {"guard_id": guard_id, "site_id": site["id"], "shift_date": old_date, "start_time": "08:00", "end_time": "16:00"},
        token=admin_token,
    )
    api.call("PUT", f"/api/guards/{guard_id}", {"active": False}, token=admin_token)

    status, candidates = api.call("GET", "/api/retention/candidates", token=admin_token)
    assert any(c["id"] == guard_id for c in candidates["candidates"])

    status, ok = api.call("POST", f"/api/guards/{guard_id}/anonymize", token=admin_token)
    assert status == 200, ok

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    row = dict(conn.execute("SELECT * FROM guards WHERE id=?", (guard_id,)).fetchone())
    assert row["name"] != "Test Guard"
    assert "EMP123" in row["name"]
    assert row["phone"] == ""
    assert row["blood_type"] == ""
    assert row["next_of_kin_name"] == ""
    assert row["anonymized_at"]
    shift_row = conn.execute("SELECT 1 FROM shifts WHERE guard_id=?", (guard_id,)).fetchone()
    assert shift_row is not None  # financial/shift history is kept, just de-identified
    conn.close()

    # Re-processing an already-anonymized guard is rejected, and it drops
    # out of the candidates list.
    status, err = api.call("POST", f"/api/guards/{guard_id}/anonymize", token=admin_token)
    assert status == 400

    status, candidates2 = api.call("GET", "/api/retention/candidates", token=admin_token)
    assert not any(c["id"] == guard_id for c in candidates2["candidates"])
