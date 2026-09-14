"""Guard-facing golden paths: login, full clock-in/out cycle, panic alert,
incident report, and the cross-guard isolation guarantee."""
from datetime import datetime

from conftest import set_guard_password


def _publish_today(api, admin_token):
    today = datetime.now().strftime("%Y-%m-%d")
    status, body = api.call("POST", "/api/shifts/publish", {"date_from": today, "date_to": today}, token=admin_token)
    assert status == 200, body


def _create_shift(api, admin_token, guard_id, site_id):
    today = datetime.now().strftime("%Y-%m-%d")
    status, shift = api.call(
        "POST", "/api/shifts",
        {"guard_id": guard_id, "site_id": site_id, "shift_date": today, "start_time": "08:00", "end_time": "16:00"},
        token=admin_token,
    )
    assert status in (200, 201), shift
    return shift


def test_guard_login(api, guard_with_password):
    guard_id, email, password = guard_with_password
    status, body = api.call("POST", "/api/guard/login", {"email": email, "password": password})
    assert status == 200
    assert body["token"]


def test_guard_login_wrong_password_rejected(api, guard_with_password):
    _, email, _ = guard_with_password
    status, body = api.call("POST", "/api/guard/login", {"email": email, "password": "wrong"})
    assert status == 401


def test_clock_in_out_creates_pending_submission_admin_can_approve(api, admin_token, site, guard_with_password):
    guard_id, email, password = guard_with_password
    shift = _create_shift(api, admin_token, guard_id, site["id"])
    _publish_today(api, admin_token)

    status, body = api.call("POST", "/api/guard/login", {"email": email, "password": password})
    assert status == 200
    guard_token = body["token"]

    # Within the site's geofence — should verify and succeed.
    status, ci = api.call(
        "POST", f"/api/guard/shifts/{shift['id']}/clock-in",
        {"lat": site["lat"], "lng": site["lng"]}, token=guard_token,
    )
    assert status == 200, ci
    assert ci["clock_in_at"]

    # Clocking in twice is rejected.
    status, again = api.call(
        "POST", f"/api/guard/shifts/{shift['id']}/clock-in",
        {"lat": site["lat"], "lng": site["lng"]}, token=guard_token,
    )
    assert status == 400, again

    status, co = api.call(
        "POST", f"/api/guard/shifts/{shift['id']}/clock-out",
        {"lat": site["lat"], "lng": site["lng"], "notes": "all quiet"}, token=guard_token,
    )
    assert status == 200, co
    submission_id = co["submission_id"]
    assert submission_id

    status, subs = api.call("GET", f"/api/submissions?guard_id={guard_id}", token=admin_token)
    assert status == 200
    sub = next(s for s in subs if s["id"] == submission_id)
    assert sub["status"] == "pending"

    status, approved = api.call("PUT", f"/api/submissions/{submission_id}", {"status": "approved"}, token=admin_token)
    assert status == 200, approved
    assert approved["status"] == "approved"


def test_clock_in_outside_geofence_rejected(api, admin_token, site, guard_with_password):
    guard_id, email, password = guard_with_password
    shift = _create_shift(api, admin_token, guard_id, site["id"])
    _publish_today(api, admin_token)
    status, body = api.call("POST", "/api/guard/login", {"email": email, "password": password})
    guard_token = body["token"]

    # A point ~50km away — well outside any reasonable geofence radius.
    status, ci = api.call(
        "POST", f"/api/guard/shifts/{shift['id']}/clock-in",
        {"lat": site["lat"] + 0.5, "lng": site["lng"] + 0.5}, token=guard_token,
    )
    assert status == 403, ci


def test_guard_cannot_clock_into_another_guards_shift(api, admin_token, site, guard_with_password, db_path):
    """Cross-guard isolation: shift assignment is enforced server-side, not
    just hidden in the UI."""
    guard_id, email, password = guard_with_password
    shift = _create_shift(api, admin_token, guard_id, site["id"])
    _publish_today(api, admin_token)

    # A second, unrelated guard.
    other_email = f"other-guard-{shift['id']}@bos-tests.local"
    status, other_guard = api.call(
        "POST", "/api/guards",
        {"name": "Other Guard", "phone": "0400000001", "email": other_email, "base_rate": 30},
        token=admin_token,
    )
    assert status in (200, 201), other_guard
    set_guard_password(db_path, other_guard["id"], "OtherPass123!", email=other_email)
    status, body = api.call("POST", "/api/guard/login", {"email": other_email, "password": "OtherPass123!"})
    other_token = body["token"]

    status, resp = api.call(
        "POST", f"/api/guard/shifts/{shift['id']}/clock-in",
        {"lat": site["lat"], "lng": site["lng"]}, token=other_token,
    )
    assert status == 403, resp


def test_panic_alert_flow(api, admin_token, guard_with_password):
    guard_id, email, password = guard_with_password
    status, body = api.call("POST", "/api/guard/login", {"email": email, "password": password})
    guard_token = body["token"]

    status, alert = api.call("POST", "/api/guard/panic", {"lat": -37.8, "lng": 144.9}, token=guard_token)
    assert status == 201, alert

    status, active = api.call("GET", "/api/panic-alerts?status=active", token=admin_token)
    assert status == 200
    assert any(a["id"] == alert["id"] for a in active)

    status, resolved = api.call("POST", f"/api/panic-alerts/{alert['id']}/resolve", token=admin_token)
    assert status == 200, resolved

    status, active_after = api.call("GET", "/api/panic-alerts?status=active", token=admin_token)
    assert not any(a["id"] == alert["id"] for a in active_after)


def test_incident_report_flow(api, admin_token, site, guard_with_password):
    guard_id, email, password = guard_with_password
    status, body = api.call("POST", "/api/guard/login", {"email": email, "password": password})
    guard_token = body["token"]

    status, inc = api.call(
        "POST", "/api/guard/incidents",
        {"site_id": site["id"], "type": "suspicious_activity", "description": "test incident", "lat": site["lat"], "lng": site["lng"]},
        token=guard_token,
    )
    assert status == 201, inc

    status, incidents = api.call("GET", "/api/incidents", token=admin_token)
    assert status == 200
    assert any(i["id"] == inc["id"] for i in incidents)
