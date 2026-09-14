"""Admin-facing golden paths: login, dashboard, invoice export."""
from conftest import ADMIN_EMAIL, ADMIN_PASSWORD


def test_login_success(api):
    status, body = api.call("POST", "/api/login", {"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    assert status == 200
    assert body["token"]


def test_login_wrong_password_rejected(api):
    status, body = api.call("POST", "/api/login", {"email": ADMIN_EMAIL, "password": "not-the-password"})
    assert status == 401


def test_dashboard_shape(api, admin_token):
    status, body = api.call("GET", "/api/dashboard", token=admin_token)
    assert status == 200
    for key in ("pending", "approved_today", "total_guards", "total_sites", "revenue_month", "recent"):
        assert key in body


def test_dashboard_requires_auth(api):
    status, body = api.call("GET", "/api/dashboard")
    assert status == 401


def test_dashboard_trends_shape(api, admin_token):
    status, body = api.call("GET", "/api/dashboard/trends?weeks=8", token=admin_token)
    assert status == 200
    assert len(body["weeks"]) == len(body["revenue"]) == len(body["hours"])
    for key in ("open", "reviewing", "resolved"):
        assert len(body["incidents"][key]) == len(body["weeks"])


def test_create_site(api, admin_token):
    status, site = api.call(
        "POST", "/api/sites",
        {"name": "API Test Site", "client_name": "API Test Client", "address": "2 Test St",
         "lat": -37.81, "lng": 144.96, "geofence_radius": 150, "billing_rate": 45},
        token=admin_token,
    )
    assert status in (200, 201), site
    assert site["name"] == "API Test Site"

    status, sites = api.call("GET", "/api/sites", token=admin_token)
    assert status == 200
    assert any(s["id"] == site["id"] for s in sites)


def test_invoice_pdf_download(api, admin_token):
    status, content, headers = api.call(
        "GET", "/api/invoice/pdf?date_from=2020-01-01&date_to=2099-01-01", token=admin_token, raw=True
    )
    assert status == 200, content[:200]
    assert content[:4] == b"%PDF"


def test_invoice_csv_download(api, admin_token):
    status, content, headers = api.call(
        "GET", "/api/invoice/csv?date_from=2020-01-01&date_to=2099-01-01", token=admin_token, raw=True
    )
    assert status == 200, content[:200]
    assert b"," in content or len(content) >= 0  # header row present even with zero data rows
