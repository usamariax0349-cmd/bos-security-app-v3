"""Shared fixtures: spin up the real server.py against a throwaway DATA_DIR
for the whole test session, and give tests a small API client + a way to
set a guard's password directly (bypassing the invite-email step, which is
its own concern — these tests are about what the app does once someone is
logged in, not the invite flow).
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from collections import namedtuple

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

ADMIN_EMAIL = "test-admin@bos-tests.local"
ADMIN_PASSWORD = "TestAdmin123!"

ServerInfo = namedtuple("ServerInfo", "base_url data_dir")


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Api:
    """Thin wrapper over server.py's actual HTTP API — same request shape
    the real frontend uses (X-Auth-Token header, JSON bodies)."""

    def __init__(self, base_url):
        self.base_url = base_url

    def call(self, method, path, body=None, token=None, raw=False):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base_url + path, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if token:
            req.add_header("X-Auth-Token", token)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                if raw:
                    return resp.status, resp.read(), dict(resp.headers)
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            body_bytes = e.read()
            if raw:
                return e.code, body_bytes, dict(e.headers)
            try:
                return e.code, json.loads(body_bytes)
            except ValueError:
                return e.code, {"error": body_bytes.decode(errors="replace")}


@pytest.fixture(scope="session")
def server_info():
    data_dir = tempfile.mkdtemp(prefix="bos_test_")
    port = _free_port()
    env = os.environ.copy()
    env["DATA_DIR"] = data_dir
    env["PORT"] = str(port)
    env["ADMIN_EMAIL"] = ADMIN_EMAIL
    env["ADMIN_PASSWORD"] = ADMIN_PASSWORD
    proc = subprocess.Popen(
        [sys.executable, "server.py"],
        cwd=REPO_ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    base_url = f"http://localhost:{port}"
    up = False
    for _ in range(60):
        if proc.poll() is not None:
            break
        try:
            urllib.request.urlopen(base_url, timeout=1)
            up = True
            break
        except Exception:
            time.sleep(0.5)
    if not up:
        out = proc.stdout.read().decode(errors="replace") if proc.stdout else ""
        proc.terminate()
        raise RuntimeError(f"server.py did not start on {base_url}:\n{out}")

    yield ServerInfo(base_url, data_dir)

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    shutil.rmtree(data_dir, ignore_errors=True)


@pytest.fixture(scope="session")
def server(server_info):
    return server_info.base_url


@pytest.fixture(scope="session")
def db_path(server_info):
    return os.path.join(server_info.data_dir, "data", "security.db")


@pytest.fixture(scope="session")
def api(server):
    return Api(server)


@pytest.fixture(scope="session")
def admin_token(api):
    status, body = api.call("POST", "/api/login", {"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    assert status == 200, body
    return body["token"]


def set_guard_password(db_path, guard_id, password, email=None):
    """Set a guard's password directly in the DB — bypasses the invite-email
    step (temp password + forced first-login change), which is a separate
    concern from what these tests check. Mirrors the technique used for
    manual testing throughout this app's development."""
    import sqlite3
    from server import hash_password

    h, salt = hash_password(password)
    conn = sqlite3.connect(db_path)
    if email:
        conn.execute(
            "UPDATE guards SET password_hash=?, salt=?, must_change_password=0, email=? WHERE id=?",
            (h, salt, email, guard_id),
        )
    else:
        conn.execute(
            "UPDATE guards SET password_hash=?, salt=?, must_change_password=0 WHERE id=?",
            (h, salt, guard_id),
        )
    conn.commit()
    conn.close()


@pytest.fixture
def guard_with_password(api, admin_token, db_path):
    """Creates a fresh guard, gives them a known password, and returns
    (guard_id, email, password)."""
    email = f"guard-{int(time.time()*1000)}@bos-tests.local"
    status, guard = api.call(
        "POST", "/api/guards",
        {"name": "Test Guard", "phone": "0400000000", "email": email, "base_rate": 30},
        token=admin_token,
    )
    assert status in (200, 201), guard
    password = "GuardPass123!"
    set_guard_password(db_path, guard["id"], password, email=email)
    return guard["id"], email, password


@pytest.fixture(scope="session")
def browser():
    """Chromium for the UI smoke tests. In most environments plain
    p.chromium.launch() is enough once `playwright install chromium` has
    run; environments that pin a pre-installed browser at a fixed path can
    point PLAYWRIGHT_CHROMIUM_EXECUTABLE at it instead of downloading."""
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        kwargs = {}
        exe = os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE")
        if exe:
            kwargs["executable_path"] = exe
        b = p.chromium.launch(**kwargs)
        yield b
        b.close()


@pytest.fixture
def site(api, admin_token):
    status, s = api.call(
        "POST", "/api/sites",
        {"name": "Test Site", "client_name": "Test Client", "address": "1 Test St",
         "lat": -37.8136, "lng": 144.9631, "geofence_radius": 200, "billing_rate": 40},
        token=admin_token,
    )
    assert status in (200, 201), s
    return s
