"""Sessions must survive a server restart (a Railway deploy, a crash) rather
than silently signing out every admin, client and guard at once.

This test kills and relaunches the actual server process, so it can't share
the session-scoped `server` fixture every other test file uses (that would
disrupt whatever else is running in the same pytest session) — it manages
its own throwaway server instead, only for the tests in this file.
"""
import collections
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ADMIN_EMAIL = "restart-test-admin@bos-tests.local"
ADMIN_PASSWORD = "RestartTest123!"


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _call(base_url, method, path, body=None, token=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base_url + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("X-Auth-Token", token)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def _drain_stdout(proc, buf):
    """server.py logs structured JSON on every request now — if nothing
    reads its stdout pipe, the OS pipe buffer fills up and the server
    deadlocks the moment a request handler blocks on a write() call that
    never drains. Keeps only the last `buf.maxlen` lines, just enough for a
    startup-failure error message; nothing here is asserted on."""
    try:
        for line in proc.stdout:
            buf.append(line.decode(errors="replace"))
    except Exception:
        pass


def _launch(data_dir, port):
    env = os.environ.copy()
    env["DATA_DIR"] = data_dir
    env["PORT"] = str(port)
    env["ADMIN_EMAIL"] = ADMIN_EMAIL
    env["ADMIN_PASSWORD"] = ADMIN_PASSWORD
    proc = subprocess.Popen(
        [sys.executable, "server.py"], cwd=REPO_ROOT, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    output_buf = collections.deque(maxlen=500)
    threading.Thread(target=_drain_stdout, args=(proc, output_buf), daemon=True).start()
    base_url = f"http://localhost:{port}"
    for _ in range(60):
        if proc.poll() is not None:
            break
        try:
            urllib.request.urlopen(base_url, timeout=1)
            return proc, base_url
        except Exception:
            time.sleep(0.5)
    proc.terminate()
    raise RuntimeError(f"server.py did not start on {base_url}:\n{''.join(output_buf)}")


@pytest.fixture
def restartable_server():
    data_dir = tempfile.mkdtemp(prefix="bos_restart_test_")
    port = _free_port()
    proc, base_url = _launch(data_dir, port)
    state = {"proc": proc, "base_url": base_url, "data_dir": data_dir, "port": port}
    yield state
    state["proc"].terminate()
    try:
        state["proc"].wait(timeout=5)
    except subprocess.TimeoutExpired:
        state["proc"].kill()
    shutil.rmtree(data_dir, ignore_errors=True)


def _restart(state):
    state["proc"].terminate()
    try:
        state["proc"].wait(timeout=5)
    except subprocess.TimeoutExpired:
        state["proc"].kill()
    proc, base_url = _launch(state["data_dir"], state["port"])
    state["proc"] = proc
    state["base_url"] = base_url


def test_admin_and_guard_sessions_survive_a_restart(restartable_server):
    base = restartable_server["base_url"]
    status, login = _call(base, "POST", "/api/login", {"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    assert status == 200
    admin_token = login["token"]

    status, guard = _call(
        base, "POST", "/api/guards",
        {"name": "Restart Test Guard", "phone": "0400000000", "email": "restart-guard@bos-tests.local", "base_rate": 30},
        token=admin_token,
    )
    assert status in (200, 201)
    status, reset = _call(base, "POST", f"/api/guards/{guard['id']}/reset-password", token=admin_token)
    temp_pw = reset["temp_password"]
    status, glogin = _call(base, "POST", "/api/guard/login", {"email": "restart-guard@bos-tests.local", "password": temp_pw})
    pending_guard_token = glogin["token"]
    status, gsetup = _call(
        base, "POST", "/api/guard/setup-password",
        {"new_password": "GuardRestart123!", "confirm_password": "GuardRestart123!"}, token=pending_guard_token,
    )
    guard_token = gsetup["token"]

    _restart(restartable_server)
    base = restartable_server["base_url"]  # port is reused, but re-read for clarity

    status, guards = _call(base, "GET", "/api/guards/all", token=admin_token)
    assert status == 200, "admin token should still work after a restart"

    status, messages = _call(base, "GET", "/api/guard/messages", token=guard_token)
    assert status == 200, "guard token should still work after a restart"


def test_logout_removes_the_persisted_session_not_just_memory(restartable_server):
    base = restartable_server["base_url"]
    status, login = _call(base, "POST", "/api/login", {"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    token = login["token"]

    status, _ = _call(base, "POST", "/api/logout", token=token)
    assert status == 200

    _restart(restartable_server)
    base = restartable_server["base_url"]
    status, err = _call(base, "GET", "/api/guards/all", token=token)
    assert status == 401, "a logged-out session must not come back after a restart"
