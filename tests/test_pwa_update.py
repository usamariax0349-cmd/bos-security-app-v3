"""Regression coverage for a real bug: a guard who "saved" the app (added it
to their home screen as a PWA) kept seeing the old version after a deploy.

Two things had to be true for a deploy to actually reach an already-open
app: the service worker must serve the page shell network-first (not
cache-first — see sw.js), and the page must reload itself once a newer
service worker actually takes over (see the `controllerchange` handler in
index.html). The second part also had a real gotcha: sw.js calls
clients.claim(), which fires `controllerchange` on a page's very FIRST
activation too, not just on a genuine update — an earlier version of the
reload handler didn't distinguish the two and reloaded on every first
visit, which is covered here by test_first_visit_never_reloads.

This launches its own throwaway server.py (like test_session_persistence.py)
against an isolated copy of public/ (via the PUBLIC_PATH env var), so tests
can safely rewrite index.html/sw.js on disk to simulate a deploy without
touching the real source tree.
"""
import collections
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ADMIN_EMAIL = "pwa-test-admin@bos-tests.local"
ADMIN_PASSWORD = "PwaTest123!"


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _drain_stdout(proc, buf):
    try:
        for line in proc.stdout:
            buf.append(line.decode(errors="replace"))
    except Exception:
        pass


@pytest.fixture
def pwa_server():
    data_dir = tempfile.mkdtemp(prefix="bos_pwa_data_")
    public_dir = tempfile.mkdtemp(prefix="bos_pwa_public_")
    shutil.copytree(os.path.join(REPO_ROOT, "public"), public_dir, dirs_exist_ok=True)
    port = _free_port()
    env = os.environ.copy()
    env["DATA_DIR"] = data_dir
    env["PUBLIC_PATH"] = public_dir
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
        proc.terminate()
        shutil.rmtree(data_dir, ignore_errors=True)
        shutil.rmtree(public_dir, ignore_errors=True)
        raise RuntimeError(f"server.py did not start on {base_url}:\n{''.join(output_buf)}")

    yield base_url, public_dir

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    shutil.rmtree(data_dir, ignore_errors=True)
    shutil.rmtree(public_dir, ignore_errors=True)


MARKER_TAG = '<title>Brown Owl Security</title>'


def _index_path(public_dir):
    return os.path.join(public_dir, "index.html")


def _sw_path(public_dir):
    return os.path.join(public_dir, "sw.js")


def test_first_visit_never_reloads(browser, pwa_server):
    """The bug this guards against: clients.claim() in sw.js fires
    controllerchange on a page's first-ever activation, not just on a real
    update. An update-reload handler that doesn't check for that reloads
    every first visit — which, under load, can race a login flow and wipe
    it out mid-submission (this is what made the guard clock-in UI test
    flaky after the update-detection feature was first added)."""
    base_url, public_dir = pwa_server
    ctx = browser.new_context(viewport={"width": 1280, "height": 800})
    page = ctx.new_page()
    loads = []
    page.on("load", lambda: loads.append(time.time()))

    page.goto(base_url, wait_until="networkidle")
    page.wait_for_function("navigator.serviceWorker.controller !== null", timeout=15000)
    page.wait_for_timeout(3000)

    assert len(loads) == 1, "a spurious reload happened on a brand-new page's first-ever visit"
    ctx.close()


def test_content_only_deploy_is_visible_on_next_reload(browser, pwa_server):
    """The actual bug report: a deploy that only changes index.html (no new
    service worker) must show up immediately — this is what cache-first
    serving of the app shell broke."""
    base_url, public_dir = pwa_server
    index_path = _index_path(public_dir)
    original = open(index_path).read()
    assert MARKER_TAG in original

    try:
        v1 = original.replace(MARKER_TAG, MARKER_TAG + '\n<meta name="pwatest" content="v1">')
        open(index_path, "w").write(v1)

        ctx = browser.new_context(viewport={"width": 1280, "height": 800})
        page = ctx.new_page()
        page.goto(base_url, wait_until="networkidle")
        page.wait_for_function("navigator.serviceWorker.controller !== null", timeout=15000)
        assert page.eval_on_selector('meta[name="pwatest"]', "el => el.content") == "v1"

        v2 = v1.replace('content="v1"', 'content="v2"')
        open(index_path, "w").write(v2)

        page.reload(wait_until="networkidle")
        assert page.eval_on_selector('meta[name="pwatest"]', "el => el.content") == "v2", (
            "content-only deploy did not show up on reload — the app shell is being served stale"
        )
        ctx.close()
    finally:
        open(index_path, "w").write(original)


def test_sw_update_reloads_an_already_open_page(browser, pwa_server):
    """The other half of the fix: once a real update lands (a new service
    worker version, not just new page content), a page that was already
    open must pick it up on its own rather than requiring the guard to
    force-close and reopen the app."""
    base_url, public_dir = pwa_server
    index_path = _index_path(public_dir)
    sw_path = _sw_path(public_dir)
    original_index = open(index_path).read()
    original_sw = open(sw_path).read()
    assert MARKER_TAG in original_index

    try:
        v1 = original_index.replace(MARKER_TAG, MARKER_TAG + '\n<meta name="pwatest" content="v1">')
        open(index_path, "w").write(v1)

        ctx = browser.new_context(viewport={"width": 1280, "height": 800})
        page = ctx.new_page()
        page.goto(base_url, wait_until="networkidle")
        page.wait_for_function("navigator.serviceWorker.controller !== null", timeout=15000)

        v2 = v1.replace('content="v1"', 'content="v2"')
        open(index_path, "w").write(v2)
        # Bump whatever the current CACHE version string is — this must
        # keep working as sw.js's own version gets bumped on future PRs.
        new_sw, n = re.subn(r"(const CACHE = '[^']+)'", r"\1-test'", original_sw, count=1)
        assert n == 1, "could not find the CACHE version string in sw.js to bump"
        open(sw_path, "w").write(new_sw)

        # Nudge the update check the same way the app does on refocus —
        # never navigate/reload manually here, since the whole point is
        # that the ALREADY-OPEN page reloads itself.
        page.evaluate("document.dispatchEvent(new Event('visibilitychange'))")
        page.evaluate("navigator.serviceWorker.getRegistration().then(r => r.update())")

        page.wait_for_function(
            "document.querySelector('meta[name=\"pwatest\"]')?.content === 'v2'", timeout=15000
        )
        ctx.close()
    finally:
        open(index_path, "w").write(original_index)
        open(sw_path, "w").write(original_sw)
