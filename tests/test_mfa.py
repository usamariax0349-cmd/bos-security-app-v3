"""Two-factor authentication: enroll, confirm, login-verify (TOTP + backup
codes), disable, regenerate. Uses an independent Python re-implementation of
the server's TOTP algorithm so this proves interop (same secret -> same
code) rather than just calling the server's own function back at itself.
"""
import base64
import hashlib
import hmac
import struct
import time

import pytest

from conftest import set_guard_password


def totp_code(secret, for_time=None, step=30, digits=6):
    if for_time is None:
        for_time = time.time()
    padded = secret.upper() + "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(padded)
    counter = int(for_time // step)
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    truncated = (struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(truncated).zfill(digits)


@pytest.fixture
def mfa_admin(api, admin_token):
    """A fresh admin with MFA enrolled, returned with its TOTP secret and a
    couple of unused backup codes so tests don't collide over shared state.
    Disables MFA again at teardown so this account never leaks into other
    tests in the same session."""
    status, admin = api.call(
        "POST", "/api/admins",
        {"name": "MFA Test Admin", "email": f"mfa-{time.time()}@bos-tests.local",
         "password": "TempPass123!", "role": "manager"},
        token=admin_token,
    )
    assert status in (200, 201), admin
    email = admin["email"]

    status, login = api.call("POST", "/api/login", {"email": email, "password": "TempPass123!"})
    assert login.get("force_password_change"), login
    pending = login["token"]
    status, setup = api.call(
        "POST", "/api/setup-password",
        {"new_password": "RealPass123!", "confirm_password": "RealPass123!"}, token=pending,
    )
    full_token = setup["token"]

    status, enroll = api.call("POST", "/api/mfa/setup", token=full_token)
    assert status == 200, enroll
    secret = enroll["secret"]
    assert "otpauth://" in enroll["otpauth_url"]

    status, confirm = api.call("POST", "/api/mfa/confirm", {"code": totp_code(secret)}, token=full_token)
    assert status == 200, confirm
    backup_codes = confirm["backup_codes"]
    assert len(backup_codes) == 8

    yield {"email": email, "secret": secret, "backup_codes": backup_codes, "full_token": full_token}

    # Best-effort cleanup — log back in (possibly needs a fresh TOTP code)
    # and disable MFA so this account can't interfere with anything else.
    status, login2 = api.call("POST", "/api/login", {"email": email, "password": "RealPass123!"})
    if login2.get("mfa_required"):
        api.call("POST", "/api/mfa/login-verify", {"code": totp_code(secret)}, token=login2["token"])
        api.call("POST", "/api/mfa/disable", {"password": "RealPass123!"}, token=login2["token"])


def test_setup_confirm_enables_mfa(api, mfa_admin):
    status, status_body = api.call("GET", "/api/mfa/status", token=mfa_admin["full_token"])
    assert status == 200
    assert status_body["enabled"] is True


def test_confirm_rejects_wrong_code(api, admin_token):
    status, admin = api.call(
        "POST", "/api/admins",
        {"name": "MFA Wrong Code Admin", "email": f"mfa-wrong-{time.time()}@bos-tests.local",
         "password": "TempPass123!", "role": "manager"},
        token=admin_token,
    )
    email = admin["email"]
    _, login = api.call("POST", "/api/login", {"email": email, "password": "TempPass123!"})
    _, setup = api.call(
        "POST", "/api/setup-password",
        {"new_password": "RealPass123!", "confirm_password": "RealPass123!"}, token=login["token"],
    )
    full_token = setup["token"]
    api.call("POST", "/api/mfa/setup", token=full_token)
    status, err = api.call("POST", "/api/mfa/confirm", {"code": "000000"}, token=full_token)
    assert status == 400, err


def test_login_requires_mfa_when_enabled(api, mfa_admin):
    status, login = api.call("POST", "/api/login", {"email": mfa_admin["email"], "password": "RealPass123!"})
    assert status == 200
    assert login["mfa_required"] is True
    assert "role" not in login  # not a full profile — just a pending token


def test_pending_session_blocked_from_other_admin_routes(api, mfa_admin):
    _, login = api.call("POST", "/api/login", {"email": mfa_admin["email"], "password": "RealPass123!"})
    pending = login["token"]
    status, err = api.call("GET", "/api/guards/all", token=pending)
    assert status == 403
    assert "two-factor" in err.get("error", "").lower()


def test_login_verify_wrong_code_rejected(api, mfa_admin):
    _, login = api.call("POST", "/api/login", {"email": mfa_admin["email"], "password": "RealPass123!"})
    status, err = api.call("POST", "/api/mfa/login-verify", {"code": "111111"}, token=login["token"])
    assert status == 401, err


def test_login_verify_correct_code_completes_login(api, mfa_admin):
    _, login = api.call("POST", "/api/login", {"email": mfa_admin["email"], "password": "RealPass123!"})
    pending = login["token"]
    status, done = api.call(
        "POST", "/api/mfa/login-verify", {"code": totp_code(mfa_admin["secret"])}, token=pending,
    )
    assert status == 200, done
    assert done["role"] == "manager"
    assert done["token"] == pending  # same token, now upgraded to full access

    status, guards = api.call("GET", "/api/guards/all", token=pending)
    assert status == 200


def test_backup_code_login_is_single_use(api, mfa_admin):
    code = mfa_admin["backup_codes"][0]

    _, login = api.call("POST", "/api/login", {"email": mfa_admin["email"], "password": "RealPass123!"})
    status, done = api.call("POST", "/api/mfa/login-verify", {"backup_code": code}, token=login["token"])
    assert status == 200, done

    _, login2 = api.call("POST", "/api/login", {"email": mfa_admin["email"], "password": "RealPass123!"})
    status, err = api.call("POST", "/api/mfa/login-verify", {"backup_code": code}, token=login2["token"])
    assert status == 401, err  # already used

    # Clean up the dangling pending session with a real TOTP code
    api.call("POST", "/api/mfa/login-verify", {"code": totp_code(mfa_admin["secret"])}, token=login2["token"])


def test_regenerate_backup_codes_requires_password(api, mfa_admin):
    status, err = api.call(
        "POST", "/api/mfa/regenerate-backup-codes", {"password": "wrong"}, token=mfa_admin["full_token"],
    )
    assert status == 401, err

    status, ok = api.call(
        "POST", "/api/mfa/regenerate-backup-codes", {"password": "RealPass123!"}, token=mfa_admin["full_token"],
    )
    assert status == 200, ok
    new_codes = ok["backup_codes"]
    assert len(new_codes) == 8
    assert new_codes[0] not in mfa_admin["backup_codes"]


def test_disable_requires_password_then_login_no_longer_requires_mfa(api, mfa_admin):
    status, err = api.call("POST", "/api/mfa/disable", {"password": "wrong"}, token=mfa_admin["full_token"])
    assert status == 401, err

    status, ok = api.call("POST", "/api/mfa/disable", {"password": "RealPass123!"}, token=mfa_admin["full_token"])
    assert status == 200, ok

    status, login = api.call("POST", "/api/login", {"email": mfa_admin["email"], "password": "RealPass123!"})
    assert status == 200
    assert not login.get("mfa_required")
    assert login["role"] == "manager"
