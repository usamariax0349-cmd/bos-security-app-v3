"""Feature flags for gradual rollout: superadmin-only management, and the
deterministic bucketing that lets a flag be "on for 50% of accounts" without
any one account's experience flickering between requests.
"""
import time

import pytest


@pytest.fixture
def flag_key():
    return f"test_flag_{int(time.time()*1000)}"


def test_flags_crud_requires_superadmin(api, admin_token, guard_with_password, flag_key):
    guard_id, email, password = guard_with_password
    status, login = api.call("POST", "/api/guard/login", {"email": email, "password": password})
    guard_token = login["token"]

    # A guard session isn't an admin session at all.
    status, err = api.call("GET", "/api/feature-flags", token=guard_token)
    assert status == 401

    status, admin = api.call(
        "POST", "/api/admins",
        {"name": "Flags Test Manager", "email": f"flags-mgr-{time.time()}@bos-tests.local",
         "password": "TempPass123!", "role": "manager"},
        token=admin_token,
    )
    email2 = admin["email"]
    _, login2 = api.call("POST", "/api/login", {"email": email2, "password": "TempPass123!"})
    _, setup = api.call(
        "POST", "/api/setup-password",
        {"new_password": "RealPass123!", "confirm_password": "RealPass123!"}, token=login2["token"],
    )
    manager_token = setup["token"]

    # A manager is an admin, but not superadmin — feature flags gate real
    # production behavior, so this stays one notch more locked down.
    status, err = api.call("GET", "/api/feature-flags", token=manager_token)
    assert status == 403
    status, err = api.call("POST", "/api/feature-flags", {"key": flag_key}, token=manager_token)
    assert status == 403

    status, ok = api.call("GET", "/api/feature-flags", token=admin_token)
    assert status == 200

    status, created = api.call(
        "POST", "/api/feature-flags", {"key": flag_key, "enabled": True, "rollout_pct": 100}, token=admin_token,
    )
    assert status == 200, created

    status, err = api.call("DELETE", f"/api/feature-flags/{flag_key}", token=manager_token)
    assert status == 403
    status, ok = api.call("DELETE", f"/api/feature-flags/{flag_key}", token=admin_token)
    assert status == 200


def test_invalid_key_format_rejected(api, admin_token):
    status, err = api.call("POST", "/api/feature-flags", {"key": "Not Valid Key!"}, token=admin_token)
    assert status == 400
    assert "snake_case" in err.get("error", "").lower()


def test_invalid_rollout_pct_rejected(api, admin_token, flag_key):
    status, err = api.call(
        "POST", "/api/feature-flags", {"key": flag_key, "rollout_pct": 150}, token=admin_token,
    )
    assert status == 400


def test_disabled_flag_is_off_for_everyone(api, admin_token, guard_with_password, flag_key):
    guard_id, email, password = guard_with_password
    api.call("POST", "/api/feature-flags", {"key": flag_key, "enabled": False, "rollout_pct": 100}, token=admin_token)

    _, login = api.call("POST", "/api/guard/login", {"email": email, "password": password})
    status, mine = api.call("GET", "/api/feature-flags/mine", token=login["token"])
    assert status == 200
    assert mine[flag_key] is False


def test_full_and_zero_rollout_are_all_or_nothing(api, admin_token, guard_with_password, flag_key):
    guard_id, email, password = guard_with_password
    _, login = api.call("POST", "/api/guard/login", {"email": email, "password": password})
    guard_token = login["token"]

    api.call("POST", "/api/feature-flags", {"key": flag_key, "enabled": True, "rollout_pct": 100}, token=admin_token)
    status, mine = api.call("GET", "/api/feature-flags/mine", token=guard_token)
    assert mine[flag_key] is True

    api.call("POST", "/api/feature-flags", {"key": flag_key, "enabled": True, "rollout_pct": 0}, token=admin_token)
    status, mine = api.call("GET", "/api/feature-flags/mine", token=guard_token)
    assert mine[flag_key] is False


def test_partial_rollout_is_stable_per_subject_not_random_per_request(api, admin_token, guard_with_password, flag_key):
    guard_id, email, password = guard_with_password
    _, login = api.call("POST", "/api/guard/login", {"email": email, "password": password})
    guard_token = login["token"]

    api.call("POST", "/api/feature-flags", {"key": flag_key, "enabled": True, "rollout_pct": 50}, token=admin_token)

    results = []
    for _ in range(5):
        status, mine = api.call("GET", "/api/feature-flags/mine", token=guard_token)
        assert status == 200
        results.append(mine[flag_key])
    assert len(set(results)) == 1, "the same guard must land on the same side of a rollout every time"


def test_deleted_flag_no_longer_appears(api, admin_token, guard_with_password, flag_key):
    guard_id, email, password = guard_with_password
    api.call("POST", "/api/feature-flags", {"key": flag_key, "enabled": True, "rollout_pct": 100}, token=admin_token)
    api.call("DELETE", f"/api/feature-flags/{flag_key}", token=admin_token)

    _, login = api.call("POST", "/api/guard/login", {"email": email, "password": password})
    status, mine = api.call("GET", "/api/feature-flags/mine", token=login["token"])
    assert status == 200
    assert flag_key not in mine
