"""Use case: identity x systems. Joiner, mover, leaver driven from Active Directory."""
import secrets

import pytest

import lab
import lifecycle


@pytest.fixture(scope="module")
def dave(kc):
    name = f"dave{secrets.token_hex(3)}"
    lifecycle.joiner(name, "Finance", "Dave", "Test")
    yield name
    lifecycle.delete(name, kc)


def test_joiner_gets_access_from_ad_group_alone(dave):
    b = lab.Browser()
    page = b.portal_login(dave)                   # nothing configured in Keycloak by hand
    assert lab.logged_in(page)
    assert b.get(f"{lab.PORTAL}/finance").status_code == 200


def test_mover_loses_old_access_at_next_login(dave):
    before = lab.Browser()
    before.portal_login(dave)
    lifecycle.mover(dave, "Finance", "HR")
    after = lab.Browser()
    after.portal_login(dave)
    assert after.get(f"{lab.PORTAL}/finance").status_code == 403
    assert after.get(f"{lab.PORTAL}/hr").status_code == 200
    # Documented limitation: a session opened before the move keeps its old groups.
    assert before.get(f"{lab.PORTAL}/finance").status_code == 200


def test_leaver_new_logins_refused_and_open_sessions_revoked(dave, kc):
    laptop, phone = lab.Browser(), lab.Browser()   # two sessions still open (regression guard)
    assert lab.logged_in(laptop.portal_login(dave)) and lab.logged_in(phone.portal_login(dave))
    token = lab.access_token(dave)["access_token"]

    revoked = lifecycle.leaver(dave, kc)
    assert revoked >= 2

    page = lab.Browser().portal_login(dave)       # 1. new login refused
    assert not lab.logged_in(page)
    # Generic message on purpose: no account-state disclosure (the DC audit has the reason).
    assert "Invalid username or password" in page.text

    for device in (laptop, phone):                  # 2. every open portal session killed
        r = device.get(f"{lab.PORTAL}/hr", allow_redirects=False)
        assert r.status_code == 302 and "/login" in r.headers["Location"]

    # 3. Residual risk, by design of stateless JWTs: an access token already issued stays
    #    valid at the API until it expires (5 minutes max in this realm).
    import requests
    r = requests.get(f"{lab.PORTAL}/api/me", headers={"Authorization": f"Bearer {token}"}, verify=lab.CA)
    assert r.status_code == 200


def test_disabling_in_ad_alone_leaves_sessions_open(kc):
    """Why the leaver procedure has a second step."""
    name = f"erin{secrets.token_hex(3)}"
    lifecycle.joiner(name, "HR", "Erin", "Test")
    try:
        b = lab.Browser()
        assert lab.logged_in(b.portal_login(name))
        lab.samba("user", "disable", name)        # AD only, no Keycloak revocation
        assert b.get(f"{lab.PORTAL}/hr").status_code == 200
    finally:
        lifecycle.delete(name, kc)
