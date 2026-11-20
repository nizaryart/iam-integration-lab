"""Use case: identity x security monitoring. Lockout, then detections across Keycloak and AD."""
import secrets

import detect
import lab
import lifecycle


def test_bruteforce_locks_account_and_is_detected(kc):
    for _ in range(5):
        assert not lab.logged_in(lab.Browser().portal_login("bob", password="Winter2026!"))
    page = lab.Browser().portal_login("bob")                    # right password, still refused
    assert not lab.logged_in(page)
    bob = lab.user_id(kc, "bob")
    assert kc("GET", f"/corp/attack-detection/brute-force/users/{bob}")["disabled"] is True

    alerts = detect.run(minutes=5, kc=kc)
    rules = {(a["rule"], a["user"]) for a in alerts}
    assert ("KC-BRUTE", "bob") in rules
    assert ("KC-LOCKED", "bob") in rules

    kc("DELETE", f"/corp/attack-detection/brute-force/users/{bob}")   # unlock (helpdesk action)
    assert lab.logged_in(lab.Browser().portal_login("bob"))


def test_leaver_sign_in_attempt_is_correlated_with_ad(kc):
    name = f"frank{secrets.token_hex(3)}"
    lifecycle.joiner(name, "HR", "Frank", "Test")
    try:
        lifecycle.leaver(name, kc)
        assert not lab.logged_in(lab.Browser().portal_login(name))
        hits = [a for a in detect.run(minutes=5, kc=kc) if a["rule"] == "AD-DISABLED" and a["user"] == name]
        assert hits, "disabled-account logon not detected"
        ev = hits[0]["evidence"]
        assert ev["dc_status"] == "NT_STATUS_ACCOUNT_DISABLED" and ev["dc_event"] == 4625
        assert ev["keycloak_error"] == "invalid_user_credentials" and ev["client"] == "portal-oidc"
    finally:
        lifecycle.delete(name, kc)


def test_password_spray_is_detected(kc):
    for user in ("alice", "bob", "carol"):
        lab.Browser().portal_login(user, password="Spring2026!")
    sprays = [a for a in detect.run(minutes=5, kc=kc) if a["rule"] == "AD-SPRAY"]
    assert sprays and {"alice", "bob", "carol"} <= set(sprays[-1]["evidence"]["accounts"])
    kc("DELETE", "/corp/attack-detection/brute-force/users")


def test_privilege_change_is_visible(kc):
    role = kc("GET", "/corp/roles/corp-admin")
    alice = lab.user_id(kc, "alice")
    kc("POST", f"/corp/users/{alice}/role-mappings/realm", json=[role])      # out-of-process grant
    kc("DELETE", f"/corp/users/{alice}/role-mappings/realm", json=[role])
    priv = [a for a in detect.run(minutes=5, kc=kc) if a["rule"] == "KC-PRIV" and alice in a["summary"]]
    assert any("role-mappings" in a["summary"] for a in priv)
