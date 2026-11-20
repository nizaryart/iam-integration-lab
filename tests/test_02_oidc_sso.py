"""Use case: AD group -> application access through OIDC single sign-on."""
import requests

import lab


def test_finance_user_gets_finance_only():
    b = lab.Browser()
    page = b.portal_login("alice")
    assert lab.logged_in(page) and "Finance" in page.text
    assert b.get(f"{lab.PORTAL}/finance").status_code == 200
    assert b.get(f"{lab.PORTAL}/hr").status_code == 403
    assert b.get(f"{lab.PORTAL}/admin").status_code == 403


def test_hr_user_gets_hr_only():
    b = lab.Browser()
    assert lab.logged_in(b.portal_login("bob"))
    assert b.get(f"{lab.PORTAL}/hr").status_code == 200
    assert b.get(f"{lab.PORTAL}/finance").status_code == 403


def test_wrong_password_does_not_log_in():
    page = lab.Browser().portal_login("alice", password="not-the-password")
    assert not lab.logged_in(page)
    assert "Invalid username or password" in page.text


def test_sso_session_is_reused_by_second_app():
    b = lab.Browser()
    b.portal_login("alice")
    action, fields = b.saml_response()            # no password prompt this time
    assert action == f"{lab.SAML_APP}/acs" and "SAMLResponse" in fields


def test_password_grant_is_disabled():
    r = requests.post(f"{lab.ISSUER}/protocol/openid-connect/token", verify=lab.CA, data={
        "grant_type": "password", "client_id": "portal-oidc", "username": "alice",
        "password": lab.PASSWORD, "client_secret": lab.os.environ["PORTAL_OIDC_CLIENT_SECRET"]})
    assert r.status_code in (400, 401) and r.json()["error"] == "unauthorized_client"


def test_unregistered_redirect_uri_is_refused():
    r = requests.get(f"{lab.ISSUER}/protocol/openid-connect/auth", verify=lab.CA, params={
        "client_id": "portal-oidc", "response_type": "code", "scope": "openid",
        "redirect_uri": "https://attacker.example/callback"})
    assert r.status_code == 400 and "Invalid parameter: redirect_uri" in r.text


def test_pkce_is_mandatory():
    r = requests.get(f"{lab.ISSUER}/protocol/openid-connect/auth", verify=lab.CA,
                     allow_redirects=False, params={
                         "client_id": "portal-oidc", "response_type": "code", "scope": "openid",
                         "redirect_uri": f"{lab.PORTAL}/callback"})
    assert r.status_code == 302 and "code_challenge" in r.headers["Location"]
    assert "error=invalid_request" in r.headers["Location"]


def test_open_redirect_after_login_is_neutralised():
    b = lab.Browser()
    page = b.kc_login(b.get(f"{lab.PORTAL}/login?next=//attacker.example/"), "alice")
    assert page.url == f"{lab.PORTAL}/"
