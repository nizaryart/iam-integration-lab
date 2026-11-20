"""Test helpers: a scripted 'browser', the Keycloak admin API and AD commands."""
import base64
import hashlib
import html
import os
import re
import secrets
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

import pyotp
import requests

ROOT = Path(__file__).resolve().parent.parent
CA = str(ROOT / "certs/ca.pem")
SSO = "https://sso.localtest.me:7443"
ISSUER = f"{SSO}/realms/corp"
PORTAL = "https://portal.localtest.me:7443"
SAML_APP = "https://saml.localtest.me:7443"

for _line in (ROOT / ".env").read_text().splitlines():
    if "=" in _line and not _line.startswith("#"):
        _k, _v = _line.split("=", 1)
        os.environ.setdefault(_k, _v)
PASSWORD = os.environ["AD_USER_PASSWORD"]

sys.path.insert(0, str(ROOT / "scripts"))
from configure_keycloak import KC  # noqa: E402


def admin():
    return KC()


# ---------------- Active Directory (samba-tool inside dc1) ----------------

def compose(*args, check=True):
    return subprocess.run(["docker", "compose", *args], cwd=ROOT, check=check,
                          capture_output=True, text=True)


def samba(*args, check=True):
    return compose("exec", "-T", "dc1", "samba-tool", *args, check=check)


# ---------------- Scripted browser ----------------

def form(page, form_id=None):
    """Returns (action, hidden inputs) of a form on an HTML page."""
    pattern = r'<form[^>]*id="%s"[^>]*>' % form_id if form_id else r"<form[^>]*>"
    tag = re.search(pattern, page.text)
    if not tag:
        return None, {}
    action = html.unescape(re.search(r'action="([^"]+)"', tag.group(0)).group(1))
    hidden = dict(re.findall(r'<input[^>]*type="hidden"[^>]*name="([^"]+)"[^>]*value="([^"]*)"', page.text))
    return action, {k: html.unescape(v) for k, v in hidden.items()}


class Browser:
    def __init__(self):
        self.s = requests.Session()
        self.s.verify = CA
        self.last_otp = None

    def get(self, url, **kw):
        return self.s.get(url, **kw)

    def kc_login(self, page, username, password=PASSWORD, otp_secret=None):
        """Fills Keycloak pages (password, TOTP enrolment, TOTP) until we leave the login UI."""
        action, _ = form(page, "kc-form-login")
        page = self.s.post(action, data={"username": username, "password": password, "credentialId": ""})
        for _ in range(3):
            if 'id="kc-totp-settings-form"' in page.text:      # forced enrolment for admins
                action, hidden = form(page, "kc-totp-settings-form")
                raw = hidden["totpSecret"]
                self.enrolled_secret = base64.b32encode(raw.encode()).decode()
                page = self.s.post(action, data={"totp": self.otp(self.enrolled_secret),
                                                 "totpSecret": raw, "userLabel": "pytest"})
            elif 'id="kc-otp-login-form"' in page.text:
                if not otp_secret:                              # stop on the OTP page
                    break
                action, hidden = form(page, "kc-otp-login-form")
                code = "000000" if otp_secret == "WRONG" else self.otp(otp_secret)
                page = self.s.post(action, data={**hidden, "otp": code})
                if otp_secret == "WRONG":
                    break
            else:
                break
        return page

    def otp(self, secret):
        """Current TOTP code; waits for a fresh window, Keycloak refuses code reuse."""
        totp = pyotp.TOTP(secret)
        code = totp.now()
        while code == Browser._last_code.get(secret):
            time.sleep(1)
            code = totp.now()
        Browser._last_code[secret] = code
        return code

    _last_code: dict = {}

    def portal_login(self, username, password=PASSWORD, otp_secret=None):
        page = self.get(f"{PORTAL}/login")
        return self.kc_login(page, username, password, otp_secret)

    def saml_response(self, username=None, password=PASSWORD):
        """Starts SP-initiated SAML SSO and returns (acs_url, fields) without posting them."""
        page = self.get(f"{SAML_APP}/login")
        if 'id="kc-form-login"' in page.text:
            page = self.kc_login(page, username, password)
        action, _ = form(page)
        fields = dict(re.findall(r'<input[^>]*name="(SAMLResponse|RelayState)"[^>]*value="([^"]*)"', page.text))
        return action, fields


def logged_in(page):
    return urlparse(page.url).hostname == "portal.localtest.me" and "Welcome" in page.text


# ---------------- Tokens obtained the way a client would ----------------

def access_token(username, password=PASSWORD):
    """Authorization code + PKCE as client portal-oidc, returns the token response."""
    b = Browser()
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    state = secrets.token_urlsafe(16)
    query = urlencode({"client_id": "portal-oidc", "response_type": "code", "scope": "openid",
                       "redirect_uri": f"{PORTAL}/callback", "state": state,
                       "code_challenge": challenge, "code_challenge_method": "S256"})
    page = b.get(f"{ISSUER}/protocol/openid-connect/auth?{query}")
    action, _ = form(page, "kc-form-login")
    resp = b.s.post(action, data={"username": username, "password": password, "credentialId": ""},
                    allow_redirects=False)
    params = parse_qs(urlparse(resp.headers["Location"]).query)
    assert params["state"] == [state]
    tok = requests.post(f"{ISSUER}/protocol/openid-connect/token", verify=CA, data={
        "grant_type": "authorization_code", "code": params["code"][0], "code_verifier": verifier,
        "redirect_uri": f"{PORTAL}/callback", "client_id": "portal-oidc",
        "client_secret": os.environ["PORTAL_OIDC_CLIENT_SECRET"]})
    tok.raise_for_status()
    return tok.json()


def user_id(kc, username):
    users = kc("GET", "/corp/users", params={"username": username, "exact": "true"})
    return users[0]["id"] if users else None
