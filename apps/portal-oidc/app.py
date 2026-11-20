"""Corporate portal: OpenID Connect relying party (Authorization Code + PKCE).

Browser routes use a server-side login session; /api/* routes accept Bearer access
tokens and validate them locally against the realm's JWKS. Authorization decisions
come from the AD groups that Keycloak puts in the `groups` claim.
"""
import os
import secrets
import threading
import time

import jwt
import requests
from authlib.integrations.flask_client import OAuth
from flask import Flask, abort, jsonify, redirect, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

ISSUER = os.environ["ISSUER"]
CLIENT_ID = os.environ["CLIENT_ID"]
BASE_URL = os.environ["BASE_URL"]

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET"]
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
app.config.update(SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True,
                  SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_NAME="portal_session")

oauth = OAuth(app)
oauth.register(
    "corp",
    client_id=CLIENT_ID,
    client_secret=os.environ["CLIENT_SECRET"],
    server_metadata_url=f"{ISSUER}/.well-known/openid-configuration",
    client_kwargs={"scope": "openid profile email", "code_challenge_method": "S256"},
)

# Ended by back-channel logout. In memory: one process, lab only.
revoked_sids: set[str] = set()          # one Keycloak session
revoked_subs: dict[str, float] = {}     # every session of a user opened before this time
_lock = threading.Lock()

# Which AD group opens which page.
ACCESS = {"finance": "Finance", "hr": "HR", "admin": "IT-Admins"}


def current_user():
    user = session.get("user")
    if not user:
        return None
    with _lock:
        if user.get("sid") in revoked_sids or \
                user.get("login_at", 0) <= revoked_subs.get(user.get("sub"), -1):
            session.clear()
            return None
    return user


def require_group(group):
    user = current_user()
    if not user:
        return redirect(url_for("login", next=request.path))
    if group not in user["groups"]:
        abort(403, f"requires AD group {group}")
    return None


@app.get("/")
def index():
    user = current_user()
    if not user:
        return '<h1>Corporate portal</h1><a href="/login">Sign in with CORP SSO</a>'
    links = " | ".join(f'<a href="/{p}">{p}</a>' for p in ACCESS)
    return (f"<h1>Welcome {user['username']}</h1><p>Groups: {', '.join(user['groups']) or '-'}</p>"
            f"<p>{links}</p><a href='/logout'>Sign out</a>")


@app.get("/login")
def login():
    session["next"] = request.args.get("next", "/")
    return oauth.corp.authorize_redirect(f"{BASE_URL}/callback")


@app.get("/callback")
def callback():
    # Authlib checks state, PKCE verifier, and the ID token (signature, iss, aud, exp, nonce).
    token = oauth.corp.authorize_access_token()
    claims = token["userinfo"]
    next_page = session.get("next", "/")
    session.clear()             # new session after login: no session fixation
    session["user"] = {
        "username": claims.get("preferred_username"),
        "groups": sorted(claims.get("groups", [])),
        "sid": claims.get("sid"),
        "sub": claims.get("sub"),
        "login_at": time.time(),
    }
    session["id_token"] = token["id_token"]
    return redirect(safe_next(next_page))


def safe_next(target):
    """Only local paths: no open redirect through ?next=."""
    if not target or not target.startswith("/") or target.startswith("//") or "\\" in target:
        return "/"
    return target


@app.get("/<page>")
def protected(page):
    if page not in ACCESS:
        abort(404)
    denied = require_group(ACCESS[page])
    if denied:
        return denied
    return f"<h1>{page.upper()} area</h1><p>Access granted to {session['user']['username']}</p>"


@app.get("/logout")
def logout():
    id_token = session.get("id_token")
    session.clear()
    meta = oauth.corp.load_server_metadata()
    if not id_token:
        return redirect("/")
    return redirect(f"{meta['end_session_endpoint']}?id_token_hint={id_token}"
                    f"&post_logout_redirect_uri={BASE_URL}/")


@app.post("/backchannel-logout")
def backchannel_logout():
    """OIDC Back-Channel Logout: Keycloak tells us a session ended (logout, admin revoke)."""
    try:
        claims = validate_jwt(request.form["logout_token"], audience=CLIENT_ID, require_exp=False)
    except Exception as exc:  # noqa: BLE001 - any validation failure is a 400
        abort(400, f"invalid logout token: {exc}")
    if "http://schemas.openid.net/event/backchannel-logout" not in claims.get("events", {}):
        abort(400, "not a logout token")
    with _lock:
        if claims.get("sid"):
            revoked_sids.add(claims["sid"])
        else:                                    # sub-only token: all sessions of the user
            revoked_subs[claims["sub"]] = time.time()
    app.logger.warning("back-channel logout: sid=%s sub=%s", claims.get("sid"), claims.get("sub"))
    return "", 200


# ---------------- API: Bearer access tokens ----------------

_jwks = {"keys": None, "fetched": 0.0}


def signing_key(kid):
    if _jwks["keys"] is None or time.time() - _jwks["fetched"] > 300:
        meta = oauth.corp.load_server_metadata()
        _jwks["keys"] = jwt.PyJWKSet.from_dict(requests.get(meta["jwks_uri"], timeout=5).json())
        _jwks["fetched"] = time.time()
    for key in _jwks["keys"].keys:
        if key.key_id == kid:
            return key.key
    raise jwt.InvalidTokenError("unknown kid")


def validate_jwt(token, audience, require_exp=True):
    header = jwt.get_unverified_header(token)
    if header.get("alg") != "RS256":            # pin the algorithm: no 'none', no HS256 confusion
        raise jwt.InvalidAlgorithmError(f"alg {header.get('alg')} not allowed")
    return jwt.decode(
        token, signing_key(header.get("kid")), algorithms=["RS256"], audience=audience,
        issuer=ISSUER, leeway=5,
        options={"require": ["iss", "aud", "iat"] + (["exp"] if require_exp else [])},
    )


def bearer_claims():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        abort(401, "missing bearer token")
    try:
        return validate_jwt(auth[7:], audience=CLIENT_ID)
    except jwt.PyJWTError as exc:
        abort(401, f"invalid token: {exc}")


@app.get("/api/me")
def api_me():
    claims = bearer_claims()
    return jsonify(sub=claims["sub"], username=claims.get("preferred_username"),
                   groups=claims.get("groups", []), aud=claims["aud"])


@app.get("/api/finance/report")
def api_finance():
    claims = bearer_claims()
    if "Finance" not in claims.get("groups", []):
        abort(403, "requires AD group Finance")
    return jsonify(report="Q3 budget", requested_by=claims.get("preferred_username"))


@app.errorhandler(401)
@app.errorhandler(403)
@app.errorhandler(400)
def error(err):
    if request.path.startswith("/api/") or request.path == "/backchannel-logout":
        return jsonify(error=err.name, detail=err.description), err.code
    return f"<h1>{err.code} {err.name}</h1><p>{err.description}</p>", err.code


@app.get("/healthz")
def healthz():
    return "ok"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
