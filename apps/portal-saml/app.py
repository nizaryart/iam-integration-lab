"""HR documents app: SAML 2.0 service provider (SP-initiated, HTTP-POST binding).

Requires a signed Response *and* a signed Assertion from the IdP, accepts only responses
to AuthnRequests it issued itself (no unsolicited/IdP-initiated SSO, no replay), and
authorizes pages from the `groups` attribute.
"""
import os
import tempfile
import time

import requests
from flask import Flask, abort, redirect, request, session
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client
from saml2.config import SPConfig
from werkzeug.middleware.proxy_fix import ProxyFix

BASE_URL = os.environ["BASE_URL"]
IDP_METADATA_URL = os.environ["IDP_METADATA_URL"]
ENTITY_ID = f"{BASE_URL}/metadata"

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET"]
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
app.config.update(SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True,
                  SESSION_COOKIE_SAMESITE="None",   # the IdP returns via cross-site POST
                  SESSION_COOKIE_NAME="saml_session")

ACCESS = {"hr-documents": "HR", "finance-documents": "Finance"}
_client = None


def client():
    """Builds the SP lazily, once Keycloak publishes the realm's IdP metadata."""
    global _client
    if _client is None:
        for _ in range(30):
            try:
                xml = requests.get(IDP_METADATA_URL, timeout=5)
                xml.raise_for_status()
                break
            except requests.RequestException:
                time.sleep(2)
        else:
            abort(503, "IdP metadata unavailable")
        path = os.path.join(tempfile.gettempdir(), "idp-metadata.xml")
        with open(path, "w") as fh:
            fh.write(xml.text)
        cfg = SPConfig()
        cfg.load({
            "entityid": ENTITY_ID,
            "metadata": {"local": [path]},
            "xmlsec_binary": "/usr/bin/xmlsec1",
            "service": {"sp": {
                "endpoints": {"assertion_consumer_service": [(f"{BASE_URL}/acs", BINDING_HTTP_POST)]},
                "allow_unsolicited": False,          # only answers to our own AuthnRequests
                "want_response_signed": True,
                "want_assertions_signed": True,
                "authn_requests_signed": False,
                "name_id_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
            }},
            # `groups` is a custom attribute with no standard OID mapping: keep it.
            "allow_unknown_attributes": True,
            "accepted_time_diff": 5,
        })
        _client = Saml2Client(config=cfg)
    return _client


def current_user():
    return session.get("user")


@app.get("/")
def index():
    user = current_user()
    if not user:
        return '<h1>HR documents (SAML)</h1><a href="/login">Sign in with CORP SSO</a>'
    links = " | ".join(f'<a href="/{p}">{p}</a>' for p in ACCESS)
    return (f"<h1>Welcome {user['name_id']}</h1><p>Groups: {', '.join(user['groups']) or '-'}</p>"
            f"<p>{links}</p>")


@app.get("/login")
def login():
    req_id, info = client().prepare_for_authenticate(binding=BINDING_HTTP_REDIRECT)
    # Remember the request ID: the response must answer *this* request (InResponseTo).
    session["outstanding"] = {req_id: f"{BASE_URL}/"}
    return redirect(dict(info["headers"])["Location"])


@app.post("/acs")
def acs():
    outstanding = session.pop("outstanding", {})   # single use: a replayed response finds nothing
    try:
        resp = client().parse_authn_request_response(
            request.form["SAMLResponse"], BINDING_HTTP_POST, outstanding=outstanding)
        if resp is None:
            raise ValueError("empty response")
    except Exception as exc:  # noqa: BLE001 - signature, InResponseTo, audience, time checks
        app.logger.warning("SAML response rejected: %s: %s", type(exc).__name__, exc)
        abort(403, f"SAML response rejected ({type(exc).__name__})")
    ava = resp.get_identity()
    session.clear()
    session["user"] = {"name_id": resp.name_id.text, "groups": sorted(ava.get("groups", []))}
    return redirect("/")


@app.get("/<page>")
def protected(page):
    if page not in ACCESS:
        abort(404)
    user = current_user()
    if not user:
        return redirect("/login")
    if ACCESS[page] not in user["groups"]:
        abort(403, f"requires AD group {ACCESS[page]}")
    return f"<h1>{page}</h1><p>Access granted to {user['name_id']}</p>"


@app.get("/metadata")
def metadata():
    from saml2.metadata import create_metadata_string
    return create_metadata_string(None, config=client().config), 200, {"Content-Type": "text/xml"}


@app.errorhandler(403)
def forbidden(err):
    return f"<h1>403 Forbidden</h1><p>{err.description}</p>", 403


@app.get("/healthz")
def healthz():
    return "ok"
