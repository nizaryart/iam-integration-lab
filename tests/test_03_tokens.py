"""Use case: an API validating access tokens. Forged and misdirected tokens are refused."""
import base64
import hashlib
import hmac
import json
import os

import jwt
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import lab

API = f"{lab.PORTAL}/api"


def call(path, token):
    return requests.get(f"{API}{path}", headers={"Authorization": f"Bearer {token}"}, verify=lab.CA)


def b64(data):
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()


def test_valid_token_and_group_authorization():
    alice = lab.access_token("alice")["access_token"]
    bob = lab.access_token("bob")["access_token"]
    assert call("/me", alice).json()["groups"] == ["Finance"]
    assert call("/finance/report", alice).status_code == 200
    assert call("/finance/report", bob).status_code == 403


def test_access_tokens_are_short_lived():
    claims = jwt.decode(lab.access_token("alice")["access_token"], options={"verify_signature": False})
    assert claims["exp"] - claims["iat"] <= 300


def test_missing_token():
    assert requests.get(f"{API}/me", verify=lab.CA).status_code == 401


def test_alg_none_is_rejected():
    claims = jwt.decode(lab.access_token("bob")["access_token"], options={"verify_signature": False})
    claims["groups"] = ["Finance"]
    forged = f"{b64({'alg': 'none', 'typ': 'JWT'})}.{b64(claims)}."
    assert call("/finance/report", forged).status_code == 401


def test_modified_payload_breaks_signature():
    header, _, signature = lab.access_token("bob")["access_token"].split(".")
    claims = jwt.decode(lab.access_token("bob")["access_token"], options={"verify_signature": False})
    claims["groups"] = ["Finance"]                     # privilege escalation attempt
    assert call("/finance/report", f"{header}.{b64(claims)}.{signature}").status_code == 401


def test_token_signed_by_attacker_key_is_rejected():
    real = lab.access_token("bob")["access_token"]
    kid = jwt.get_unverified_header(real)["kid"]       # reuse the real key id
    claims = jwt.decode(real, options={"verify_signature": False}) | {"groups": ["Finance"]}
    attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    forged = jwt.encode(claims, attacker, algorithm="RS256", headers={"kid": kid})
    assert call("/finance/report", forged).status_code == 401


def test_hs256_key_confusion_is_rejected():
    """Classic alg confusion: HMAC-sign with the server's *public* key as the secret."""
    real = lab.access_token("bob")["access_token"]
    jwks = requests.get(f"{lab.ISSUER}/protocol/openid-connect/certs", verify=lab.CA).json()
    rsa_jwk = next(k for k in jwks["keys"] if k.get("use") == "sig" and k["kty"] == "RSA")
    public_pem = jwt.PyJWK(rsa_jwk).key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    claims = jwt.decode(real, options={"verify_signature": False}) | {"groups": ["Finance"]}
    body = f"{b64({'alg': 'HS256', 'typ': 'JWT', 'kid': rsa_jwk['kid']})}.{b64(claims)}"
    sig = base64.urlsafe_b64encode(hmac.new(public_pem, body.encode(), hashlib.sha256).digest())
    assert call("/finance/report", f"{body}.{sig.rstrip(b'=').decode()}").status_code == 401


def test_token_issued_to_another_client_is_rejected():
    """reporting-job is a valid machine identity in the same realm, but not for this API."""
    tok = requests.post(f"{lab.ISSUER}/protocol/openid-connect/token", verify=lab.CA, data={
        "grant_type": "client_credentials", "client_id": "reporting-job",
        "client_secret": os.environ["REPORTING_JOB_CLIENT_SECRET"]}).json()["access_token"]
    r = call("/me", tok)
    assert r.status_code == 401 and "audience" in r.json()["detail"].lower()
