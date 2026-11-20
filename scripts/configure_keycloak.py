#!/usr/bin/env python3
"""Configures the `corp` realm through the Keycloak admin REST API (idempotent).

1. Realm hardening: TLS everywhere, brute-force protection, short tokens, events on.
2. AD federation: LDAPS, read-only, least-privilege bind account, MSAD account controls.
3. AD groups imported as Keycloak groups; IT-Admins carries the realm role corp-admin.
4. Clients: portal-oidc (code + PKCE, back-channel logout), reporting-job (machine
   client, used to test audience checks), HR documents app (SAML, signed assertions).
5. MFA: TOTP required for anyone holding corp-admin; other users sign in with AD password.
"""
import os
import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
ADMIN_URL = os.environ.get("KC_ADMIN_URL", "https://sso-admin.localtest.me:7444")
REALM = "corp"
PORTAL = "https://portal.localtest.me:7443"
SAML_APP = "https://saml.localtest.me:7443"
BASE_DN = "DC=corp,DC=lab"
MFA_FLOW = "browser-mfa-admins"


def load_env():
    for line in (ROOT / ".env").read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            os.environ.setdefault(k, v)


class KC:
    """Admin REST client. Master-realm admin tokens live 60 s: re-authenticate on 401."""

    def __init__(self):
        self.s = requests.Session()
        self.s.verify = str(ROOT / "certs/ca.pem")
        self.login()

    def login(self):
        tok = self.s.post(f"{ADMIN_URL}/realms/master/protocol/openid-connect/token", data={
            "grant_type": "password", "client_id": "admin-cli",
            "username": os.environ["KC_ADMIN_USER"], "password": os.environ["KC_ADMIN_PASSWORD"],
        })
        tok.raise_for_status()
        self.s.headers["Authorization"] = f"Bearer {tok.json()['access_token']}"

    def __call__(self, method, path, **kw):
        url = f"{ADMIN_URL}/admin/realms{path}"
        r = self.s.request(method, url, **kw)
        if r.status_code == 401:
            self.login()
            r = self.s.request(method, url, **kw)
        if r.status_code >= 400:
            sys.exit(f"{method} {path} -> {r.status_code}: {r.text[:400]}")
        return r.json() if r.content and "json" in r.headers.get("content-type", "") else r


def step(msg):
    print(f"[+] {msg}")


def realm(kc):
    settings = {
        "realm": REALM, "enabled": True, "displayName": "CORP SSO",
        "sslRequired": "all",
        "registrationAllowed": False, "resetPasswordAllowed": False,  # passwords live in AD
        "rememberMe": False, "loginWithEmailAllowed": False, "duplicateEmailsAllowed": True,
        # Brute-force protection in front of AD: temporary lockout after 5 failures.
        "bruteForceProtected": True, "failureFactor": 5, "permanentLockout": False,
        "waitIncrementSeconds": 60, "maxFailureWaitSeconds": 900,
        "maxDeltaTimeSeconds": 43200, "quickLoginCheckMilliSeconds": 1000,
        "minimumQuickLoginWaitSeconds": 60,
        # Short-lived tokens; refresh tokens rotate and cannot be reused.
        "accessTokenLifespan": 300, "ssoSessionIdleTimeout": 1800, "ssoSessionMaxLifespan": 28800,
        "revokeRefreshToken": True, "refreshTokenMaxReuse": 0,
        "otpPolicyType": "totp", "otpPolicyAlgorithm": "HmacSHA1", "otpPolicyDigits": 6,
        "otpPolicyPeriod": 30, "otpPolicyCodeReusable": False,
    }
    existing = [r["realm"] for r in kc("GET", "")]
    if REALM not in existing:
        kc("POST", "", json=settings)
    else:
        kc("PUT", f"/{REALM}", json=settings)
    kc("PUT", f"/{REALM}/events/config", json={
        "eventsEnabled": True, "eventsListeners": ["jboss-logging"], "enabledEventTypes": [],
        "eventsExpiration": 7 * 86400, "adminEventsEnabled": True, "adminEventsDetailsEnabled": True,
    })
    step("realm corp: TLS required, brute-force protection, 5 min tokens, login + admin events")


def ldap(kc):
    cfg = {
        "vendor": ["ad"], "enabled": ["true"], "priority": ["0"],
        "connectionUrl": ["ldaps://dc1.corp.lab:636"], "useTruststoreSpi": ["always"],
        "startTls": ["false"], "authType": ["simple"],
        "bindDn": [f"CN=Keycloak Service,OU=Service,{BASE_DN}"],
        "bindCredential": [os.environ["AD_SVC_KEYCLOAK_PASSWORD"]],
        "editMode": ["READ_ONLY"],                 # AD stays the source of truth
        "usersDn": [f"OU=Staff,{BASE_DN}"], "searchScope": ["2"],
        "usernameLDAPAttribute": ["sAMAccountName"], "rdnLDAPAttribute": ["cn"],
        "uuidLDAPAttribute": ["objectGUID"], "userObjectClasses": ["person, organizationalPerson, user"],
        "customUserSearchFilter": ["(&(objectCategory=person)(objectClass=user))"],
        "importEnabled": ["true"], "syncRegistrations": ["false"], "pagination": ["true"],
        "connectionPooling": ["true"], "connectionTimeout": ["5000"], "readTimeout": ["10000"],
        # Directory changes (leaver, mover) must apply at the next login, not after a cache expiry.
        "cachePolicy": ["NO_CACHE"],
        "trustEmail": ["true"], "allowKerberosAuthentication": ["false"],
        "fullSyncPeriod": ["-1"], "changedSyncPeriod": ["300"],
    }
    comps = kc("GET", f"/{REALM}/components?type=org.keycloak.storage.UserStorageProvider")
    comp = next((c for c in comps if c["name"] == "corp-ad"), None)
    body = {"name": "corp-ad", "providerId": "ldap",
            "providerType": "org.keycloak.storage.UserStorageProvider", "config": cfg}
    if comp:
        kc("PUT", f"/{REALM}/components/{comp['id']}", json={**comp, **body})
    else:
        kc("POST", f"/{REALM}/components", json=body)
        comp = next(c for c in kc("GET", f"/{REALM}/components?type=org.keycloak.storage.UserStorageProvider")
                    if c["name"] == "corp-ad")
    lid = comp["id"]
    res = kc("POST", f"/{REALM}/testLDAPConnection", json={
        "action": "testAuthentication", "componentId": lid,
        "connectionUrl": cfg["connectionUrl"][0], "bindDn": cfg["bindDn"][0],
        "bindCredential": cfg["bindCredential"][0], "useTruststoreSpi": "always",
        "authType": "simple", "startTls": "false", "connectionTimeout": "5000"})
    step(f"AD federation over LDAPS, read-only, bind test: HTTP {res.status_code}")

    mappers = kc("GET", f"/{REALM}/components?parent={lid}")
    gm = next((m for m in mappers if m["name"] == "ad-groups"), None)
    gm_body = {
        "name": "ad-groups", "providerId": "group-ldap-mapper", "parentId": lid,
        "providerType": "org.keycloak.storage.ldap.mappers.LDAPStorageMapper",
        "config": {
            "groups.dn": [f"OU=Groups,{BASE_DN}"], "group.name.ldap.attribute": ["cn"],
            "group.object.classes": ["group"], "preserve.group.inheritance": ["false"],
            "membership.ldap.attribute": ["member"], "membership.attribute.type": ["DN"],
            "membership.user.ldap.attribute": ["sAMAccountName"], "mode": ["READ_ONLY"],
            "user.roles.retrieve.strategy": ["LOAD_GROUPS_BY_MEMBER_ATTRIBUTE"],
            "memberof.ldap.attribute": ["memberOf"], "ignore.missing.groups": ["false"],
            "drop.non.existing.groups.during.sync": ["false"], "groups.path": ["/"],
        }}
    if gm:
        kc("PUT", f"/{REALM}/components/{gm['id']}", json={**gm, **gm_body})
    else:
        kc("POST", f"/{REALM}/components", json=gm_body)
        gm = next(m for m in kc("GET", f"/{REALM}/components?parent={lid}") if m["name"] == "ad-groups")
    kc("POST", f"/{REALM}/user-storage/{lid}/mappers/{gm['id']}/sync?direction=fedToKeycloak")
    sync = kc("POST", f"/{REALM}/user-storage/{lid}/sync?action=triggerFullSync")
    names = sorted(m["name"] for m in kc("GET", f"/{REALM}/components?parent={lid}"))
    step(f"AD groups mapped; user sync: {sync.get('status')}; mappers: {', '.join(names)}")


def roles(kc):
    if not any(r["name"] == "corp-admin" for r in kc("GET", f"/{REALM}/roles")):
        kc("POST", f"/{REALM}/roles", json={
            "name": "corp-admin", "description": "Privileged administrators (MFA enforced)"})
    role = kc("GET", f"/{REALM}/roles/corp-admin")
    group = next(g for g in kc("GET", f"/{REALM}/groups?search=IT-Admins&exact=true")
                 if g["name"] == "IT-Admins")
    kc("POST", f"/{REALM}/groups/{group['id']}/role-mappings/realm", json=[role])
    step("realm role corp-admin granted to AD group IT-Admins")


def upsert_client(kc, client, mappers):
    found = kc("GET", f"/{REALM}/clients", params={"clientId": client["clientId"]})
    if found:
        cid = found[0]["id"]
        kc("PUT", f"/{REALM}/clients/{cid}", json={**found[0], **client})
    else:
        kc("POST", f"/{REALM}/clients", json=client)
        cid = kc("GET", f"/{REALM}/clients", params={"clientId": client["clientId"]})[0]["id"]
    for m in kc("GET", f"/{REALM}/clients/{cid}/protocol-mappers/models"):
        kc("DELETE", f"/{REALM}/clients/{cid}/protocol-mappers/models/{m['id']}")
    for m in mappers:
        kc("POST", f"/{REALM}/clients/{cid}/protocol-mappers/models", json=m)
    return cid


def clients(kc):
    groups_claim = {"name": "groups", "protocol": "openid-connect",
                    "protocolMapper": "oidc-group-membership-mapper",
                    "config": {"claim.name": "groups", "full.path": "false", "id.token.claim": "true",
                               "access.token.claim": "true", "userinfo.token.claim": "true"}}
    audience = {"name": "audience-portal", "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper",
                "config": {"included.client.audience": "portal-oidc", "access.token.claim": "true",
                           "id.token.claim": "false"}}
    upsert_client(kc, {
        "clientId": "portal-oidc", "name": "Corporate portal (OIDC)", "protocol": "openid-connect",
        "publicClient": False, "secret": os.environ["PORTAL_OIDC_CLIENT_SECRET"],
        "standardFlowEnabled": True, "directAccessGrantsEnabled": False,   # no password grant
        "implicitFlowEnabled": False, "serviceAccountsEnabled": False,
        "redirectUris": [f"{PORTAL}/callback"], "webOrigins": [PORTAL], "rootUrl": PORTAL,
        "frontchannelLogout": False,
        "attributes": {
            "pkce.code.challenge.method": "S256",
            "post.logout.redirect.uris": f"{PORTAL}/",
            "backchannel.logout.url": f"{PORTAL}/backchannel-logout",
            "backchannel.logout.session.required": "true",
            "backchannel.logout.revoke.offline.tokens": "true",
        },
    }, [groups_claim, audience])
    step("client portal-oidc: code flow + PKCE S256, exact redirect URI, back-channel logout")

    upsert_client(kc, {
        "clientId": "reporting-job", "name": "Nightly reporting job (machine identity)",
        "protocol": "openid-connect", "publicClient": False,
        "secret": os.environ["REPORTING_JOB_CLIENT_SECRET"],
        "standardFlowEnabled": False, "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": True,
    }, [])
    step("client reporting-job: client-credentials only (its tokens are NOT for the portal)")

    entity = f"{SAML_APP}/metadata"
    saml_mappers = [
        {"name": "groups", "protocol": "saml", "protocolMapper": "saml-group-membership-mapper",
         "config": {"attribute.name": "groups", "full.path": "false", "single": "false",
                    "attribute.nameformat": "Basic"}},
        {"name": "email", "protocol": "saml", "protocolMapper": "saml-user-property-mapper",
         "config": {"user.attribute": "email", "attribute.name": "email",
                    "attribute.nameformat": "Basic"}},
    ]
    upsert_client(kc, {
        "clientId": entity, "name": "HR documents (SAML)", "protocol": "saml",
        "redirectUris": [f"{SAML_APP}/acs"], "baseUrl": f"{SAML_APP}/", "frontchannelLogout": False,
        "attributes": {
            "saml_assertion_consumer_url_post": f"{SAML_APP}/acs",
            "saml.server.signature": "true", "saml.assertion.signature": "true",
            "saml.signature.algorithm": "RSA_SHA256", "saml.client.signature": "false",
            "saml.encrypt": "false", "saml.force.post.binding": "true",
            "saml.authnstatement": "true", "saml_force_name_id_format": "true",
            "saml_name_id_format": "username",
        },
    }, saml_mappers)
    # Data minimisation: drop default SAML client scopes (role_list sends every internal
    # role name). The app receives exactly email + groups.
    cid = kc("GET", f"/{REALM}/clients", params={"clientId": entity})[0]["id"]
    for sc in kc("GET", f"/{REALM}/clients/{cid}/default-client-scopes"):
        kc("DELETE", f"/{REALM}/clients/{cid}/default-client-scopes/{sc['id']}")
    step("client HR documents: SAML 2.0, signed response + signed assertion, RSA-SHA256, "
         "attributes limited to email + groups")


def mfa_flow(kc):
    flows = kc("GET", f"/{REALM}/authentication/flows")
    if not any(f["alias"] == MFA_FLOW for f in flows):
        kc("POST", f"/{REALM}/authentication/flows/browser/copy", json={"newName": MFA_FLOW})
    def second_factor_subflow():
        """Returns (sub-flow row, its direct children) for the 'Conditional 2FA/OTP' step."""
        execs = kc("GET", f"/{REALM}/authentication/flows/{MFA_FLOW}/executions")
        i = next(i for i, e in enumerate(execs) if e.get("authenticationFlow")
                 and ("Conditional 2FA" in e["displayName"] or "Conditional OTP" in e["displayName"]))
        sub, children = execs[i], []
        for e in execs[i + 1:]:
            if e["level"] <= sub["level"]:
                break
            if e["level"] == sub["level"] + 1:
                children.append(e)
        return sub, children

    sub, children = second_factor_subflow()
    # Replace the default conditions ("user has OTP configured", "credential used") with
    # "user holds corp-admin": an admin cannot skip MFA just because they never enrolled.
    for e in children:
        if e.get("providerId") in ("conditional-user-configured", "conditional-credential"):
            kc("DELETE", f"/{REALM}/authentication/executions/{e['id']}")
    sub, children = second_factor_subflow()
    cond = next((e for e in children if e.get("providerId") == "conditional-user-role"), None)
    if not cond:
        kc("POST", f"/{REALM}/authentication/flows/{requests.utils.quote(sub['displayName'])}"
                   "/executions/execution", json={"provider": "conditional-user-role"})
        sub, children = second_factor_subflow()
        cond = next(e for e in children if e.get("providerId") == "conditional-user-role")
    cond["requirement"] = "REQUIRED"
    kc("PUT", f"/{REALM}/authentication/flows/{MFA_FLOW}/executions", json=cond)
    if not cond.get("authenticationConfig"):
        kc("POST", f"/{REALM}/authentication/executions/{cond['id']}/config", json={
            "alias": "is-corp-admin", "config": {"condUserRole": "corp-admin", "negate": "false"}})
    # Explicit priorities: the role condition is listed (and read) before the OTP form.
    cond["priority"] = 5
    kc("PUT", f"/{REALM}/authentication/flows/{MFA_FLOW}/executions", json=cond)
    otp = next(e for e in children if e.get("providerId") == "auth-otp-form")
    otp["requirement"], otp["priority"] = "REQUIRED", 20
    kc("PUT", f"/{REALM}/authentication/flows/{MFA_FLOW}/executions", json=otp)
    rep = kc("GET", f"/{REALM}")
    rep["browserFlow"] = MFA_FLOW
    kc("PUT", f"/{REALM}", json=rep)
    sub, children = second_factor_subflow()
    order = [f"{e['displayName']} [{e['requirement']}]" for e in children]
    step(f"browser flow {MFA_FLOW}: password, then 2FA sub-flow: " + " -> ".join(order))


if __name__ == "__main__":
    load_env()
    kc = KC()
    realm(kc)
    ldap(kc)
    roles(kc)
    clients(kc)
    mfa_flow(kc)
    print("[=] Keycloak configured")
