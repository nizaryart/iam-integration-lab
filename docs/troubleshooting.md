# Troubleshooting runbook

Every entry follows the same pattern: symptom, cause, how to check, and the fix.
Entries marked **(observed)** happened while building this lab. The others are the
standard checks I run for this kind of integration.

## Directory (Samba AD / LDAP)

### DC exits during provisioning: `fset_nt_acl returned NT_STATUS_ACCESS_DENIED` (observed)
- **Cause:** SYSVOL NT ACLs are stored in `security.*` extended attributes, and writing
  them needs `CAP_SYS_ADMIN`.
- **Check:** `docker compose logs dc1 | grep set_nt_acl`
- **Fix:** add `cap_add: [SYS_ADMIN]` to the DC service. Full `privileged` mode isn't needed.

### DC exits after a rebuild: `Samba detected misconfigured 'server role'` (observed)
- **Cause:** `smb.conf` was in the container filesystem, not in the volume. A new container
  got Debian's default file while the AD database was still in the volume.
- **Check:** `docker compose exec dc1 readlink /etc/samba/smb.conf` should point to `/var/lib/samba/etc/smb.conf`.
- **Fix:** the entrypoint now moves `smb.conf` into the volume and symlinks it.

### `ldap_bind: Strong(er) authentication required (8)` / `Transport encryption required`
- **Cause:** a simple bind over plaintext LDAP (389). This is the intended setting
  (`ldap server require strong auth = yes`).
- **Fix:** use `ldaps://dc1.corp.lab:636`, or StartTLS. Don't relax the DC setting.

### LDAPS fails from Keycloak: `PKIX path building failed` or hostname mismatch
- **Cause:** Keycloak doesn't trust the DC's CA, or the URL host isn't in the certificate's SAN.
- **Check:**
  - `openssl s_client -connect dc1.corp.lab:636 -CAfile certs/ca.pem` (from a container on the directory network)
  - `openssl x509 -in certs/dc1.pem -noout -ext subjectAltName`
- **Fix:** `KC_TRUSTSTORE_PATHS` points to the CA. The connection URL uses the name in the SAN
  (`dc1.corp.lab`), not an IP.

### Keycloak "Test authentication" fails with `49 / data 52e`
- **Cause:** wrong bind DN or password. AD sub-codes: `52e` bad credentials, `533` disabled,
  `775` locked, `532` password expired.
- **Check:** bind by hand with `ldapsearch -H ldaps://dc1.corp.lab -D "<bind DN>" -W -b "<base>"`.

### A user changed groups in AD but the app still shows the old access (observed, by design)
- **Cause:** groups are copied into the token and the app session at login. The federation
  uses `NO_CACHE`, so the *next* login is correct, but an existing session keeps its old groups.
- **Fix:** have the user log in again, or revoke their sessions (`lifecycle.py leaver` does this
  for leavers). Short token lifetimes limit the window.

## SSO (Keycloak / OIDC / SAML)

### `Invalid parameter: redirect_uri`
- **Cause:** the redirect URI isn't an exact match: scheme, host, port, path, or a trailing slash.
- **Check:** compare the `redirect_uri` in the authorization request with the client's Valid redirect URIs.
- **Fix:** register the exact URI. Avoid wildcards.

### Authorization request rejected: `Missing parameter: code_challenge_method`
- **Cause:** PKCE is required for the client (`pkce.code.challenge.method = S256`) and the
  client didn't send it.
- **Fix:** send `code_challenge` and `code_challenge_method=S256`. Don't disable PKCE.

### API returns `401 invalid token: Audience doesn't match` (observed, by design)
- **Cause:** the token was issued to another client (here `reporting-job`), or the audience
  mapper is missing.
- **Fix:** request the token for the right client, or add an audience mapper if the API
  really should accept it.

### Disabled user sees "Invalid username or password", not "account disabled" (observed)
- **Cause:** Keycloak only sees a failed LDAP bind. Its event says
  `invalid_user_credentials`, the same as a typo.
- **Check:** the DC audit: `docker compose logs dc1 | grep NT_STATUS_ACCOUNT_DISABLED`,
  or `scripts/detect.py` (rule `AD-DISABLED`).
- **Fix:** none needed for users, since a generic message is safer. Support staff check the DC audit.

### Correct password refused right after a few failures (observed)
- **Cause:** brute-force protection. Five failures lock the account temporarily, and so do
  two failures less than one second apart ("quick login check").
- **Check:** `GET /admin/realms/corp/attack-detection/brute-force/users/{id}`
- **Fix:** wait, or unlock as a helpdesk action:
  `DELETE /admin/realms/corp/attack-detection/brute-force/users/{id}`. The unlock is logged
  as an admin event (`KC-PRIV`).

### Leaver still has access in the app after the AD account is disabled (observed)
- **Cause:** disabling the account blocks new logins only. Open application sessions continue.
  On Keycloak 26.4, the bulk `POST /users/{id}/logout` sent one back-channel logout for
  several sessions.
- **Check:**
  - the portal log shows one `back-channel logout: sid=...` line per session
  - `GET /admin/realms/corp/users/{id}/sessions` returns an empty list
- **Fix:** `lifecycle.py leaver` revokes every session with `DELETE /sessions/{id}` and fails
  if any session is left.

### SAML login works but the app sees no groups (observed)
- **Cause:** pysaml2 drops attributes with no known mapping (`groups` with the Basic name
  format) unless `allow_unknown_attributes` is set at the top level of the configuration.
- **Check:** decode the `SAMLResponse` (base64) and look at `AttributeStatement`.
- **Fix:** set `allow_unknown_attributes: True` in the SP configuration, or add an attribute map.

### SAML response rejected: `ResponseLifetimeExceed` / `ToEarly`
- **Cause:** clock skew between the IdP and the SP.
- **Check:** compare `date -u` on both hosts with the `NotBefore` / `NotOnOrAfter` values in the assertion.
- **Fix:** sync with NTP. A few seconds of tolerance (`accepted_time_diff`) is fine; minutes are not.

### SAML response rejected with `UnsolicitedResponse` (observed, by design)
- **Cause:** the response doesn't answer an AuthnRequest issued in this browser session.
  This is the case for a replay, a response stolen into another browser, or IdP-initiated SSO.
- **Fix:** none for attacks. If IdP-initiated SSO is a business need, enable it for that SP
  only, together with replay protection.

## Network / platform

### Public URL returns 403 on `/admin` (by design)
- The admin console is only on the management listener: `https://sso-admin.localtest.me:7444/admin/`.

### `bind: address already in use` when starting the proxy (observed)
- **Cause:** another lab already listens on the port.
- **Check:** `ss -ltnp | grep 7443` and `docker ps --format '{{.Names}} {{.Ports}}'`
- **Fix:** change the published port in `docker-compose.yml` *and* every URL that contains it
  (issuer, redirect URIs, `KC_HOSTNAME`). The issuer must be identical inside and outside Docker.

### Apps can't reach Keycloak, or the token issuer doesn't match
- **Cause:** containers and the browser must use the same issuer URL. Here the proxy carries
  network aliases (`sso.localtest.me`, ...) so containers resolve the public names to the proxy.
- **Check:** `docker compose exec portal-oidc python -c "import socket; print(socket.gethostbyname('sso.localtest.me'))"`

### Admin script fails after a minute with 401
- **Cause:** master-realm admin tokens live 60 seconds.
- **Fix:** the admin client re-authenticates on 401 (`scripts/configure_keycloak.py`, class `KC`).
