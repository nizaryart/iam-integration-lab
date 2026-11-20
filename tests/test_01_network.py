"""Use case: identity x network. Segmentation, transport security, exposed surface."""
import requests

import lab


def connect_from(service, host, port):
    code = (f"import socket\ntry:\n socket.create_connection(('{host}',{port}),3); print('OPEN')\n"
            f"except Exception as e: print('BLOCKED', type(e).__name__)")
    return lab.compose("exec", "-T", service, "python", "-c", code).stdout.strip()


def test_applications_cannot_reach_the_directory():
    assert connect_from("portal-oidc", "dc1.corp.lab", 636).startswith("BLOCKED")
    assert connect_from("portal-saml", "dc1.corp.lab", 636).startswith("BLOCKED")


def test_applications_cannot_bypass_the_proxy_to_keycloak():
    assert connect_from("portal-oidc", "keycloak", 8080).startswith("BLOCKED")


def test_keycloak_reaches_the_directory_over_ldaps_only():
    probe = "exec 3<>/dev/tcp/dc1.corp.lab/{} && echo OPEN || echo BLOCKED"
    assert "OPEN" in lab.compose("exec", "-T", "keycloak", "bash", "-c", probe.format(636)).stdout


def test_directory_is_not_published_on_the_host():
    assert lab.compose("port", "dc1", "636", check=False).stdout.strip() in ("", ":0")
    assert lab.compose("port", "dc1", "389", check=False).stdout.strip() in ("", ":0")


def test_plaintext_ldap_bind_is_refused():
    out = lab.compose("exec", "-T", "-e", f"P={lab.os.environ['AD_SVC_KEYCLOAK_PASSWORD']}", "dc1",
                      "bash", "-c", 'ldapsearch -H ldap://dc1.corp.lab -x -D '
                      '"CN=Keycloak Service,OU=Service,DC=corp,DC=lab" -w "$P" -s base -b "" 2>&1',
                      check=False).stdout
    assert "Strong(er) authentication required" in out


def test_ldaps_certificate_is_verified():
    out = lab.compose("exec", "-T", "dc1", "bash", "-c",
                      "LDAPTLS_CACERT=/certs/ca.pem ldapsearch -H ldaps://dc1.corp.lab -x -s base -b '' "
                      "namingContexts 2>&1; echo; LDAPTLS_CACERT=/etc/ssl/certs/ca-certificates.crt "
                      "ldapsearch -H ldaps://dc1.corp.lab -x -s base -b '' 2>&1", check=False).stdout
    assert "namingContexts: DC=corp,DC=lab" in out          # trusted lab CA: OK
    assert "Can't contact LDAP server" in out                # unknown CA: TLS refused


def test_admin_console_not_exposed_on_public_listener():
    for path in ("/admin/", "/admin/master/console/", "/realms/master/protocol/openid-connect/token"):
        assert requests.get(f"{lab.SSO}{path}", verify=lab.CA).status_code == 403


def test_unknown_virtual_host_is_dropped():
    try:
        requests.get("https://other.localtest.me:7443/", verify=lab.CA, timeout=5)
        dropped = False
    except requests.ConnectionError:
        dropped = True
    assert dropped
