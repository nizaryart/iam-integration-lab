#!/usr/bin/env python3
"""Joiner / mover / leaver procedures. AD is the source of truth; Keycloak follows.

  lifecycle.py joiner <user> <group> [--given G --surname S]
  lifecycle.py mover  <user> <from-group> <to-group>
  lifecycle.py leaver <user>

Leaver does two things on purpose: disabling the AD account blocks *new* logins, but
sessions already open stay alive until something ends them. Step 2 revokes every
Keycloak session of the user, one by one, which triggers OIDC back-channel logout in the
apps, then checks that no session is left.
"""
import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from configure_keycloak import KC, load_env  # noqa: E402

REALM = "corp"


def samba(*args):
    out = subprocess.run(["docker", "compose", "exec", "-T", "dc1", "samba-tool", *args],
                         cwd=ROOT, capture_output=True, text=True)
    if out.returncode != 0:
        sys.exit(f"samba-tool {' '.join(args[:2])} failed: {out.stderr.strip() or out.stdout.strip()}")
    return out.stdout.strip()


def keycloak_user(kc, username):
    users = kc("GET", f"/{REALM}/users", params={"username": username, "exact": "true"})
    return users[0] if users else None


def joiner(user, group, given="New", surname="Joiner"):
    samba("user", "add", user, os.environ["AD_USER_PASSWORD"], "--userou=OU=Staff",
          f"--given-name={given}", f"--surname={surname}", f"--mail-address={user}@corp.lab")
    samba("group", "addmembers", group, user)
    print(f"[joiner] {user} created in OU=Staff and added to {group}; access follows at first login")


def mover(user, old, new):
    samba("group", "removemembers", old, user)
    samba("group", "addmembers", new, user)
    print(f"[mover] {user}: {old} -> {new}; new tokens carry the new groups. "
          "Apps holding an old session keep old groups until re-login.")


def leaver(user, kc=None):
    samba("user", "disable", user)
    print(f"[leaver] 1/2 AD account {user} disabled: new logins refused")
    kc = kc or KC()
    kuser = keycloak_user(kc, user)
    if not kuser:
        print("[leaver] 2/2 no Keycloak record (user never signed in): nothing to revoke")
        return 0
    sessions = kc("GET", f"/{REALM}/users/{kuser['id']}/sessions")
    # One DELETE per session: each one sends its own back-channel logout token (with sid).
    # Observed on Keycloak 26.4: the bulk POST /users/{id}/logout notified the app for only
    # one of several sessions, leaving the others open in the application.
    for sess in sessions:
        kc("DELETE", f"/{REALM}/sessions/{sess['id']}")
    kc("POST", f"/{REALM}/users/{kuser['id']}/logout")          # offline sessions, consents
    left = kc("GET", f"/{REALM}/users/{kuser['id']}/sessions")
    if left:
        sys.exit(f"[leaver] {len(left)} session(s) still active, investigate")
    print(f"[leaver] 2/2 {len(sessions)} SSO session(s) revoked one by one; back-channel logout sent")
    return len(sessions)


def delete(user, kc=None):
    """Test cleanup: remove the AD account and Keycloak's imported copy."""
    subprocess.run(["docker", "compose", "exec", "-T", "dc1", "samba-tool", "user", "delete", user],
                   cwd=ROOT, capture_output=True)
    kc = kc or KC()
    kuser = keycloak_user(kc, user)
    if kuser:
        kc.s.delete(f"{kc_admin_url()}/admin/realms/{REALM}/users/{kuser['id']}")


def kc_admin_url():
    from configure_keycloak import ADMIN_URL
    return ADMIN_URL


if __name__ == "__main__":
    load_env()
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    j = sub.add_parser("joiner"); j.add_argument("user"); j.add_argument("group")
    j.add_argument("--given", default="New"); j.add_argument("--surname", default="Joiner")
    m = sub.add_parser("mover"); m.add_argument("user"); m.add_argument("old"); m.add_argument("new")
    lv = sub.add_parser("leaver"); lv.add_argument("user")
    a = p.parse_args()
    if a.cmd == "joiner":
        joiner(a.user, a.group, a.given, a.surname)
    elif a.cmd == "mover":
        mover(a.user, a.old, a.new)
    else:
        leaver(a.user)
