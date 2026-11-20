#!/usr/bin/env python3
"""Identity detections over two sources: Keycloak events and the AD authentication audit.

  detect.py [--minutes 60] [--json]

Rules
  KC-BRUTE      >= 5 failed SSO login attempts on one account within 10 minutes
                (wrong password or attempt while locked)
  KC-LOCKED     login attempted while the account is locked by brute-force protection
  AD-DISABLED   logon with a disabled AD account (event 4625, NT_STATUS_ACCOUNT_DISABLED)
                correlated with the Keycloak failure it caused: a leaver trying to sign in
  AD-SPRAY      wrong passwords on >= 3 different accounts within 5 minutes
  KC-PRIV       admin-plane changes: role mappings, clients, authentication flows, users

Keycloak logs a disabled AD account as a plain `invalid_user_credentials`, exactly like a
typo. Only the domain controller knows the reason, hence the correlation.
"""
import argparse
import json
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from configure_keycloak import KC, load_env  # noqa: E402

REALM = "corp"


def keycloak_events(kc, since_ms):
    events = kc("GET", f"/{REALM}/events", params={"dateFrom": time.strftime("%Y-%m-%d", time.gmtime(since_ms / 1000)),
                                                    "max": 5000})
    admin = kc("GET", f"/{REALM}/admin-events", params={"max": 2000})
    return ([e for e in events if e["time"] >= since_ms],
            [e for e in admin if e["time"] >= since_ms])


def ad_auth_events(minutes):
    out = subprocess.run(["docker", "compose", "logs", "--no-log-prefix", f"--since={minutes}m", "dc1"],
                         cwd=ROOT, capture_output=True, text=True).stdout
    events = []
    for line in out.splitlines():
        if '"type": "Authentication"' not in line:
            continue
        rec = json.loads(line[line.index("{"):])
        a = rec["Authentication"]
        ts = datetime.fromisoformat(rec["timestamp"]).timestamp() * 1000
        events.append({"time": ts, "event_id": a["eventId"], "status": a["status"],
                       "account": (a.get("mappedAccount") or "").lower(),
                       "service": a["serviceDescription"], "auth": a["authDescription"],
                       "source": a["remoteAddress"]})
    return events


def iso(ms):
    return datetime.fromtimestamp(ms / 1000, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def detect(kc_events, admin_events, ad_events):
    alerts = []

    def alert(rule, severity, user, when, summary, evidence):
        alerts.append({"rule": rule, "severity": severity, "user": user, "time": iso(when),
                       "summary": summary, "evidence": evidence})

    failures, locked = defaultdict(list), defaultdict(list)
    for e in kc_events:
        user = (e.get("details", {}).get("username") or "").lower()
        if e["type"] == "LOGIN_ERROR" and e.get("error") == "invalid_user_credentials" and user:
            failures[user].append(e)
        if e["type"] == "LOGIN_ERROR" and e.get("error") == "user_temporarily_disabled":
            locked[user].append(e)

    # Fast attempts trip Keycloak's quick-login lock after two failures; the next ones are
    # logged as user_temporarily_disabled, not invalid_user_credentials. Count both, or a
    # fast attacker stays under the brute-force threshold.
    attempts = defaultdict(list)
    for user in set(failures) | set(locked):
        attempts[user] = failures.get(user, []) + locked.get(user, [])

    for user, evs in locked.items():                     # one alert per account, with a count
        alert("KC-LOCKED", "high", user, max(e["time"] for e in evs),
              f"{len(evs)} login attempt(s) on an account locked by brute-force protection",
              {"ips": sorted({e.get("ipAddress") for e in evs}),
               "first": iso(min(e["time"] for e in evs))})

    for user, evs in attempts.items():
        evs.sort(key=lambda e: e["time"])
        for i in range(len(evs)):
            window = [e for e in evs[i:] if e["time"] - evs[i]["time"] <= 600_000]
            if len(window) >= 5:
                alert("KC-BRUTE", "high", user, window[-1]["time"],
                      f"{len(window)} failed SSO login attempts in {(window[-1]['time'] - window[0]['time']) // 1000}s",
                      {"ips": sorted({e.get("ipAddress") for e in window}),
                       "clients": sorted({e.get("clientId") for e in window})})
                break

    for a in ad_events:
        if a["status"] == "NT_STATUS_ACCOUNT_DISABLED":
            sso = [e for e in failures.get(a["account"], []) if abs(e["time"] - a["time"]) <= 60_000]
            alert("AD-DISABLED", "medium", a["account"], a["time"],
                  "disabled AD account tried to sign in" + (" through SSO" if sso else ""),
                  {"dc_event": a["event_id"], "dc_status": a["status"], "service": a["service"],
                   "keycloak_error": sso[0].get("error") if sso else None,
                   "client": sso[0].get("clientId") if sso else None,
                   "user_ip": sso[0].get("ipAddress") if sso else None})

    wrong = sorted((a for a in ad_events if a["status"] == "NT_STATUS_WRONG_PASSWORD"), key=lambda a: a["time"])
    for i, first in enumerate(wrong):
        window = [a for a in wrong[i:] if a["time"] - first["time"] <= 300_000]
        accounts = sorted({a["account"] for a in window})
        if len(accounts) >= 3:
            alert("AD-SPRAY", "high", ",".join(accounts), window[-1]["time"],
                  f"wrong passwords on {len(accounts)} accounts within 5 minutes", {"accounts": accounts})
            break

    watched = ("role-mappings", "clients", "authentication", "components", "users")
    for e in admin_events:
        path = e.get("resourcePath", "")
        if e["operationType"] in ("CREATE", "UPDATE", "DELETE") and any(w in path for w in watched) \
                and e.get("resourceType") not in ("USER_SESSION",):
            alert("KC-PRIV", "info", e.get("authDetails", {}).get("userId", "?"), e["time"],
                  f"{e['operationType']} {e.get('resourceType')} {path}",
                  {"admin_ip": e.get("authDetails", {}).get("ipAddress")})
    return sorted(alerts, key=lambda a: a["time"])


def run(minutes=60, kc=None):
    kc = kc or KC()
    since = int(time.time() * 1000) - minutes * 60_000
    kc_events, admin_events = keycloak_events(kc, since)
    return detect(kc_events, admin_events, ad_auth_events(minutes))


if __name__ == "__main__":
    load_env()
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--minutes", type=int, default=60)
    p.add_argument("--json", action="store_true", help="one JSON alert per line (SIEM ingestion)")
    p.add_argument("--no-info", action="store_true", help="hide KC-PRIV informational alerts")
    a = p.parse_args()
    alerts = [x for x in run(a.minutes) if not (a.no_info and x["severity"] == "info")]
    for x in alerts:
        if a.json:
            print(json.dumps(x))
        else:
            print(f"{x['time']}  {x['severity']:<6} {x['rule']:<12} {x['user']:<12} {x['summary']}")
    if not a.json:
        print(f"-- {len(alerts)} alert(s) over the last {a.minutes} min")
