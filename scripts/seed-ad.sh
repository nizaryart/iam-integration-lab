#!/usr/bin/env bash
# Seeds CORP.LAB with OUs, security groups, three staff users and the Keycloak bind account.
# Idempotent: existing objects are left as they are.
set -euo pipefail
cd "$(dirname "$0")/.."
set -a; source .env; set +a

st() { docker compose exec -T dc1 samba-tool "$@"; }
quiet() { "$@" >/dev/null 2>&1 || true; }

for ou in Staff Groups Service; do quiet st ou add "OU=$ou"; done
for g in Finance HR IT-Admins; do quiet st group add "$g" --groupou="OU=Groups"; done

add_user() {  # sam given surname group
  quiet st user add "$1" "$AD_USER_PASSWORD" --userou="OU=Staff" \
    --given-name="$2" --surname="$3" --mail-address="$1@corp.lab"
  quiet st group addmembers "$4" "$1"
}
add_user alice Alice Martin  Finance
add_user bob   Bob   Bennani HR
add_user carol Carol Idrissi IT-Admins

# Least-privilege bind account for Keycloak: an ordinary user (authenticated users can read
# the directory), no group membership, kept outside the Staff OU so it is never federated.
quiet st user add svc-keycloak "$AD_SVC_KEYCLOAK_PASSWORD" --userou="OU=Service" \
  --given-name=Keycloak --surname=Service --description="LDAP bind account for Keycloak (read-only)"
quiet st user setexpiry svc-keycloak --noexpiry

echo "Directory content:"
st ou listobjects "OU=Staff"; st ou listobjects "OU=Groups"; st ou listobjects "OU=Service"
for g in Finance HR IT-Admins; do echo "$g: $(st group listmembers "$g" | tr '\n' ' ')"; done
