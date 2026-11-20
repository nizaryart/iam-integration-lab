#!/usr/bin/env bash
# One command from an empty checkout to a configured lab.
set -euo pipefail
cd "$(dirname "$0")/.."

wait_healthy() {
  echo "[setup] waiting for $1 ..."
  timeout 300 bash -c "until [ \"\$(docker compose ps $1 --format '{{.Health}}')\" = healthy ]; do sleep 3; done"
}

bash scripts/make-certs.sh
bash scripts/gen-env.sh

if [[ ! -x .venv/bin/python ]]; then
  python3 -m venv .venv
  .venv/bin/pip install -q -r requirements-dev.txt
fi

docker compose up -d --build
wait_healthy dc1
bash scripts/seed-ad.sh
wait_healthy keycloak
.venv/bin/python scripts/configure_keycloak.py

echo
echo "[setup] ready:"
echo "  portal (OIDC)   https://portal.localtest.me:7443"
echo "  HR docs (SAML)  https://saml.localtest.me:7443"
echo "  admin console   https://sso-admin.localtest.me:7444/admin/  (user/password in .env)"
echo "  tests           .venv/bin/python -m pytest -c tests/pytest.ini tests"
