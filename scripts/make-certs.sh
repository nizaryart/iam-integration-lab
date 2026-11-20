#!/usr/bin/env bash
# Creates a private lab CA and the two server certificates used by the lab:
#   - dc1.corp.lab           LDAPS on the Samba AD domain controller
#   - *.localtest.me         HTTPS on the reverse proxy (SSO, portals, admin)
# Nothing here is meant for production. Keys stay in certs/ (git-ignored).
set -euo pipefail
cd "$(dirname "$0")/../certs"

if [[ -f ca.pem && "${1:-}" != "--force" ]]; then
  echo "certs/ already populated (use --force to regenerate)"; exit 0
fi

openssl req -x509 -newkey rsa:3072 -nodes -days 825 -sha256 \
  -keyout ca.key -out ca.pem -subj "/CN=IAM Lab Root CA/O=iam-integration-lab" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"

issue() {  # name, subject CN, SAN list
  openssl req -newkey rsa:2048 -nodes -keyout "$1.key" -out "$1.csr" -subj "/CN=$2" 2>/dev/null
  openssl x509 -req -in "$1.csr" -CA ca.pem -CAkey ca.key -CAcreateserial -days 397 -sha256 \
    -out "$1.pem" -extfile <(printf "subjectAltName=%s\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature,keyEncipherment\n" "$3") 2>/dev/null
  rm -f "$1.csr"
}

issue dc1   dc1.corp.lab      "DNS:dc1.corp.lab,DNS:dc1"
issue proxy "*.localtest.me"  "DNS:*.localtest.me,DNS:localtest.me"
chmod 600 ./*.key
echo "Lab CA and certificates written to certs/"
