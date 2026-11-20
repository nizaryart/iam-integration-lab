#!/usr/bin/env bash
# Provisions a Samba AD domain (CORP.LAB) on first start, then runs samba in the foreground.
set -euo pipefail

REALM=CORP.LAB
DOMAIN=CORP
TLS_DIR=/var/lib/samba/private/tls-lab
CONF=/var/lib/samba/etc/smb.conf      # kept in the volume: survives container rebuilds

if [[ ! -f /var/lib/samba/private/sam.ldb ]]; then
  echo "[dc] provisioning domain $REALM"
  rm -f /etc/samba/smb.conf
  samba-tool domain provision \
    --realm="$REALM" --domain="$DOMAIN" --server-role=dc \
    --dns-backend=SAMBA_INTERNAL --use-rfc2307 \
    --adminpass="$AD_ADMIN_PASSWORD" \
    --option="dns forwarder = 127.0.0.11" \
    --option="tls enabled = yes" \
    --option="tls keyfile = $TLS_DIR/dc1.key" \
    --option="tls certfile = $TLS_DIR/dc1.pem" \
    --option="tls cafile = $TLS_DIR/ca.pem" \
    --option="ldap server require strong auth = yes" \
    --option="dns update command = /bin/true"
  mkdir -p /var/lib/samba/etc
  mv /etc/samba/smb.conf "$CONF"
fi
ln -sf "$CONF" /etc/samba/smb.conf
cp /var/lib/samba/private/krb5.conf /etc/krb5.conf

# Lab certificate (issued by the lab CA) -- samba refuses keys that are not 0600.
mkdir -p "$TLS_DIR"
install -m 600 /certs/dc1.key "$TLS_DIR/dc1.key"
install -m 644 /certs/dc1.pem "$TLS_DIR/dc1.pem"
install -m 644 /certs/ca.pem  "$TLS_DIR/ca.pem"

# Authentication audit in JSON on stdout (docker logs): one event per bind/logon with a
# Windows event ID (4624/4625) and the NT status, e.g. NT_STATUS_ACCOUNT_DISABLED.
# Keycloak only sees "bind failed"; the DC knows why.
sed -i '/auth_json_audit/d' "$CONF"
sed -i '/^\[global\]/a\\tlog level = 1 auth_json_audit:3' "$CONF"

echo "[dc] starting samba"
exec samba --foreground --no-process-group --debug-stdout
