FROM debian:bookworm-slim
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      samba samba-ad-dc samba-ad-provision winbind krb5-user ldb-tools ldap-utils ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 636
ENTRYPOINT ["/entrypoint.sh"]
