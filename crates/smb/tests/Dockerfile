FROM debian:bookworm-slim

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        samba samba-ad-dc samba-ad-provision winbind krb5-user smbclient && \
    rm -rf /var/lib/apt/lists/* /etc/samba/smb.conf
COPY kerberos-entrypoint.sh /usr/local/bin/kerberos-entrypoint.sh
ENTRYPOINT ["sh", "/usr/local/bin/kerberos-entrypoint.sh"]
