#!/bin/sh
set -eu

# Disposable test domain. Credentials must never be used outside this fixture.
if [ ! -f /var/lib/samba/private/sam.ldb ]; then
    samba-tool domain provision \
        --server-role=dc --dns-backend=SAMBA_INTERNAL \
        --realm=SMB.TEST --domain=SMB --host-name=samba \
        --adminpass='TestAdmin123!'
    samba-tool domain passwordsettings set --complexity=off --min-pwd-length=1
    samba-tool user create LocalAdmin 123456
    samba-tool user setexpiry LocalAdmin --noexpiry
    samba-tool user setpassword Guest --newpassword=123456
    samba-tool user enable Guest
    samba-tool spn add cifs/samba 'SAMBA$'
    samba-tool spn add cifs/samba.smb.test 'SAMBA$'
    samba-tool spn add cifs/localhost 'SAMBA$'
    # Insert global settings before the provisioned share sections.
    sed -i '/^\[global\]/a\
    server min protocol = SMB2_02\
    server max protocol = SMB3_11\
    server multi channel support = yes\
    smb encrypt = auto\
    map to guest = Bad User' /etc/samba/smb.conf
    cat >> /etc/samba/smb.conf <<'EOF'

[MyShare]
    path = /shares/MyShare
    read only = no
    browseable = yes
    create mask = 0777
    directory mask = 0777
    smb encrypt = desired

[KerberosShare]
    path = /shares/KerberosShare
    read only = no
    browseable = yes
    create mask = 0777
    directory mask = 0777
    smb encrypt = desired

[PublicShare]
    path = /shares/PublicShare
    read only = no
    browseable = yes
    guest ok = yes
    guest only = yes
    create mask = 0777
    directory mask = 0777
    smb encrypt = disabled
EOF
fi

mkdir -p /shares/MyShare /shares/KerberosShare /shares/PublicShare
chmod 777 /shares/MyShare /shares/KerberosShare /shares/PublicShare
cp /var/lib/samba/private/krb5.conf /etc/krb5.conf
# Docker's resolver does not serve the AD DNS SRV records.
sed -i '/SMB.TEST = {/a\    kdc = samba.smb.test' /etc/krb5.conf
exec samba --foreground --no-process-group
