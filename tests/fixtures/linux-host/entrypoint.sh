#!/bin/sh
set -eu

install -d -m 0755 /run/sshd
install -d -m 0755 /fixture

ssh-keygen -A
rm -f /fixture/client_key /fixture/client_key.pub /fixture/known_hosts
ssh-keygen -q -t ed25519 -N '' -f /fixture/client_key
chmod 0600 /fixture/client_key
chmod 0644 /fixture/client_key.pub
chown 10001:10001 /fixture/client_key /fixture/client_key.pub

install -m 0600 -o secscan-audit -g secscan-audit /fixture/client_key.pub /home/secscan-audit/.ssh/authorized_keys

host_key="$(awk '{print $1 " " $2}' /etc/ssh/ssh_host_ed25519_key.pub)"
printf 'linux-host-fixture %s\n' "$host_key" > /fixture/known_hosts
chmod 0644 /fixture/known_hosts
chown 10001:10001 /fixture/known_hosts

cat > /etc/ssh/sshd_config <<'EOF'
Port 22
ListenAddress 0.0.0.0
HostKey /etc/ssh/ssh_host_ed25519_key
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
AllowUsers secscan-audit
AuthorizedKeysFile .ssh/authorized_keys
UsePAM no
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
PrintMotd no
Subsystem sftp internal-sftp
EOF

exec /usr/sbin/sshd -D -e
