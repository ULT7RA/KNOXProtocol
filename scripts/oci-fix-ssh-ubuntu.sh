#!/usr/bin/env bash
set -euo pipefail

PUB='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH8AlitPxjojgFL0i/J62hA5aHBzqaOUg8ut3Cb0JVSL knox-oracle'

if ! id -u ubuntu >/dev/null 2>&1; then
  useradd -m -s /bin/bash -G sudo ubuntu
fi

install -d -m 700 -o ubuntu -g ubuntu /home/ubuntu/.ssh
touch /home/ubuntu/.ssh/authorized_keys
grep -qxF "$PUB" /home/ubuntu/.ssh/authorized_keys || echo "$PUB" >> /home/ubuntu/.ssh/authorized_keys
chown ubuntu:ubuntu /home/ubuntu/.ssh/authorized_keys
chmod 600 /home/ubuntu/.ssh/authorized_keys

if systemctl list-unit-files | grep -q '^ssh\.service'; then
  systemctl restart ssh
elif systemctl list-unit-files | grep -q '^sshd\.service'; then
  systemctl restart sshd
fi

echo "ok"
