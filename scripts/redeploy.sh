#!/usr/bin/env bash
set -e
SSH_KEY="$HOME/.ssh/knox_oracle"
OPTS="-o ConnectTimeout=8 -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes -i $SSH_KEY"
IPS=(132.226.76.90 141.148.131.54 129.146.133.68 132.226.119.131 161.153.44.116 129.153.196.159)
BIN="/mnt/d/KNOX/target/x86_64-unknown-linux-gnu/release/knox-node"

for i in "${!IPS[@]}"; do
  IP="${IPS[$i]}"
  echo "=== VM$((i+1)) ($IP) ==="
  ssh $OPTS ubuntu@"$IP" 'sudo chmod 1777 /tmp && sudo chown knox:knox /etc/knox/p2p-psk && sudo chmod 0400 /etc/knox/p2p-psk'
  scp $OPTS "$BIN" ubuntu@"$IP":~/knox-node
  ssh $OPTS ubuntu@"$IP" 'sudo systemctl stop knox-node-a knox-node-b && sudo cp ~/knox-node /opt/knox/bin/knox-node && sudo chmod +x /opt/knox/bin/knox-node && sudo systemctl start knox-node-a knox-node-b && echo done'
  echo ""
done
