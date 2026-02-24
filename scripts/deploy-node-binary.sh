#!/bin/bash
KEY=~/.ssh/knox_oracle
BINARY="target/release/knox-node"
IPS=(132.226.76.90 141.148.131.54 129.146.133.68 132.226.119.131 161.153.44.116 129.153.196.159)

for IP in "${IPS[@]}"; do
  echo "=== $IP ==="
  scp -i "$KEY" "$BINARY" ubuntu@$IP:/tmp/knox-node-new
  ssh -i "$KEY" ubuntu@$IP "
    sudo systemctl stop knox-node-a knox-node-b
    sudo cp /tmp/knox-node-new /opt/knox/bin/knox-node
    sudo chmod +x /opt/knox/bin/knox-node
    sudo systemctl start knox-node-a knox-node-b
    sleep 3
    echo -n 'a:'; sudo systemctl is-active knox-node-a
    echo -n 'b:'; sudo systemctl is-active knox-node-b
    sudo journalctl -u knox-node-a -n 5 --no-pager | grep -i 'genesis\|seeded\|ledger\|tip'
  "
  echo
done
