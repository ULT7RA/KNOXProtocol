#!/bin/bash
KEY=~/.ssh/knox_oracle
IPS=(132.226.76.90 141.148.131.54 129.146.133.68 132.226.119.131 161.153.44.116 129.153.196.159)

for IP in "${IPS[@]}"; do
  echo "=== $IP ==="
  ssh -i "$KEY" -o ConnectTimeout=10 ubuntu@$IP "
    sudo sed -i 's/^KNOX_MAINNET_GENESIS_HASH=.*/KNOX_MAINNET_GENESIS_HASH=/' /etc/default/knox-node-a
    sudo sed -i 's/^KNOX_MAINNET_GENESIS_HASH=.*/KNOX_MAINNET_GENESIS_HASH=/' /etc/default/knox-node-b
    sudo systemctl restart knox-node-a knox-node-b
    sleep 2
    echo -n 'node-a: '; sudo systemctl is-active knox-node-a
    echo -n 'node-b: '; sudo systemctl is-active knox-node-b
    sudo grep KNOX_MAINNET_GENESIS_HASH /etc/default/knox-node-a
  " 2>&1
  echo
done
