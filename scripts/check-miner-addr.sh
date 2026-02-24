#!/bin/bash
KEY=~/.ssh/knox_oracle
ADDR=knox15ecb39847f041ae

for IP in 132.226.76.90 141.148.131.54 129.146.133.68 132.226.119.131 161.153.44.116 129.153.196.159; do
  echo "=== $IP ==="
  ssh -i "$KEY" -o ConnectTimeout=5 ubuntu@$IP "sudo cat /etc/default/knox-node-a" 2>&1
done
