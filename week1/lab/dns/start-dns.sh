#!/bin/sh
# Start the lab DNS server on 127.0.0.1:53 (needs sudo for port 53).
DIR=$(cd "$(dirname "$0")" && pwd)
sudo dnsmasq --conf-file="$DIR/seclab.conf" --pid-file=/run/seclab-dnsmasq.pid \
  && echo "Lab DNS running. Test: dig @127.0.0.1 www.seclab.test"
