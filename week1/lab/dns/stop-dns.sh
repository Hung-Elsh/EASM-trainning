#!/bin/sh
[ -f /run/seclab-dnsmasq.pid ] && sudo kill "$(cat /run/seclab-dnsmasq.pid)" && echo "Lab DNS stopped."
