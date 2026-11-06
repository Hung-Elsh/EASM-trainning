# Lab address plan

The lab uses the block 192.168.1.248/29 at the end of the home network.
Hosts keep the normal /24 netmask so they can still reach the router
(192.168.1.1) and the internet; the /29 is the lab's *scope*, not its netmask.

| IP              | Name                | Role                          |
|-----------------|---------------------|-------------------------------|
| 192.168.1.248   | -                   | block start (kept unused)     |
| 192.168.1.249   | kali.seclab.test    | attacker, lab DNS             |
| 192.168.1.250   | win.seclab.test     | Windows target                |
| 192.168.1.251   | (free)              | next week's device            |
| 192.168.1.252   | (free)              |                               |
| 192.168.1.253   | (free)              |                               |
| 192.168.1.254   | (free)              |                               |
| 192.168.1.255   | -                   | broadcast for the /24, never use |

Adding a device: reserve the IP on the router, add a row here, add a
host-record in dns/seclab.conf. The firewall guard already allows the whole /29.
