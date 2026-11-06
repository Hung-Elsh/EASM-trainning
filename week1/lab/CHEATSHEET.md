# nmap & Discovery Cheat Sheet (seclab)

**Scope rule:** only target `192.168.1.248/29` (or `192.168.1.250`). Never `192.168.1.0/24`.
Re-read the target before pressing Enter. If you see home devices as `filtered`, your target is wrong.

## Learning order
1. Host discovery: which machines are up?
2. Port scanning: which ports are open?
3. Service / version detection: what software is listening?
4. NSE scripts: more detail about those services.
5. DNS discovery against `seclab.test` with dig and Amass.

For each step: predict the result, run the scan, compare.

## 1. Host discovery
| Command | What it does |
|---|---|
| `sudo nmap -sn 192.168.1.248/29` | Ping sweep, no port scan. Uses ARP on the local network (most reliable). |
| `nmap -sn 192.168.1.248/29` | Same without sudo: TCP probes, Windows may look down. |
| `sudo nmap -sn -PE 192.168.1.250` | ICMP echo only. |
| `sudo nmap -Pn 192.168.1.250` | Skip discovery, assume the host is up. |
| `sudo nmap -sL 192.168.1.248/29` | List targets only, sends nothing. Safe scope check. |

## 2. Port scanning
| Command | What it does |
|---|---|
| `sudo nmap 192.168.1.250` | SYN scan of the top 1000 TCP ports. |
| `sudo nmap -p- 192.168.1.250` | All 65535 TCP ports. |
| `sudo nmap -p 22,80,135,139,445,3389 192.168.1.250` | Only the listed ports. |
| `sudo nmap --top-ports 100 192.168.1.250` | Quick first look. |
| `sudo nmap -sU --top-ports 20 192.168.1.250` | UDP scan (slow, keep it small). |
| `nmap -sT 192.168.1.250` | TCP connect scan, no root needed, noisier. |

Port states:
- **open**: a service answered.
- **closed**: host answered, nothing listening.
- **filtered**: a firewall dropped the probe (common on Windows).

## 3. Service, version, OS
| Command | What it does |
|---|---|
| `sudo nmap -sV 192.168.1.250` | Software and version on open ports. |
| `sudo nmap -O 192.168.1.250` | OS guess. |
| `sudo nmap -A 192.168.1.250` | -sV, -O, default scripts, traceroute. Loud: labs only. |

## 4. NSE scripts
| Command | What it does |
|---|---|
| `sudo nmap -sC 192.168.1.250` | Default safe scripts. |
| `sudo nmap --script smb-os-discovery -p445 192.168.1.250` | Windows / SMB details. |
| `sudo nmap --script "dns-*" -p53 127.0.0.1` | DNS scripts against the lab DNS. |
| `ls /usr/share/nmap/scripts/ \| grep smb` | List available scripts. |
| `nmap --script-help smb-os-discovery` | Read what a script does before running it. |

## 5. Speed, output, visibility
| Option | What it does |
|---|---|
| `-T4` / `-T2` | Faster (fine in the lab) / slower and quieter. |
| `-v` / `-d` | Verbose / debug output. |
| `--reason` | Why each port got its state. |
| `--packet-trace` | Every packet sent. Use on one port to learn. |
| `-oA scans/win-full` | Save normal, grepable and XML output (XML for Python later). |

## DNS discovery (week 1 goal)
Start the lab DNS first: `dns/start-dns.sh`

| Command | What it does |
|---|---|
| `dig @127.0.0.1 www.seclab.test` | A record. |
| `dig @127.0.0.1 seclab.test MX` / `TXT` / `ANY` | Other record types. Read the TXT records carefully. |
| `dig @127.0.0.1 _ldap._tcp.seclab.test SRV` | Services via SRV records. |
| `dig @127.0.0.1 -x 192.168.1.250` | Reverse lookup. |
| `for s in $(cat wordlists/subdomains-small.txt); do dig +short @127.0.0.1 $s.seclab.test; done` | Simple brute force (rebuild it in Python). |
| `amass enum -d seclab.test -r 127.0.0.1 -tr 127.0.0.1 -brute -w wordlists/subdomains-small.txt` | Subdomain enumeration with Amass. |

**Challenge:** two subdomains are hidden. They are not in the wordlist. Find both.
Afterwards, check `logs/dnsmasq.log` to see what your tools queried.

## Practice exercises
1. Run `nmap -sn` with and without sudo. Explain the difference.
2. Scan the laptop with Windows Firewall on, then briefly off. Compare filtered vs open. Turn it back on.
3. On Windows run `python -m http.server 8080`. Find it with nmap and identify it with `-sV`.
4. Run `sudo nmap --packet-trace -p 445 192.168.1.250` and match it to SYN → SYN/ACK → RST.
5. Save a full scan with `-oA`. Next week, parse the XML with Python.

## References
- `man nmap` (host discovery and port scanning techniques sections)
- nmap.org/book: "Nmap Network Scanning" (chapters 3–5 free)
- TryHackMe "Nmap" rooms
- SANS Nmap cheat sheet (PDF)
