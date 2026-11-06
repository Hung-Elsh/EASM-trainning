# Week 1: Host and Service Inventory (seclab.test)

**Date:** 2026-10-30. **Scope:** `seclab.test` and `192.168.1.248/29`. **Tester:** Kali at 192.168.1.249.

## Method
1. Read the DNS records (MX, TXT) for `seclab.test` from the lab DNS server (127.0.0.1).
2. Extracted labels from the records, then brute forced the wordlist plus year mutations with gobuster.
3. Grouped the names by IP and checked that each IP is inside 192.168.1.248/29.
4. Scanned the in-scope IPs: `nmap -sS -sV -T4 --max-retries 1` (top 1000 TCP ports).

## Host inventory
| IP | Names | Role | Status |
|---|---|---|---|
| 192.168.1.249 | kali, ns1, vpn | Kali (the tester) | Up. Results invalid: a raw SYN scan of your own IP shows every port as filtered. Scan it with `-sT 127.0.0.1` instead. |
| 192.168.1.250 | win, www, mail, webmail, ftp, dev, api, admin, intranet, staging, **hr-portal-x7**, **backup-2026** | Windows laptop | Up. |

Twelve names point to a single Windows host. The names suggest web, mail and admin services, but none of them is running. DNS names alone don't prove that a service exists.

## Service inventory: 192.168.1.250
| Port | Service | Product / version | Confidence | Notes |
|---|---|---|---|---|
| 135/tcp | msrpc | Microsoft Windows RPC | probed | Standard on Windows |
| 139/tcp | netbios-ssn | Windows NetBIOS | probed | Old file sharing |
| 445/tcp | microsoft-ds (SMB) | unknown (`?`) | port-based guess | File sharing. Run `--script smb-os-discovery,smb2-security-mode` next. |
| 2179/tcp | vmrdp? | Hyper-V VM console (guess) | port-based guess | Suggests Hyper-V or WSL2 is enabled |
| 5357/tcp | http | Microsoft HTTPAPI 2.0 (SSDP/UPnP) | probed | Network discovery (WSD) |

The other 995 ports are filtered: Windows Firewall drops the probes without replying.

## Findings
1. **Leaked names in DNS.** A TXT record reveals `hr-portal-x7`, and a year mutation finds `backup-2026`. Neither is in a standard wordlist.
2. **The DNS names don't match what's running.** Names like `www`, `mail` and `ftp` point to `.250`, but there's no HTTP on port 80, no SMTP and no FTP. These are stale records, which is a common real-world issue.
3. **SMB and RPC are reachable on the LAN.** That's normal for Windows on a private network profile, but it's the main attack surface for week 2.
4. **The firewall blocks almost everything,** so ping or a TCP scan without root can wrongly show the host as down. Use ARP or `-Pn` for discovery.

## Next steps
- Run NSE scripts against SMB (445) and check the SMB signing settings.
- Do a UDP scan of the top 20 ports (NetBIOS 137, SSDP 1900, LLMNR 5355).
- Make the script compare each new scan with this one, so new ports are flagged.
