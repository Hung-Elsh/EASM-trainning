# NSE scripts by port and protocol

Checked against the scripts installed on Kali (nmap 7.99, `/usr/share/nmap/scripts`).

Tag key:
- **[safe]** read-only, fine for EASM scans
- **[intrusive]** sends attack-like traffic, can lock accounts or crash services; only with explicit permission
- **[brute]** password guessing

Use `nmap --script-help <name>` to see what a script does and its arguments. Always pass `-p <port>`. Most scripts only run if nmap sees the right service there, so use `-sV` on unusual ports.

## Generic: work on almost any TCP port
| Script | What it does |
|---|---|
| `banner` [safe] | Prints what the service says first. Empty for client-speaks-first protocols (HTTP, TLS, Redis) |
| `-sV` (not a script) | Version detection; also feeds the right scripts on non-standard ports |
| `ssl-cert` [safe] | TLS certificate: subject, issuer, validity dates (any TLS port: 443, 993, 992, 2376, 6443…) |
| `ssl-enum-ciphers` [safe] | TLS versions and ciphers offered, with an A–F grade |
| `ssl-date` [safe] | Server clock taken from the TLS handshake |
| `tls-alpn` [safe] | Application protocols offered over TLS (h2, http/1.1) |
| `ssl-heartbleed`, `ssl-poodle`, `sslv2`, `sslv2-drown`, `ssl-ccs-injection`, `ssl-dh-params` [vuln, mostly safe] | Checks for known TLS weaknesses |

## Basic / legacy services
| Port | Protocol | Scripts |
|---|---|---|
| 7/tcp, udp | Echo | **No NSE script.** Test by hand: `nc 192.168.1.x 7` and type something |
| 13/tcp, udp | Daytime | `daytime` [safe]: reads the server's date/time string |

## File transfer and sharing
| Port | Protocol | Scripts |
|---|---|---|
| 20/21 tcp | FTP (20 = data, 21 = control) | `ftp-anon` [safe]: anonymous login allowed? Lists files<br>`ftp-syst` [safe]: OS/server info from SYST/STAT<br>`ftp-bounce` [intrusive]: can the server be used to scan other hosts?<br>`ftp-vsftpd-backdoor`, `ftp-proftpd-backdoor`, `ftp-vuln-cve2010-4221` [vuln]: known backdoors/bugs<br>`ftp-brute` [brute] |
| 115/tcp | SFTP: the old *Simple* File Transfer Protocol (RFC 913), **not** SSH-SFTP | No NSE script; use `banner` and `-sV`. SSH-SFTP runs on port 22 |
| 445/tcp | SMB | `smb-protocols` [safe]: SMBv1/2/3 supported<br>`smb2-security-mode` [safe]: is signing required?<br>`smb-os-discovery` [safe]: OS, computer name, domain (mainly SMBv1)<br>`smb2-capabilities`, `smb2-time` [safe]<br>`smb-enum-shares`, `smb-enum-users`, `smb-ls` [intrusive]: lists shares/users/files, works best with credentials<br>`smb-vuln-ms17-010` [vuln]: EternalBlue check<br>`smb-vuln-*` others [vuln]: some are DoS-risky (`smb-vuln-regsvc-dos`, `smb-flood`): avoid<br>`smb-brute` [brute] |
| 2049/tcp, udp | NFS | `nfs-showmount` [safe]: exported folders (like `showmount -e`)<br>`nfs-ls` [safe]: lists files in the exports<br>`nfs-statfs` [safe]: disk space of the exports<br>`rpcinfo` [safe]: NFS needs RPC (port 111), so run it there too |

## Remote access
| Port | Protocol | Scripts |
|---|---|---|
| 22/tcp | SSH | `ssh-hostkey` [safe]: host key fingerprints (spot the same key on many hosts)<br>`ssh2-enum-algos` [safe]: key exchange/cipher/MAC lists, finds weak algorithms<br>`ssh-auth-methods` [safe]: password, publickey, …? Password auth = brute-force risk<br>`sshv1` [safe]: old SSHv1 enabled?<br>`ssh-publickey-acceptance` [intrusive]: tries known public keys<br>`ssh-run` [intrusive]: runs a command, needs credentials<br>`ssh-brute` [brute] |
| 23/tcp | Telnet (cleartext) | `telnet-encryption` [safe]: does it support encryption?<br>`telnet-ntlm-info` [safe]: Windows host/domain info from NTLM<br>`telnet-brute` [brute] |
| 992/tcp | Telnet over TLS | No dedicated script: `ssl-cert`, `ssl-enum-ciphers`, then `telnet-*` if `-sV` recognises it |

## Mail
| Port | Protocol | Scripts |
|---|---|---|
| 25/tcp | SMTP | `smtp-commands` [safe]: EHLO capabilities (STARTTLS, AUTH, …)<br>`smtp-open-relay` [intrusive]: will it relay mail for outside domains?<br>`smtp-ntlm-info` [safe]: Windows host/domain info<br>`smtp-enum-users` [intrusive]: VRFY/EXPN/RCPT user guessing<br>`smtp-strangeport` [safe]: SMTP on a non-standard port<br>`smtp-vuln-cve2010-4344`, `smtp-vuln-cve2011-1720`, `smtp-vuln-cve2011-1764` [vuln]: Exim/Postfix bugs<br>`smtp-brute` [brute] |
| 143/tcp | IMAP | `imap-capabilities` [safe]: supported features (STARTTLS, LOGINDISABLED…)<br>`imap-ntlm-info` [safe]: Windows host/domain info (Exchange)<br>`imap-brute` [brute] |
| 993/tcp | IMAP over TLS | `ssl-cert`, `ssl-enum-ciphers`, plus the `imap-*` scripts (they handle TLS) |

## Name services
| Port | Protocol | Scripts |
|---|---|---|
| 53/udp, tcp | DNS | `dns-recursion` [safe]: open resolver? (an amplification-attack risk)<br>`dns-nsid` [safe]: server ID/version<br>`dns-zone-transfer` [intrusive]: AXFR leaks every record; needs `--script-args dns-zone-transfer.domain=seclab.test`<br>`dns-srv-enum` [safe]: common SRV records (LDAP, Kerberos, SIP…)<br>`dns-nsec-enum`, `dns-nsec3-enum` [intrusive]: walk DNSSEC chains to list names<br>`dns-brute` [intrusive]: subdomain brute force (like your gobuster step)<br>`dns-cache-snoop` [intrusive]: which domains the server has cached<br>Use `-sU -p 53` for UDP |

## Web
| Port | Protocol | Scripts |
|---|---|---|
| 80/tcp | HTTP | `http-title` [safe]: page title ("Index of /" = directory listing)<br>`http-headers` [safe]: all response headers<br>`http-server-header` [safe]: Server header only<br>`http-security-headers` [safe]: lists security headers that are *present*<br>`http-methods` [safe]: allowed methods (PUT/DELETE/TRACE = risky)<br>`http-robots.txt` [safe]: hidden paths in robots.txt<br>`http-cors` [safe]: CORS policy<br>`http-git` [safe]: exposed `.git/` folder<br>`http-auth`, `http-auth-finder` [safe]: login/auth pages<br>`http-webdav-scan` [safe]: WebDAV enabled?<br>`http-enum` [intrusive]: probes about 2,000 known paths (admin panels, backups)<br>`http-backup-finder` [intrusive]: `file.bak`, `file~` copies<br>`http-default-accounts` [intrusive]: tries default logins on known apps |
| 443/tcp | HTTPS | All the `http-*` scripts (they speak TLS automatically) + `ssl-cert`, `ssl-enum-ciphers`, `ssl-heartbleed`. `http-security-headers` reports missing HSTS only here |

## RPC
| Port | Protocol | Scripts |
|---|---|---|
| 530/tcp, udp | "courier" RPC (rare, old) | No dedicated script; `-sV`, `banner`. The RPC ports you'll meet more often are below |
| 111/tcp, udp | Sun RPC portmapper | `rpcinfo` [safe]: lists RPC programs (NFS, mountd…) and their ports<br>`rpc-grind` [intrusive]: identifies RPC services on unknown ports |
| 135/tcp | Microsoft RPC (open on your laptop) | `msrpc-enum` [safe]: lists RPC endpoints (works over SMB/445) |

## Containers and orchestration
| Port | Protocol | Scripts |
|---|---|---|
| 2375/tcp | Docker API, plain HTTP, **no auth by default** | `docker-version` [safe]: Docker/API/OS version. If it answers, the whole host is exposed: anyone can start containers. Treat as Critical<br>`http-title`, `http-headers` |
| 2376/tcp | Docker API over TLS | `docker-version` (if no client cert is required), `ssl-cert`: does it ask for a client certificate? |
| 2377/tcp | Docker Swarm cluster management (TLS) | No dedicated script: `ssl-cert`, `ssl-enum-ciphers` |
| 6443/tcp | Kubernetes API (HTTPS) | No dedicated script: `ssl-cert` (the cert's SANs leak cluster names), `http-title`, `http-headers`. By hand: `curl -sk https://<ip>:6443/version`. If it answers without a token, that's a finding |

## Databases
| Port | Protocol | Scripts |
|---|---|---|
| 3306/tcp | MySQL / MariaDB | `mysql-info` [safe]: version, capabilities, auth plugin<br>`mysql-empty-password` [intrusive]: root/anonymous with no password?<br>`mysql-databases`, `mysql-users`, `mysql-variables`, `mysql-dump-hashes`, `mysql-query`, `mysql-audit` [intrusive]: need credentials<br>`mysql-vuln-cve2012-2122` [vuln]: auth bypass<br>`mysql-brute` [brute] |
| 5432/tcp | PostgreSQL | Only `pgsql-brute` [brute]. Use `-sV` for the version; by hand: `psql -h <ip> -U postgres` to test trust/no-password login |
| 2483/tcp (TLS: 2484) | Oracle DB TNS listener (default is usually 1521) | `oracle-tns-version` [safe]: listener version<br>`oracle-sid-brute` [brute]: guesses database SIDs<br>`oracle-enum-users` [intrusive]<br>`oracle-brute`, `oracle-brute-stealth` [brute] |
| 6201, 6225, 6227, 6240, 6244, 6255/tcp | Oracle WebCenter (web applications) | No dedicated scripts: they're HTTP(S), so use the Web scripts (`http-title`, `http-headers`, `http-enum`, `ssl-cert`) |
| *(your lab)* 6379/tcp | Redis | `redis-info` [safe]: version, config, clients; works = no auth |
| *(your lab)* 9200/tcp | Elasticsearch (HTTP) | No dedicated script: `http-title`, `http-headers`; by hand: `curl http://<ip>:9200/_cat/indices` |

## Media streaming
| Port | Protocol | Scripts |
|---|---|---|
| 7070/tcp (standard: 554) | RTSP (cameras, streaming) | `rtsp-methods` [safe]: supported RTSP methods<br>`rtsp-url-brute` [brute]: guesses stream URLs (finds open camera feeds) |
| 5004/5005 udp | RTP / RTCP media streams | No NSE script. Ports are negotiated by RTSP/SIP; scan RTSP or SIP (5060: `sip-methods` [safe]) instead |

## Cloud and blockchain
| Port | Protocol | Scripts |
|---|---|---|
| 4195/tcp | AWS remote access (your note) | No NSE script: `-sV`, `ssl-cert`, `banner` |
| 8333/tcp | Bitcoin P2P | `bitcoin-info` [safe]: node version, block height<br>`bitcoin-getaddr` [safe]: peer list from the node |
| 8332/tcp | Bitcoin JSON-RPC | `bitcoinrpc-info` [safe]: RPC info (should never be public: it controls the wallet) |
| 9735/tcp | Lightning Network | No NSE script: `-sV`, `banner`, `ssl-cert` |

## Notes on your list
- **445** is **SMB** (`microsoft-ds`), not "MDS".
- **115** is the old *Simple* File Transfer Protocol, almost never seen. SFTP over SSH uses **22**.
- **530** is rare. On Windows, RPC is **135**; on Linux it's **111**.
- **Oracle DB** usually listens on **1521**; 2483/2484 are the officially registered ports.
- Ports only say what *usually* runs there. `-sV` tells you what *actually* runs, and nmap then picks the matching scripts.
