# Week 2 setup: misconfigured targets + pipeline tools

Phase 2 goal: discovery → Masscan sweep → Nmap/NSE validation → classify → Flask API.
You run every system step yourself. The files you need are already in this folder.

```
week2/
├── lab/targets/          # copy this folder to the Windows laptop
│   ├── docker-compose.yml
│   ├── firewall.ps1      # lets only Kali reach the targets
│   ├── web/ api/ vulnshop/ apache/ tomcat/ dns/ ntp/ snmp/ mocks/ ftp-files/
│   └── EXPECTED.md       # answer key: don't read it until your classifier works
├── scripts/python/       # your week 2 code
├── scans/                # Masscan + Nmap output
├── reports/
└── requirements.txt
```

## The targets (all on 192.168.1.250)
On non-standard ports add `-sV`. Without it, HTTP scripts skip the port and show nothing.

**Web**
| Port | Target | NSE to try |
|---|---|---|
| 80, 443 | nginx 1.18: old TLS, expired cert, directory listing | `http-title`, `http-headers`, `http-enum`, `ssl-cert`, `ssl-enum-ciphers` |
| 8443 | nginx, hardened, for comparison | same scripts: compare with 443 |
| 8000 | vulnshop (Flask): SQLi, XSS, weak cookies, Basic auth | `http-sql-injection`, `http-unsafe-output-escaping`, `http-csrf`, `http-cookie-flags`, `http-auth-finder`, `http-comments-displayer`, `http-robots.txt` |
| 8080 | Flask API with no auth | `http-headers`, `http-cors` |
| 8081 | DVWA (PHP, old Apache) | `http-enum`, `http-cookie-flags`, `http-php-version` |
| 8082 | Apache 2.4.49: TRACE, WebDAV, server-status, `.git` | `http-methods`, `http-trace`, `http-webdav-scan`, `http-apache-server-status`, `http-git`, `http-enum`, `http-backup-finder` |
| 3000 | Juice Shop (Node) | `http-title`, `http-robots.txt`, `http-headers`, `http-enum` |
| 8888, 8009 | Tomcat 9.0.30: default login, AJP | `http-default-accounts`, `ajp-headers`, `ajp-methods` |
| 9000, 9090 | Fake admin console, Prometheus: no login | `http-title`, `http-headers` |

**Databases**
| Port | Target | NSE to try |
|---|---|---|
| 3306 | MySQL 5.7, root with no password | `mysql-info`, `mysql-empty-password`, `mysql-databases` |
| 5432 | PostgreSQL 13, trust auth | `-sV`, `pgsql-brute` |
| 6379 | Redis, no password | `redis-info` |
| 9200 | Elasticsearch, no security | `http-title`, then `curl .../_cat/indices` |
| 27017 | MongoDB 4.4, no auth | `mongodb-info`, `mongodb-databases` |
| 11211 | Memcached, TCP and UDP | `memcached-info` |
| 1433 | MSSQL (heavy profile), sa/Password1! | `ms-sql-info`, `ms-sql-ntlm-info`, `ms-sql-empty-password` |

**Remote access and file transfer**
| Port | Target | NSE to try |
|---|---|---|
| 21 | Anonymous FTP (passive ports 30000-30009) | `ftp-anon`, `ftp-syst` |
| 22 | Real Windows OpenSSH | `ssh-hostkey`, `ssh2-enum-algos`, `ssh-auth-methods` |
| 2222 | SSH with password login | same scripts: compare with 22 |
| 23 | Telnet, admin/admin | `telnet-encryption`, `banner` |
| 5900 | Fake VNC, no auth | `vnc-info` |
| 3389 | xrdp (heavy profile) | `rdp-enum-encryption` |
| 445, 135 | Real Windows SMB and RPC | `smb-protocols`, `smb2-security-mode`, `msrpc-enum`. Safe scripts only: **no `smb-vuln-*`, `smb-flood` or `smb-brute`** on your real laptop |

**Mail, DNS, containers, UDP**
| Port | Target | NSE to try |
|---|---|---|
| 25 | Mailpit, relay-like behaviour | `smtp-commands`, `smtp-open-relay` |
| 465, 587, 110, 143, 993, 995 | GreenMail, with and without TLS | `smtp-commands`, `pop3-capabilities`, `imap-capabilities`, `ssl-cert` |
| 53 tcp/udp | BIND, zone `corp.seclab.test` | `dns-recursion`, `dns-nsid`, `dns-srv-enum`, `dns-zone-transfer` with `--script-args dns-zone-transfer.domain=corp.seclab.test` |
| 2375, 2376 | Fake Docker API | `docker-version`, `ssl-cert` |
| 2379 | Fake etcd | `curl .../version`, `curl .../v2/keys` |
| 6443, 10250 | Fake Kubernetes API and kubelet | `ssl-cert` (SANs leak names), `curl -k .../version`, `curl -k .../pods` |
| 123/udp | NTP | `ntp-info` |
| 161/udp | SNMP, community `public` | `snmp-info`, `snmp-sysdescr`, `snmp-processes` |
| 1900/udp | Real Windows SSDP | `upnp-info` |

UDP scans need root: `sudo nmap -sU -Pn -p 53,123,161,1900,11211 --script <name> 192.168.1.250`

**Fake on purpose:** the Docker API, Kubernetes, kubelet, etcd, VNC and port 9000 services. They answer scans but control nothing. A real open Docker API would give control of the laptop's Docker.

**Left out:** ports from `reports/nse-by-port.md` that a web app doesn't normally use (7, 13, 115, 530, 992, 2049, 2377, 2483, 4195, 5004/5005, 6201-6255, 7070, 8332/8333, 9735). Also no open proxy: it could carry your traffic past labguard to other home devices.

## Step 1: Windows firewall FIRST (PowerShell as Administrator)
Do this with the new files in place (step 2) and **before** `docker compose up`.
```powershell
cd $HOME\seclab-targets
powershell -ExecutionPolicy Bypass -File .\firewall.ps1
```
The script creates two kinds of rule, for TCP and UDP:
- **Kali only (allow):** 192.168.1.249 can reach the target ports on the Private profile.
- **Block others:** every other IPv4 and IPv6 address is blocked on those ports, on every profile. A block rule beats any allow rule, so this holds even if Docker Desktop re-creates its allow-all rules after an update.

It also covers port 22, so other devices can't SSH to the laptop any more. Remove `"22"` from the list if you need that.

Keep the Docker rule limited as well (from the first setup; run it again after a Docker update):
```powershell
Get-NetFirewallRule -DisplayName "Docker Desktop Backend" -Direction Inbound |
  Set-NetFirewallRule -EdgeTraversalPolicy Block -RemoteAddress 192.168.1.249
```
Don't use `-Action Block` on the Docker rules: it would also block Kali.

Check that your network is **Private** (the script prints this). If it's `Public`:
```powershell
Set-NetConnectionProfile -InterfaceAlias "<Wi-Fi or Ethernet name>" -NetworkCategory Private
```

**Prove it works from a second device.** Testing on the laptop itself proves nothing, because Windows doesn't filter its own loopback traffic. With the targets running, use a phone on the same Wi-Fi to open `http://192.168.1.250:8000` and `http://192.168.1.250:8080`: both must time out, while `curl http://192.168.1.250:8000` from Kali works. If the phone gets a page, run `docker compose down` and tell me.

If you publish a new port, add it to `firewall.ps1` and run it again **first**.

**What this doesn't cover:**
- The real Windows ports 135, 139, 445 and 5357 stay as they were, for your other home devices.
- Containers can still make outbound connections to your LAN and the internet. Nothing here mounts the Docker socket or runs privileged, so a compromised container stays inside Docker's limits, but don't add `privileged` or `docker.sock` to this file.

## Step 2: Copy the targets to Windows
Stop the old targets and remove the old folder first. Otherwise scp nests the new copy inside it as `seclab-targets\targets`.
```powershell
cd $HOME\seclab-targets
docker compose down
cd $HOME
Remove-Item -Recurse -Force .\seclab-targets
```
From Kali (you're doing the SSH yourself):
```bash
# use the full Windows path; a relative path lands in the home folder of <user>, which may not be you
scp -r ~/Projects/Security/training/week2/lab/targets <user>@192.168.1.250:C:/Users/<you>/seclab-targets
```

**On a fresh clone only:** Git can't store a folder named `.git`, so restore the fake exposed repo before copying:
```bash
cp -r lab/targets/apache/dot-git lab/targets/apache/html/.git
```
Scan output isn't in the repo either: run `week1/scripts/python/scanner_easm.py` first to create `week1/scans/subdomains.json`, which the week 2 pipeline reads.

## Step 3: Start the targets (on Windows, Docker Desktop running)
```powershell
cd $HOME\seclab-targets      # PowerShell; in cmd use: cd %USERPROFILE%\seclab-targets
docker compose up -d                  # 23 services, about 4-6 GB of RAM
docker compose ps
docker compose --profile heavy up -d  # optional: adds MSSQL and RDP, about 3 GB more
```
The first start downloads a lot, and Elasticsearch, MySQL and Tomcat take up to a minute. For DVWA, open `http://192.168.1.250:8081` from Kali, log in with admin/password and press "Create / Reset Database".

Troubleshooting ("port is already allocated" or "bind" errors):
- Find the owner with `netstat -ano | findstr :<port>`.
- **53:** Internet Connection Sharing or a hotspot may own it.
- **123:** the Windows Time service may own it.
- **80:** IIS or HTTP.sys.
- **3389:** Windows Remote Desktop.
- Either stop the Windows service, or change the left number in the compose file (`"1053:53/udp"`) and add the new port to `firewall.ps1`.

One failed container doesn't stop the others. See why with `docker compose logs <service>`.

## Known nmap 7.99 bugs on your Kali
Some scripts fail with `ERROR: Script execution failed`. That's nmap, not your target.

**`http-sql-injection` and `http-unsafe-output-escaping`** crash on any URL with a query string (`url.lua:382`). The fix is one line in a system file, and it worked on a scratch copy:
```bash
sudo cp /usr/share/nmap/nselib/url.lua /usr/share/nmap/nselib/url.lua.bak
sudo sed -i 's/query:gsub(query, "%+", " ")/query:gsub("%+", " ")/' /usr/share/nmap/nselib/url.lua
```
A Kali update may overwrite this. Other scripts that parse query strings use the same function.

**`http-config-backup`** crashes after it finds a file, because it calls a helper that doesn't exist. Skip it and check by hand: `curl -s http://192.168.1.250:8082/wp-config.php.bak`.

## Step 4: Check from Kali
```bash
curl -sI http://192.168.1.250/            # Server: nginx/1.18.0
curl -sk https://192.168.1.250/ -o /dev/null -w '%{http_code}\n'
curl -s  http://192.168.1.250:8080/api/v1/users
redis-cli -h 192.168.1.250 ping           # PONG (no password!)
curl -s  http://192.168.1.250:9200/       # Elasticsearch banner JSON
nc -vn -w 5 192.168.1.250 25 </dev/null  # 220 ... Mailpit ESMTP, then exits
curl -s  http://192.168.1.250:8000/ | head -3    # SecLab Shop
curl -sI http://192.168.1.250:8082/ | grep Server  # Apache/2.4.49
curl -s  http://192.168.1.250:2375/version       # fake Docker
dig @192.168.1.250 corp.seclab.test AXFR +short  # zone transfer works
```
If something times out, the cause is usually the Windows firewall (step 1) or Docker's port publishing.

## Step 5: Kali tools and venv
Masscan, nmap 7.99 and all the NSE scripts in the tables above are already installed.
```bash
cd ~/Projects/Security/training/week2
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```
Masscan needs root and a rate limit. Keep it small on a home LAN:
```bash
sudo masscan 192.168.1.250 -p1-65535 --rate 500 -oJ scans/masscan_250.json
```
Never give masscan a range bigger than `192.168.1.248/29`. Your labguard firewall drops anything else, but don't rely on that.

## Step 6: When you stop training
```powershell
docker compose down
```
Don't leave vulnerable targets running when you're not using them. Add `--profile heavy` if you started that profile. The services use `restart: "no"`, so they won't come back by themselves after a reboot.

## Week 2 assignments (your work)
1. **Pipeline:** read `week1/scans/subdomains.json` → unique in-scope IPs → masscan → Nmap `-sV` on only the ports masscan found. Your `scan_open_ports()` is the start of this.
2. **NSE:** collect HTTP headers, TLS facts (issuer, expiry, protocols, cipher grade) and banners.
   Start with `nmap -Pn -p 80,443 --script http-headers,http-security-headers,ssl-cert,ssl-enum-ciphers 192.168.1.250`.
3. **Classification:** turn the NSE output into findings with a severity, e.g. unauth DB = High, expired TLS = Medium, missing HSTS = Low/Medium.
4. **Flask API:** `/assets`, `/findings`, `/score` serving that data.
5. **Demo prep:** which findings could be false positives, and why? (Hint: the SMTP "relay" and the self-signed cert.)

## Rules and test data
- `rules/rules.json`: classification rules. Add a rule here; no code change is needed unless it needs a new `op`.
- `rules/rules.schema.json`: checks the rule file's format when it's loaded.
- `rules/scan_profile.json`: which ports, NSE scripts and HTTP probes to run.
- `scripts/python/rule_engine.py`: applies the rules. No nmap or network code, so Flask imports it as it is. This is the file to convert to Java.
- `tests/fixtures/`: a saved real TCP scan and its expected findings. Check any version of the engine with `.venv/bin/python -m unittest discover tests`.

## Dashboard and API
Run from `week2/`, then open http://127.0.0.1:5000. It only shows `scans/pipeline_result.json`, and rereads the file on each request, so a new pipeline run appears after a page refresh.
```bash
.venv/bin/pip install -r requirements.txt   # first time, if python-dotenv is missing
.venv/bin/python webapp/app.py
```
- `/api/summary`, `/api/assets`, `/api/score`
- `/api/findings`, with optional filters `?severity=&confidence=&protocol=&port=`

It has no login, so keep `WEBAPP_HOST=127.0.0.1` in `.env`.
