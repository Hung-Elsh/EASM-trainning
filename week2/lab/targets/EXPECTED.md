# Answer key: planted misconfigurations
Don't read this until your classifier has produced its own findings. Then compare.

| Target | Planted issue | How to detect | Suggested severity |
|---|---|---|---|
| 6379 Redis | No password, protected mode off | `redis-info` NSE returns data; `redis-cli ping` → PONG | High |
| 9200 Elasticsearch | Security disabled, open read/write | `GET /` and `GET /_cat/indices` work without auth | High |
| 80 web | `/backup/db_dump_2024.sql.bak` in a public directory listing | `http-enum` NSE, or follow the HTML comment | High |
| 8080 API | No auth on `/api/v1/users`; `/api/v1/config` leaks a password | `curl` the endpoints listed at `/` | High |
| 25 SMTP | Accepts mail for any domain (open relay behaviour) | `smtp-open-relay` NSE | Medium. A false positive in practice: Mailpit never delivers |
| 443 web | Certificate expired 2025-01-01, self-signed | `ssl-cert` NSE: "Not valid after" | Medium |
| 443 web | TLS 1.0/1.1 and weak ciphers allowed | `ssl-enum-ciphers` NSE grade (C or worse) | Medium |
| 80/443 web | No HSTS, X-Frame-Options, X-Content-Type-Options or CSP | `http-security-headers`, `http-headers` | Low/Medium |
| 80 web | Version disclosure `nginx/1.18.0` (end-of-life) | `-sV`, Server header | Low |
| 80 web | Directory listing on | `http-title` "Index of /" | Low |
| 8080 API | `Access-Control-Allow-Origin: *`, `X-Powered-By` banner | `http-headers` | Low |
| 22 SSH | Remote admin service exposed | `-sV`, `ssh2-enum-algos` | Info (Low if password auth is enabled) |
| 8000 vulnshop | SQL injection in `/product?id=` | `http-sql-injection` (needs the url.lua fix), `curl "...?id=1'"` | High |
| 8000 vulnshop | Path traversal in `/page?file=` | `curl ".../page?file=../../../../etc/passwd"` | High |
| 8000 vulnshop | Default Basic auth admin/admin on `/admin` | `http-auth-finder`, `http-brute` | High |
| 8000 vulnshop | `/.env` leaks a password | `http-robots.txt` points to it, then `curl` | High |
| 8000 vulnshop | Reflected and stored XSS | `http-unsafe-output-escaping`, `http-stored-xss` | Medium |
| 8000 vulnshop | No CSRF tokens; session cookie without HttpOnly; credentials in a comment | `http-csrf`, `http-cookie-flags`, `http-comments-displayer` | Medium/Low |
| 8081 DVWA | Training app with many flaws, old Apache/PHP | `-sV`, `http-enum`, `http-cookie-flags` | High |
| 3000 Juice Shop | Training app with exposed paths in robots.txt | `http-robots.txt`, `http-enum` | Medium |
| 8082 Apache | `.git` exposed | `http-git` | High |
| 8082 Apache | Backup files with secrets (`wp-config.php.bak`, `.env`) | `http-backup-finder`, `curl` | High |
| 8082 Apache | WebDAV upload without login at `/dav` | `http-webdav-scan`, `http-methods --script-args http-methods.url-path=/dav/` | High |
| 8082 Apache | TRACE on; `/server-status`, `/server-info` public | `http-trace`, `http-apache-server-status` | Medium |
| 8082 Apache | Version 2.4.49 (CVE-2021-41773) | `-sV` | **Likely false positive:** the default `<Directory />` deny should block the traversal. Test before reporting |
| 8888 Tomcat | Manager with tomcat/tomcat | `http-default-accounts` | Critical (deploying a WAR = code execution) |
| 8009 Tomcat | AJP exposed, 9.0.30 is in the Ghostcat range (CVE-2020-1938) | `ajp-headers`, `ajp-methods`, `-sV` | High |
| 9000, 9090 | Admin console and Prometheus with no login | `http-title`, `curl /api/v1/targets` | Medium |
| 8443 nginx | Hardened control: only the self-signed cert | `ssl-cert`, `ssl-enum-ciphers`, `http-security-headers` | Low: your classifier should stay quiet here |
| 3306 MySQL | Root with no password from any host | `mysql-empty-password`, `mysql-databases` | Critical |
| 5432 PostgreSQL | Trust auth: any password works | `pgsql-brute`, `psql -h ... -U postgres` | Critical |
| 27017 MongoDB | No auth | `mongodb-info`, `mongodb-databases` | High |
| 11211 Memcached | No auth; UDP amplification | `memcached-info`, UDP scan | High |
| 1433 MSSQL (heavy) | Weak sa password | `ms-sql-info`, `ms-sql-brute` | High |
| 21 FTP | Anonymous login exposes a file | `ftp-anon` | High |
| 23 Telnet | Cleartext login, admin/admin | `telnet-encryption`, `telnet-brute` | High |
| 2222 SSH | Password login, admin/admin | `ssh-auth-methods`, `ssh-brute` | Medium |
| 5900 VNC | No authentication (fake) | `vnc-info` | High. Mock: a real scanner can't connect further |
| 3389 RDP (heavy) | Remote desktop exposed | `rdp-enum-encryption` | Medium |
| 2375 Docker | Unauthenticated API (fake) | `docker-version`, `curl /containers/json` | Critical in real life; a mock here |
| 2376 Docker | TLS API with no client cert (fake) | `docker-version`, `ssl-cert` | Critical in real life; a mock here |
| 6443, 10250 | Kubernetes API and kubelet answer without a token (fake); cert SANs leak names | `ssl-cert`, `curl -k` | Critical in real life; a mock here |
| 2379 etcd | Keys readable without auth (fake) | `curl /v2/keys` | Critical in real life; a mock here |
| 53 DNS | Open resolver | `dns-recursion` | Medium |
| 53 DNS | Zone transfer open; version disclosed | `dns-zone-transfer`, `dns-nsid` | Medium/Low |
| 53 DNS | SPF `+all`, DMARC `p=none` | `dig TXT`, `dig TXT _dmarc.corp.seclab.test` | Medium |
| 53 DNS | Dangling CNAME `assets` | `dig`, then check whether the target resolves | High |
| 110, 143, 587 mail | Login allowed without TLS | `pop3-capabilities`, `imap-capabilities`, `smtp-commands` | Medium |
| 465, 993, 995 mail | Self-signed certificate | `ssl-cert` | Low |
| 123 NTP | Answers anyone | `ntp-info` | Low |
| 161 SNMP | Default community `public` | `snmp-info`, `snmp-sysdescr` | High |

Note: whether TLS 1.0 is actually offered depends on the OpenSSL build in the nginx image. If the scan shows TLS 1.2 only, that isn't a bug in your scanner. Record what you observe.
