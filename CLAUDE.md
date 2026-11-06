# EASM self-training

Self-study of External Attack Surface Management, for the owner's own practice (not for an employer).
The plan is a guide, not a checklist: `SecPod Vietnam Onboarding Training Plan for EASM Product Development.docx`.
`week1/` holds Phase 1 and `week2/` holds Phase 2.

## How to work with me
Follow the wording of each request. Don't guess across requests.

| I say | You do |
|---|---|
| "give me instruction", "guide me", or similar | Explain the cause and the steps. I type the code and commands myself, so don't edit. |
| "you should write", "fix it for me", or similar | Write the code directly. |
| Asking you to check or review | Read and test only. Report what you find, and don't edit. |

- If I ask you to do a task, I'll include the action and related information. If something you need is missing, ask me for it instead of guessing.
- An instruction applies to its own request, unless I say it applies from now on.
- Change the system (services, firewall, packages) only when I ask. `sudo` needs my password, so give me those commands to run.
- **Never SSH or scp to the Windows laptop without my permission for that specific action.** Otherwise, give me the command. Scanning its port 22 is fine.

## Lab
| Item | Value |
|---|---|
| Kali (attacker, lab DNS) | 192.168.1.249, on `wlan0` |
| Windows laptop (target, Docker) | 192.168.1.250 |
| Scope | 192.168.1.248/29, domain `seclab.test` |
| Router | 192.168.1.1 |

**Safety:** never scan outside the scope. Other devices on this home network are off limits, and the lab isn't exposed to the internet. Only Kali may reach the targets. On the real Windows services, use safe scripts only: no `smb-vuln-*`, `smb-flood`, `smb-brute` or other brute-force scripts.

**After a Kali restart:** the lab DNS and firewall guard may need starting again (I run these):
```bash
cd week1/lab
sh dns/start-dns.sh
dig +short @127.0.0.1 admin.seclab.test      # expect 192.168.1.250
sudo nft list table inet labguard            # if missing: sudo nft -f firewall/labguard.nft
```
The scratchpad can also be lost after a restart, so don't keep anything there that you need later.

## Reference
| Topic | File |
|---|---|
| Address plan | `week1/lab/NETWORK.md` |
| Nmap and DNS cheat sheet | `week1/lab/CHEATSHEET.md` |
| Week 1 scanner | `week1/scripts/python/scanner_easm.py` |
| Week 1 reports | `week1/reports/` |
| Discovered names | `week1/scans/subdomains.json` |
| Week 2 setup, targets, port-to-script tables | `week2/README.md` |
| Docker targets and Kali-only firewall | `week2/lab/targets/` (`firewall.ps1`) |
| NSE scripts by port | `week2/reports/nse-by-port.md` |
| Week 2 pipeline | `week2/scripts/python/dummy_pipeline.py` |
| Classification rules (JSON, shared with the planned Java version) | `week2/rules/`, applied by `week2/scripts/python/rule_engine.py` |
| Rule tests on a saved scan | `week2/tests/` |
| Results API and dashboard (read-only, Flask + Chart.js) | `week2/webapp/`, run with `.venv/bin/python webapp/app.py` from `week2/`; settings in `week2/.env` |
| Answer key | `week2/lab/targets/EXPECTED.md`: **don't show me its contents until my classifier has produced its own findings** |

Each week has its own `.venv`. The week 2 pipeline needs root:
`sudo .venv/bin/python scripts/python/dummy_pipeline.py` (run from `week2/`).

## Known quirks
- Kali's nmap 7.99 has script bugs: `http-sql-injection` and `http-unsafe-output-escaping` crash on URLs with query strings unless `url.lua` is patched (see `week2/README.md`), and `http-config-backup` crashes after finding a file.
- HTTP scripts skip non-standard ports unless `-sV` is used.
- python-nmap refuses `-oX <file>`. Use `get_nmap_last_output()`, which also has the NSE tables.
- Amass v5.1.1 accepts `-brute` but never runs it (issue #1122). Subfinder is passive only, so it finds nothing for `.test`. Use gobuster.
- Masscan on Wi-Fi misses ports, even at `--rate 200 --retries 2`. Don't treat its list as complete.
- These `week2` services are fake on purpose: the Docker API, Kubernetes, kubelet, etcd, VNC and port 9000.

## Roadmap
Phase 2: the read-only Flask API and dashboard are built; extend them only when I ask. This project is also the base for my Java 21 certification practice: I convert the Python to Java later, so keep logic and data portable. Phase 3: Shodan/Censys/ZoomEye enrichment (mocked for private IPs). Phase 4: capstone with new-asset detection and alerts.
