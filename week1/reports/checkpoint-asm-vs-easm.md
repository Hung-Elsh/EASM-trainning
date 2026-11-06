# Checkpoint prep: internal ASM vs EASM

Goal: explain the difference in about 5 minutes, using your own lab as the example, then answer follow-up questions.

## 1. Core definitions (learn these by heart)
- **Attack surface:** every point where an attacker could try to get in: hosts, ports, services, domains, certificates, cloud and SaaS accounts, people.
- **ASM (Attack Surface Management):** continuously finding, inventorying, classifying and monitoring those points, then reducing them.
- **Internal ASM:** the view **from inside** the network, with credentials or agents. It's built from known sources: CMDB, Active Directory, cloud accounts, endpoint agents and internal scans.
- **EASM (External ASM):** the view **an outsider has**, with no credentials and starting from just a company name or domain. It finds what's reachable from the internet, including things the organisation doesn't know it owns.

One-line answer: *internal ASM starts from what you know you own; EASM starts from what an attacker can see, and finds what you forgot.*

## 2. Comparison table
| | Internal ASM | EASM |
|---|---|---|
| Viewpoint | Insider: admin, agent, authenticated scan | Outsider: anonymous, internet |
| Starting point | Asset inventory, AD, cloud APIs | A domain, an organisation name, IP ranges |
| Discovery | Agents, credentialed scans, config APIs | DNS, certificate transparency, passive data (Shodan/Censys), brute forcing, scanning |
| Finds | Missing patches, local misconfigurations, lateral-movement paths | Forgotten subdomains, exposed services, expired TLS, leaked records, shadow IT |
| Main risk it covers | Damage after a breach | The first point of entry |
| Scope problem | Usually clear: it's your network | Hard: you must prove an asset is yours before you scan it |

## 3. Map it to your lab (your examples)
Use these. Examples from your own work are worth more than definitions.

**EASM-style things you did:**
- Started from only `seclab.test` and found **15 names** with DNS records, label extraction, mutations and gobuster.
- Found **hidden assets**: `hr-portal-x7`, leaked in a TXT record, and `backup-2026`, found by a year mutation. An internal inventory might not list these, but an attacker would find them.
- Found **stale DNS**: `www`, `mail` and `ftp` point to `.250`, but nothing is running behind them.
- Did a **scope check** (`192.168.1.248/29`) before scanning. In real EASM, attribution ("is this really ours?") is a core problem.
- Ran an **unauthenticated nmap scan**. You saw only what the firewall allows: 5 open ports and 995 filtered.

**What internal ASM would add for the same laptop:**
- Logging into Windows would show every installed program, patch level and local user, all listening ports including those the firewall hides, and the Docker containers.
- It would explain *why* ports 2179 and 445 are open (Hyper-V, file sharing), without guessing from banners.
- It wouldn't find `hr-portal-x7` unless someone had recorded it. That's the gap EASM fills.

**The firewall is a good talking point:** from outside, 995 ports are filtered. From inside, you'd see every service. The same machine has two different attack surfaces depending on where you stand.

## 4. Likely questions, with answer outlines
1. **"Why do companies need EASM if they have an asset inventory?"** Inventories go out of date. Shadow IT, old projects, acquisitions and third-party hosting create assets nobody recorded. *Lab example:* `backup-2026`.
2. **"Passive vs active discovery?"** Passive means looking up data that already exists (cert logs, Shodan, subfinder) without touching the target. Active means sending queries or scans (brute forcing, nmap). *Lab example:* subfinder finds nothing for `.test`, but gobuster does.
3. **"Why didn't Amass work?"** v5.1.1 accepts `-brute` but never runs it (issue #1122). This shows why you verify tool behaviour, which you did with the dnsmasq log.
4. **"What's a dangling DNS record and why does it matter?"** A CNAME pointing to a resource that no longer exists, for example a deleted cloud bucket. An attacker can claim that resource and serve content under your domain (subdomain takeover).
5. **"How do you avoid scanning things you don't own?"** A written scope, checking every IP against it in code, `configure=False` on the resolver, and the labguard firewall as a second safety net.
6. **"Why does nmap show 'filtered' and how do you deal with it?"** The firewall drops the probes. Use ARP or `-Pn` for discovery, and don't assume "no reply" means "no host".
7. **"What would you add next?"** NSE checks for headers and TLS, classifying findings by severity, enrichment from Shodan/Censys, and monitoring for changes over time (Phases 2–4).

## 5. How to practise
1. Say section 1 out loud without notes, in under 1 minute.
2. Draw on paper: Kali → (outside view) → Windows firewall → services, and next to it what an agent on Windows would see.
3. Answer each question in section 4 in 2–3 sentences, always using one lab example.
4. Show the evidence: run `scanner_easm.py`, then open `scans/subdomains.json` and `reports/week1-inventory.md`.
