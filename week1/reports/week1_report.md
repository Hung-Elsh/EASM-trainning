# Week 1 report: differences between internal ASM and EASM

## 1. Terms and meanings

Attack surface refers to the entry points that attacker can try to get in

Internal attack surface refers to internal resource (view from the inside the network) - the collection of systems, applications, devices, accounts, and network paths within an organization - that attackers can exploit after gaining initial access

External attack surface refers to expose parts that attacker can see from outside of the network - outwardly exposed assets, resources, and technologies that required no credentials to access like domain, name, host ip/ports, ...

Attack Surface Management: finding, inventorying, classifying and monitoring those points, then reducing them - from both side of the network

EASM: external Surface Management - reduce external attack surface - prevent essential data leaking from exposed entry point

*internal ASM starts from what you know you own; EASM starts from what an attacker can see, and finds what you forgot.*


## 2. Comparison table
| | Internal ASM | EASM |
|---|---|---|
| Viewpoint | Insider: admin, agent, authenticated scan | Outsider: anonymous, internet |
| Starting point | Asset inventory, AD, cloud APIs | A domain, an organisation name, IP ranges |
| Discovery | Agents, credentialed scans, config APIs | DNS, certificate transparency, passive data (Shodan/Censys), brute forcing, scanning |
| Finds | Missing patches, local misconfigurations, lateral-movement paths | Forgotten subdomains, exposed services, expired TLS, leaked records, shadow IT |
| Main risk it covers | Damage after a breach | The first point of entry |
| Scope problem | Usually clear: it's your network | Hard: you must prove an asset is yours before you scan it |


## 3. In lab result

- set up lab env:
    - 2 machines - attacker kali | target window in local wlan network (fixed ip)
    - dns with seclab conf
- discovery result:
    - step 1: dig | dnspython to find dns record from known network seclab.test
        -> 15 sub domain with one hidden assets from leaking TXT record
    - step 2: mutate subdomain
    - step 3: gobuster to bruce force subdomain
        -> 2 hosts: one is attacker, other is the target's ip + new hidden domain
    - step 4: run nmap -sS for TCP SYN scan on target with port range 1 - 1000
        -> found stale subdomains, 5 ports open, 995 closed. 2 open ports are guested services behind
    - step 5: run nmap -Pn -sV to get service name
        -> port 445 has no product name
- check on target machine:
    - port 445 open for internal network file sharing with required credentials



