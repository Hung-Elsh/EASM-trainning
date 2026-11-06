import dns.resolver
import ipaddress
import json
import nmap
import requests
import re
import socket
import subprocess

from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from jsonschema import Draft202012Validator

SCRIPT_DIR = Path(__file__).resolve().parent
SCANS_DIR = SCRIPT_DIR.parents[1] / "scans"  # week1/scans
SCANS_DIR.mkdir(exist_ok=True)

with open(SCRIPT_DIR / "schemas" / "nmap_host.schema.json") as f:
    schema = json.load(f)
validator = Draft202012Validator(schema)


WORDLISTS_PATH = "/home/elliot/Projects/Security/training/week1/lab/wordlists/subdomains-small.txt"

RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "PTR", "SOA", "SRV", "TXT"]
LAB_RECORD_TYPES = ["MX", "TXT"]

resolver = dns.resolver.Resolver(configure=False)
resolver.nameservers = ["127.0.0.1"]  # kali dns

scanner = nmap.PortScanner()

LAB_SCOPE = ipaddress.ip_network("192.168.1.248/29")


def _local_ip():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("192.168.1.1", 53))
        return s.getsockname()[0]

IPADDR = _local_ip()

PORTS_RANGE = "1-1000"

# Step 1: Fetch DNS records from the lab env

def _short_helper(answer):
    # answer is an rdata object, so compare its record type, not the object itself
    rdtype = dns.rdatatype.to_text(answer.rdtype)
    if rdtype == 'MX':
        return answer.exchange.to_text().rstrip(".")
    elif rdtype == 'TXT':
        return b''.join(answer.strings).decode('utf-8')
    elif rdtype in ('A', 'AAAA'):
        return answer.address
    elif rdtype in ('CNAME', 'NS', 'PTR'):
        return answer.target.to_text().rstrip('.')
    elif rdtype == 'SRV':
        return answer.target.to_text().rstrip('.')
    else:
        return answer.to_text()

def _extract_labels(answer):
    labels = set()
    for token in re.split(r"[\s=]+", answer):
        token = token.replace(".seclab.test", "")
        if re.fullmatch(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?", token):
            labels.add(token)
    return labels

def fetch_dns_records():
    subdomains = set()
    for record_type in LAB_RECORD_TYPES:
        try:
            answers = resolver.resolve("seclab.test", record_type)
            for rdata in answers:
                subdomains.update(_extract_labels(_short_helper(rdata)))
        except dns.resolver.NoAnswer:
            print(f"No {record_type} record found.")
        except dns.resolver.NXDOMAIN:
            print(f"Domain does not exist.")
        except Exception as e:
            print(f"Error fetching {record_type} record: {e}")
    return subdomains

# Step 2: Mutate the subdomains
def mutate_subdomains(subdomains):
    wordlists = []
    with open(WORDLISTS_PATH, "r") as f:  # Open a known wordlist file
        wordlists = [line.strip() for line in f]
    wordlists.extend(subdomains)  # Add the fetched subdomains to the wordlist
    mutated_subdomain = set(wordlists)
    for word in wordlists:
        for year in ("2024", "2025", "2026"):
            mutated_subdomain.add(f"{word}-{year}")
    return mutated_subdomain

# Step 3: Brute force the subdomains with gobuster

def brute_force_subdomains(subdomains):
    mutated_subdomain = mutate_subdomains(subdomains)
    cmd = ["gobuster", "dns", "--do", "seclab.test", "--resolver", "127.0.0.1:53", "-w", "-", "-q"]
    result_subdomains = defaultdict(list)
    try:
        result = subprocess.run(
            cmd,
            input="\n".join(mutated_subdomain),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        if result.stderr:
            print(f"gobuster error: {result.stderr}")
        for line in result.stdout.splitlines():
            split_line = line.split()
            if len(split_line) < 2:
                continue
            # a name with several IPs is printed as "name ip1,ip2"
            for ip in split_line[1].split(","):
                result_subdomains[ip].append(split_line[0])
    except subprocess.CalledProcessError as e:
        print(f"Error running gobuster: {e.stderr}")
    except FileNotFoundError:
        print("gobuster command not found. Please ensure it is installed and in your PATH.")
    return result_subdomains


def save_subdomains(result_subdomains):
    # Deliverable: JSON of subdomains and their resolved IPs
    by_name = defaultdict(list)
    for ip, names in result_subdomains.items():
        for name in names:
            by_name[name].append(ip)
    subdomains = [
        {
            "fqdn": name,
            "ips": sorted(ips),
            "in_scope": all(ipaddress.ip_address(ip) in LAB_SCOPE for ip in ips),
            "source": "gobuster",
        }
        for name, ips in sorted(by_name.items())
    ]
    output_file = SCANS_DIR / "subdomains.json"
    with open(output_file, "w") as f:
        json.dump({
            "domain": "seclab.test",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "subdomains": subdomains,
        }, f, indent=4)
    print(f"Saved {len(subdomains)} subdomains to {output_file}")


# Step 4: Resolve every name to an IP address, check it's scope, and then scan with nmap
def scan(result_subdomains):
    open_ports =  defaultdict(list)
    for ip in result_subdomains.keys():
        if ipaddress.ip_address(ip) not in LAB_SCOPE:
            print(f"Out of scope, skipping {ip}: {', '.join(result_subdomains[ip])}")
            continue
        if ip == IPADDR:
            print(f"Skipping {ip}: this is the Kali host itself")
            continue  # Skip scanning the lab's own IP address
        print(f"Scanning {ip}...")
        try:
            scanner.scan(ip, arguments=f"-sS -p {PORTS_RANGE}")
            # python-nmap refuses -oX, but keeps the raw XML of the last scan
            output_file_xml = SCANS_DIR / f"nmap_scan_{ip}_result.xml"
            with open(output_file_xml, "w") as f:
                f.write(scanner.get_nmap_last_output().decode())
            scan_data = scanner[ip]
            errors = list(validator.iter_errors(scan_data))
            if errors:
                for err in errors:
                    print(f"Schema error in {ip}: {err.json_path}: {err.message}")
            else:
                output_file = SCANS_DIR / f"nmap_scan_{ip}_result.json"
                with open(output_file, "w") as f:
                    json.dump(scan_data, f, indent=4)
                # "tcp" is missing when nothing answered; keep only ports that are really open
                for port, info in scan_data.get("tcp", {}).items():
                    if info["state"] == "open":
                        open_ports[ip].append(port)
        except Exception as e:
            print(f"Error scanning {ip}: {e}")
    return open_ports


# Step 5: Service scan (-sV) on the open ports only
def scan_open_ports(open_ports):
    for ip, ports in open_ports.items():
        if not ports:
            continue
        port_list = ",".join(map(str, ports))
        print(f"Service scan {ip} on ports {port_list}...")
        try:
            scanner.scan(ip, arguments=f"-Pn -sV -p {port_list}")
            # separate files: appending a second XML/JSON document makes the file invalid
            with open(SCANS_DIR / f"nmap_services_{ip}.xml", "w") as f:
                f.write(scanner.get_nmap_last_output().decode())
            scan_data = scanner[ip]
            errors = list(validator.iter_errors(scan_data))
            if errors:
                for err in errors:
                    print(f"Schema error in {ip}: {err.json_path}: {err.message}")
            else:
                output_file = SCANS_DIR / f"nmap_services_{ip}_result.json"
                with open(output_file, "w") as f:
                    json.dump(scan_data, f, indent=4)
        except Exception as e:
            print(f"Error scanning {ip}: {e}")

if __name__ == "__main__":
    subdomains = fetch_dns_records()
    result_subdomains = brute_force_subdomains(subdomains)
    save_subdomains(result_subdomains)
    open_ports = scan(result_subdomains)
    scan_open_ports(open_ports)
 