# testing a dummy pipeline file
#
# Flow: subdomains.json -> resolve -> scope check -> masscan -> nmap -sV -> NSE -> classify -> JSON
# Run:  sudo .venv/bin/python scripts/python/dummy_pipeline.py   (masscan and -sS/-sU need root)
#
# Work in order and print each step's result before starting the next one.
# After each step, save its output in scans/ so you can rerun later steps without rescanning.

import dns
import nmap
import dns.resolver
import ipaddress
import json
import requests
import re
import socket
import subprocess
import urllib3
import xml.etree.ElementTree as ET

from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from jsonschema import Draft202012Validator

from rule_engine import RULES_DIR, evaluate, load_rules

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # lab targets use bad certificates

with open(RULES_DIR / "scan_profile.json") as f:
    PROFILE = json.load(f)

SCRIPT_DIR = Path(__file__).resolve().parent
SCANS_DIR = SCRIPT_DIR.parents[1] / "scans"  # week2/scans
SCANS_DIR.mkdir(exist_ok=True)

with open("/home/elliot/Projects/Security/training/week1/scripts/python/schemas/nmap_host.schema.json") as f:
    schema = json.load(f)
validator = Draft202012Validator(schema)

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
# Suggested imports as you need them: json, subprocess, ipaddress, re, dns.resolver,
# collections.defaultdict, datetime, pathlib.Path

# Suggested settings:
# LAB_SCOPE = ipaddress.ip_network("192.168.1.248/29")
# KALI_IP = "192.168.1.249"
# SUBDOMAINS_FILE = week1/scans/subdomains.json   (build it from Path(__file__), as in scanner_easm.py)
# SCANS_DIR = week2/scans


# step 1: read subdomains.json then resolve subdomains
def resolve_subdomains(subdomains_file):
    names_by_ip = defaultdict(list)
    with open(subdomains_file) as f:
        data = json.load(f)
    for subdomain in data["subdomains"]:
        fqdn = subdomain["fqdn"]
        try:
            answers = resolver.resolve(fqdn, "A")
            for answer in answers:
                names_by_ip[answer.address].append(fqdn)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            print(f"Stale DNS record: {fqdn} has no A record")
    return names_by_ip


# step 2: port-scan with masscan (fast sweep)
def masscan_sweep(ips):
    cmd = ["masscan", "--rate", "200", "-p1-65535,U:53,U:123,U:161,U:11211", "-oJ", SCANS_DIR / "masscan.json", "--retries" , "2"]
    to_scan = set()
    for ip in ips:
        if ipaddress.ip_address(ip) not in LAB_SCOPE or ip == IPADDR:
            continue
        to_scan.add(ip)
    if not to_scan:
        print("No IPs to scan after scope check.")
        return {}
    cmd.extend(to_scan)
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        with open(SCANS_DIR / "masscan.json") as f:
            text = f.read().rstrip()
        if not text:
            return {}
        text = re.sub(r",\s*]$", "]", text)
        sweep = defaultdict(lambda: {"tcp": set(), "udp": set()})
        for record in json.loads(text):
            for port in record["ports"]:
                sweep[record["ip"]][port["proto"]].add(port["port"])
        return {ip: {"tcp": sorted(ports["tcp"]), "udp": sorted(ports["udp"])} for ip, ports in sweep.items()}
    except subprocess.CalledProcessError as e:
        print(f"Error running masscan: {e.stderr}")
        return {}


def add_common_ports(sweep, ips):
    # Masscan misses ports on Wi-Fi, so nmap always checks these too and keeps only the open ones
    merged = {}
    for ip in ips:
        if ipaddress.ip_address(ip) not in LAB_SCOPE or ip == IPADDR:
            continue
        found = sweep.get(ip, {"tcp": [], "udp": []})
        merged[ip] = {proto: sorted(set(found[proto]) | set(PROFILE["common_ports"][proto])) for proto in ("tcp", "udp")}
    return merged


# step 3: port-scan with nmap (validate masscan and find versions)
def validate_with_nmap(sweep):
    validated_hosts = defaultdict(lambda: defaultdict(dict))
    for ip, ports in sweep.items():
        tcp_ports = ",".join(str(p) for p in ports.get("tcp", []))
        udp_ports = ",".join(str(p) for p in ports.get("udp", []))
        if not tcp_ports and not udp_ports:
            continue
        args = ["-Pn", "-sV"]
        port_specs = []  # only add a section that has ports: nmap rejects an empty "T:"
        if tcp_ports:
            args.append("-sS")
            port_specs.append(f"T:{tcp_ports}")
        if udp_ports:
            args.append("-sU")
            port_specs.append(f"U:{udp_ports}")
        args.append(f"-p {','.join(port_specs)}")
        try:
            scanner.scan(ip, arguments=" ".join(args))
            if ip not in scanner.all_hosts():
                print(f"{ip} did not respond to nmap scan")
                continue
            output_file_xml = SCANS_DIR / f"nmap_scan_{ip}_result.xml"
            with open(output_file_xml, "w") as f:
                f.write(scanner.get_nmap_last_output().decode())
            scan_data = scanner[ip]
            errors = list(validator.iter_errors(scan_data))
            if errors:
                for err in errors:
                    print(f"Schema error in {ip}: {err.json_path}: {err.message}")
            for port, info in scan_data.get("tcp", {}).items():
                if info["state"] == "open":
                    validated_hosts[ip]["tcp"][port] = info
            for port, info in scan_data.get("udp", {}).items():
                if info["state"] in ("open", "open|filtered"):
                    validated_hosts[ip]["udp"][port] = info
        except Exception as e:
            print(f"Error scanning {ip}: {e}")
    return validated_hosts


# step 4: run NSE, choosing scripts by the service that -sV found
# python-nmap keeps only each script's text, but the XML also has its structured tables.
def _nse_table(node):
    # Turns <table>/<elem> into dicts and lists: <elem key="notAfter"> becomes {"notAfter": ...}
    named, items = {}, []
    for child in node:
        value = child.text if child.tag == "elem" else _nse_table(child)
        if child.get("key") is None:
            items.append(value)
        else:
            named[child.get("key")] = value
    if named and items:
        named["items"] = items
    return named or items


def _read_nse_xml(xml_output):
    # One entry per script: {"output": text, "data": table or None, "failed": True if it crashed}
    results = {}
    for script in ET.fromstring(xml_output).iter("script"):
        output = script.get("output", "")
        results[script.get("id")] = {
            "output": output,
            "data": _nse_table(script) if len(script) else None,
            "failed": "ERROR: Script execution failed" in output,
        }
    return results


def _web_scheme(ip, port):
    # Asks the port itself, because nmap doesn't always name a web service "http" (3000 is "ppp")
    for scheme in ("https", "http"):
        try:
            requests.get(f"{scheme}://{ip}:{port}/", timeout=3, verify=False, allow_redirects=False)
            return scheme
        except requests.RequestException:
            continue
    return None


def _run_http_probes(ip, port, scheme):
    # Same result shape as an NSE script, stored as "probe:<id>". Only GET and OPTIONS are sent,
    # and the response body isn't stored.
    results = {}
    for probe in PROFILE["http_probes"]:
        try:
            response = requests.request(probe["method"], f"{scheme}://{ip}:{port}{probe['path']}",
                                        timeout=5, verify=False, allow_redirects=False)
        except requests.RequestException:
            continue
        reply = f"{response.headers}\n{response.text}"
        if response.status_code == probe["status"] and probe["contains"].lower() in reply.lower():
            results[f"probe:{probe['id']}"] = {
                "output": f"{probe['method']} {probe['path']} -> {response.status_code}, found {probe['contains']}",
                "data": None,
                "failed": False,
            }
    return results


def _scan_port(ip, proto, port, info):
    name = info.get("name")
    product = info.get("product") or ""
    scripts = list(PROFILE["service_scripts"].get(name, []))
    is_web = name in PROFILE["web_services"]
    forced = False
    if not scripts and name not in PROFILE["no_web_check_services"] and proto == "tcp":
        if _web_scheme(ip, port):
            # Without "+", NSE skips web scripts on a port nmap didn't name "http"
            scripts, is_web, forced = list(PROFILE["service_scripts"]["http"]), True, True
    if not scripts:
        print(f"No scripts for {ip}:{port}/{proto} ({name})")
        return {}

    limited = any(text in product for text in PROFILE["no_active_products"])
    if name == "http" and not limited:
        scripts += PROFILE["active_web_scripts"]
    script_list = ",".join(("+" + script) if forced else script for script in scripts)
    script_args = ",".join(f"{key}={value}" for key, value in PROFILE["script_args"].items())
    udp_flag = "-sU " if proto == "udp" else ""

    port_scanner = nmap.PortScanner()  # one per port: PortScanner isn't safe to share between threads
    port_scanner.scan(ip, arguments=f"-Pn -sV {udp_flag}--script={script_list} --script-args {script_args} "
                                    f"--script-timeout {PROFILE['script_timeout']} -p {port}")
    results = _read_nse_xml(port_scanner.get_nmap_last_output())
    if is_web and not limited:
        scheme = _web_scheme(ip, port)
        if scheme:
            results.update(_run_http_probes(ip, port, scheme))
    return results


def run_nse(hosts):
    nse_results = defaultdict(lambda: defaultdict(dict))
    jobs = [(ip, proto, port, info) for ip, services in hosts.items()
            for proto, ports in services.items() for port, info in ports.items()]
    with ThreadPoolExecutor(PROFILE["workers"]) as pool:
        futures = {pool.submit(_scan_port, *job): job for job in jobs}
        for future in as_completed(futures):
            ip, proto, port, _ = futures[future]
            try:
                results = future.result()
            except Exception as e:
                print(f"Error running NSE on {ip}:{port}/{proto}: {e}")
                continue
            for name, result in results.items():
                if result["failed"]:
                    print(f"Check failed on {ip}:{port}/{proto}: {name}")
            nse_results[ip][proto][port] = results
    return nse_results


# step 5: classify exposures. The rules are data in rules/rules.json, applied by rule_engine.py.
def classify(hosts, nse_results, names_by_ip):
    findings = []
    rules = load_rules()
    for ip, protocols in hosts.items():
        for proto, ports in protocols.items():
            for port, info in ports.items():
                scripts = nse_results.get(ip, {}).get(proto, {}).get(port, {})
                for finding in evaluate(rules, info, scripts, proto):
                    finding.update(ip=ip, port=port, protocol=proto, names=names_by_ip.get(ip, []))
                    findings.append(finding)
    return findings


# step 6: save the dataset
def save_results(hosts, names_by_ip, findings):
    assets = []
    for ip, protocols in hosts.items():
        services = []
        for proto, ports in protocols.items():
            for port, info in sorted(ports.items()):
                services.append({
                    "port": port,
                    "protocol": proto,
                    "state": info.get("state"),
                    "name": info.get("name"),
                    "product": info.get("product"),
                    "version": info.get("version"),
                })
        assets.append({"ip": ip, "names": names_by_ip.get(ip, []), "services": services})
    output_file = SCANS_DIR / "pipeline_result.json"
    with open(output_file, "w") as f:
        json.dump({
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "assets": assets,
            "findings": findings,
        }, f, indent=4)
    print(f"Saved {len(assets)} assets and {len(findings)} findings to {output_file}")


# Build this one step at a time, and uncomment each line once its function works.
if __name__ == "__main__":
    names_by_ip = resolve_subdomains("/home/elliot/Projects/Security/training/week1/scans/subdomains.json")
    sweep = masscan_sweep(names_by_ip.keys())
    hosts = validate_with_nmap(add_common_ports(sweep, names_by_ip.keys()))
    nse_results = run_nse(hosts)
    with open(SCANS_DIR / "nse_results.json", "w") as f:
        json.dump(nse_results, f, indent=4)  # raw evidence, including failed checks
    findings = classify(hosts, nse_results, names_by_ip)
    save_results(hosts, names_by_ip, findings)


# TODO: move all the code of this pipeline and scripts/python/scanner_easm.py to a complete Flask API app - backend is scanner, frontend dashboard with charts.js
