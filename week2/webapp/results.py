# Loads the pipeline result file and does the aggregation. No Flask in here.
import json
import os
from pathlib import Path

SEVERITIES = ["critical", "high", "medium", "low", "info"]
CONFIDENCES = ["confirmed", "likely", "version-only"]
WEIGHTS = {"critical": 25, "high": 10, "medium": 4, "low": 1, "info": 0}

DEFAULT_PATH = Path(__file__).resolve().parents[1] / "scans" / "pipeline_result.json"


class NoResultsError(Exception):
    pass


def load_results():
    # Read on every call so a new pipeline run shows up without a restart.
    path = os.environ.get("RESULTS_FILE") or str(DEFAULT_PATH)
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, ValueError):
        raise NoResultsError("results file missing or not valid JSON")
    if not isinstance(data, dict):
        raise NoResultsError("results file has the wrong shape")
    return data


def get_assets(data):
    return data.get("assets", [])


def get_findings(data):
    return data.get("findings", [])


def finding_penalty(finding):
    penalty = WEIGHTS.get(finding.get("severity"), 0)
    if finding.get("confidence") == "version-only":
        penalty = penalty / 2
    return penalty


def score_from_penalty(penalty):
    return max(0, round(100 - penalty))


def sort_findings(findings):
    def key(f):
        sev = f.get("severity")
        rank = SEVERITIES.index(sev) if sev in SEVERITIES else len(SEVERITIES)
        return (rank, f.get("port", 0))
    return sorted(findings, key=key)


def filter_findings(findings, severity=None, confidence=None, protocol=None, port=None):
    result = []
    for f in findings:
        if severity is not None and f.get("severity") != severity:
            continue
        if confidence is not None and f.get("confidence") != confidence:
            continue
        if protocol is not None and f.get("protocol") != protocol:
            continue
        if port is not None and f.get("port") != port:
            continue
        result.append(f)
    return result


def count_by_severity(findings):
    counts = {}
    for sev in SEVERITIES:
        counts[sev] = 0
    for f in findings:
        if f.get("severity") in counts:
            counts[f["severity"]] += 1
    return counts


def count_by_confidence(findings):
    counts = {}
    for conf in CONFIDENCES:
        counts[conf] = 0
    for f in findings:
        if f.get("confidence") in counts:
            counts[f["confidence"]] += 1
    return counts


def open_services(assets):
    result = []
    for asset in assets:
        for svc in asset.get("services", []):
            if svc.get("state") == "open":
                result.append(svc)
    return result


def top_services(assets, limit=10):
    counts = {}
    for svc in open_services(assets):
        name = (svc.get("name") or "").strip()
        if name == "":
            name = "unknown"
        counts[name] = counts.get(name, 0) + 1
    items = [{"name": n, "count": c} for n, c in counts.items()]
    # most first, name as tie-break so the order is stable
    items.sort(key=lambda i: (-i["count"], i["name"]))
    return items[:limit]


def riskiest_ports(findings, limit=10):
    groups = {}
    for f in findings:
        key = (f.get("ip"), f.get("port"), f.get("protocol"))
        if key not in groups:
            groups[key] = {"ip": key[0], "port": key[1], "protocol": key[2],
                           "findings": 0, "penalty": 0}
        groups[key]["findings"] += 1
        groups[key]["penalty"] += finding_penalty(f)
    items = list(groups.values())
    items.sort(key=lambda i: (-i["penalty"], str(i["ip"]), i["port"] or 0))
    return items[:limit]


def summary(data):
    assets = get_assets(data)
    findings = get_findings(data)
    return {
        "generated_at": data.get("generated_at"),
        "hosts": len(assets),
        "services": len(open_services(assets)),
        "findings": len(findings),
        "by_severity": count_by_severity(findings),
        "by_confidence": count_by_confidence(findings),
        "top_services": top_services(assets),
        "riskiest_ports": riskiest_ports(findings),
    }


def score(data):
    findings = get_findings(data)
    total = 0
    per_host = {}
    # hosts with no findings still appear, with a score of 100
    for asset in get_assets(data):
        per_host[asset.get("ip")] = {"ip": asset.get("ip"), "penalty": 0, "findings": 0}
    for f in findings:
        total += finding_penalty(f)
        ip = f.get("ip")
        if ip not in per_host:
            per_host[ip] = {"ip": ip, "penalty": 0, "findings": 0}
        per_host[ip]["penalty"] += finding_penalty(f)
        per_host[ip]["findings"] += 1
    hosts = []
    for entry in per_host.values():
        entry["score"] = score_from_penalty(entry["penalty"])
        hosts.append(entry)
    hosts.sort(key=lambda h: (h["score"], str(h["ip"])))
    return {
        "score": score_from_penalty(total),
        "penalty": total,
        "weights": dict(WEIGHTS),
        "hosts": hosts,
    }
