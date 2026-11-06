# Applies rules/rules.json to one port's results. It only reads data and has no nmap or network
# code, so Flask can import it as it is, and it's the file to convert to Java.
#
# A rule fires when ALL its "when" conditions match. Each condition returns evidence text, or None.
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from jsonschema import Draft202012Validator

RULES_DIR = Path(__file__).resolve().parents[2] / "rules"


def load_rules():
    with open(RULES_DIR / "rules.json") as f:
        rules = json.load(f)
    with open(RULES_DIR / "rules.schema.json") as f:
        Draft202012Validator(json.load(f)).validate(rules)
    return rules["rules"]


def _ok(ctx, name):
    # A script that didn't run or crashed never counts as evidence, for or against
    result = ctx["scripts"].get(name)
    return result if result and not result["failed"] else None


def _text(ctx, name):
    result = _ok(ctx, name)
    return result["output"] if result else None


def _value(ctx, name, path):
    result = _ok(ctx, name)
    value = result["data"] if result else None
    for key in path:
        if not isinstance(value, dict) or key not in value:
            return None
        value = value[key]
    return value


def _line_with(text, needle):
    for line in text.splitlines():
        if needle in line.lower():
            return line.strip()
    return needle


def script_ran(cond, ctx):
    text = _text(ctx, cond["script"])
    return (text.strip().splitlines() or [cond["script"]])[0].strip() if text is not None else None


def any_script_ran(cond, ctx):
    return next((e for e in (script_ran({"script": s}, ctx) for s in cond["scripts"]) if e), None)


def script_absent(cond, ctx):
    return "" if cond["script"] not in ctx["scripts"] else None


def script_contains(cond, ctx):
    text = _text(ctx, cond["script"])
    if text is None:
        return None
    for needle in cond["any"]:
        if needle.lower() in text.lower():
            return _line_with(text, needle.lower())
    return None


def script_lacks(cond, ctx):
    # Fires only if the script really ran and at least one listed text is missing
    text = _text(ctx, cond["script"])
    if text is None:
        return None
    missing = [needle for needle in cond["all"] if needle.lower() not in text.lower()]
    return f"missing: {', '.join(missing)}" if missing else None


def any_script_lacks(cond, ctx):
    # Fires if a script ran and contains NONE of the listed texts
    for name in cond["scripts"]:
        text = _text(ctx, name)
        if text is not None and not any(needle.lower() in text.lower() for needle in cond["all"]):
            return f"{name}: {' or '.join(cond['all'])} not offered"
    return None


def script_matches(cond, ctx):
    text = _text(ctx, cond["script"])
    match = re.search(cond["pattern"], text, re.IGNORECASE | re.MULTILINE) if text else None
    return match.group(0).strip() if match else None


def data_exists(cond, ctx):
    value = _value(ctx, cond["script"], cond["path"])
    return f"{cond['path'][-1]}: {value}" if value is not None else None


def data_has_any_key(cond, ctx):
    data = _value(ctx, cond["script"], [])
    found = [key for key in cond["keys"] if isinstance(data, dict) and key in data]
    return ", ".join(found) if found else None


def data_in(cond, ctx):
    value = _value(ctx, cond["script"], cond["path"])
    return f"{cond['path'][-1]}: {value}" if value in cond["values"] else None


def data_contains(cond, ctx):
    value = _value(ctx, cond["script"], cond["path"])
    items = value if isinstance(value, list) else [value]
    for item in items:
        if isinstance(item, str) and any(needle in item for needle in cond["any"]):
            return f"{cond['path'][-1]}: {item}"
    return None


def data_equal(cond, ctx):
    first = _value(ctx, cond["script"], cond["path_a"])
    second = _value(ctx, cond["script"], cond["path_b"])
    if first is None or first != second:
        return None
    return f"{cond['path_a'][-1]} equals {cond['path_b'][-1]}"


def data_date_past(cond, ctx):
    value = _value(ctx, cond["script"], cond["path"])
    try:
        date = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    if date.tzinfo is None:
        date = date.replace(tzinfo=timezone.utc)  # nmap reports certificate dates in UTC
    return f"{cond['path'][-1]}: {value}" if date < datetime.now(timezone.utc) else None


def service_in(cond, ctx):
    name = ctx["info"].get("name")
    return f"service: {name}" if name in cond["names"] else None


def protocol_is(cond, ctx):
    return "" if ctx["protocol"] == cond["protocol"] else None


def version_is(cond, ctx):
    product, version = ctx["info"].get("product") or "", ctx["info"].get("version") or ""
    if cond["product"].lower() in product.lower() and version in cond["versions"]:
        return f"{product} {version}"
    return None


OPS = {f.__name__: f for f in (
    script_ran, any_script_ran, script_absent, script_contains, script_lacks, any_script_lacks,
    script_matches, data_exists, data_has_any_key, data_in, data_contains, data_equal,
    data_date_past, service_in, protocol_is, version_is,
)}


def evaluate(rules, info, scripts, protocol):
    # Returns the findings for one port, without its ip, port or names
    ctx = {"info": info, "scripts": scripts, "protocol": protocol}
    findings = []
    for rule in rules:
        results = [(OPS[cond["op"]](cond, ctx), cond) for cond in rule["when"]]
        if any(result is None for result, _ in results):
            continue
        # "silent" conditions only decide if the rule fires; they add nothing to the evidence
        evidence = [result for result, cond in results if not cond.get("silent")]
        findings.append({
            "rule": rule["id"],
            "severity": rule["severity"],
            "title": rule["title"],
            "evidence": "; ".join(item for item in evidence if item)[:200],
            "confidence": rule["confidence"],
            "remediation": rule["remediation"],
        })
    return findings
