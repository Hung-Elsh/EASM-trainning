# Runs the rules on a saved real scan, with no network. Run from week2/:
#   .venv/bin/python -m unittest discover tests
# The Java version can use the same two fixture files and should get the same findings.
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts" / "python"))
from rule_engine import evaluate, load_rules

FIXTURES = Path(__file__).resolve().parent / "fixtures"
IP = "192.168.1.250"


def run_sample():
    with open(FIXTURES / "nse_sample.json") as f:
        sample = json.load(f)
    rules = load_rules()
    fired = set()
    for port, info in sample["hosts"][IP]["tcp"].items():
        scripts = sample["nse"][IP]["tcp"].get(port, {})
        fired |= {(int(port), finding["rule"]) for finding in evaluate(rules, info, scripts, "tcp")}
    return fired


class RuleTests(unittest.TestCase):
    def test_sample_matches_expected_findings(self):
        with open(FIXTURES / "expected_findings.json") as f:
            expected = {(port, rule) for port, rule in json.load(f)}
        self.assertEqual(run_sample(), expected)

    def test_hardened_site_stays_quiet(self):
        self.assertEqual({rule for port, rule in run_sample() if port == 8443}, {"tls-cert-self-signed"})

    def test_failed_script_is_never_evidence(self):
        crashed = {"http-headers": {"output": "ERROR: Script execution failed", "data": None, "failed": True}}
        self.assertEqual(evaluate(load_rules(), {"name": "http"}, crashed, "tcp"), [])


if __name__ == "__main__":
    unittest.main()
