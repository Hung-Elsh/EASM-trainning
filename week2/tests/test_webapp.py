# Tests the web app on a tiny temp results file, no network. Run from week2/:
#   .venv/bin/python -m unittest discover tests
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "webapp"))
import app as webapp

IP = "10.0.0.1"


def finding(rule, severity, confidence, port, protocol="tcp"):
    return {"rule": rule, "severity": severity, "title": rule, "evidence": "", "confidence": confidence,
            "remediation": "", "ip": IP, "port": port, "protocol": protocol, "names": []}


SAMPLE = {
    "generated_at": "2026-01-01T00:00:00+00:00",
    "assets": [{"ip": IP, "names": [], "services": [
        {"port": 21, "protocol": "tcp", "state": "open", "name": "ftp", "product": "", "version": ""},
        {"port": 80, "protocol": "tcp", "state": "open", "name": "", "product": "", "version": ""},
        {"port": 81, "protocol": "tcp", "state": "closed", "name": "http", "product": "", "version": ""}]}],
    "findings": [
        finding("a", "low", "confirmed", 80),
        finding("b", "high", "confirmed", 21),
        finding("c", "medium", "version-only", 443),
    ],
}


class WebappTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "result.json")
        with open(self.path, "w") as f:
            json.dump(SAMPLE, f)
        os.environ["RESULTS_FILE"] = self.path
        self.client = webapp.app.test_client()

    def tearDown(self):
        del os.environ["RESULTS_FILE"]
        self.tmp.cleanup()

    def test_summary_counts(self):
        body = self.client.get("/api/summary").get_json()
        self.assertEqual((body["hosts"], body["services"], body["findings"]), (1, 2, 3))
        self.assertEqual(body["by_severity"], {"critical": 0, "high": 1, "medium": 1, "low": 1, "info": 0})
        self.assertEqual(body["by_confidence"], {"confirmed": 2, "likely": 0, "version-only": 1})
        names = [s["name"] for s in body["top_services"]]
        self.assertEqual(sorted(names), ["ftp", "unknown"])
        self.assertEqual(body["riskiest_ports"][0]["port"], 21)

    def test_findings_filter_and_invalid(self):
        body = self.client.get("/api/findings").get_json()
        self.assertEqual([f["rule"] for f in body["findings"]], ["b", "c", "a"])
        body = self.client.get("/api/findings?severity=low&port=80").get_json()
        self.assertEqual(body["count"], 1)
        for query in ["severity=bad", "confidence=bad", "protocol=icmp", "port=abc"]:
            response = self.client.get("/api/findings?" + query)
            self.assertEqual(response.status_code, 400)
            self.assertIn("error", response.get_json())

    def test_score_halves_version_only(self):
        body = self.client.get("/api/score").get_json()
        # high 10 + low 1 + medium 4 halved to 2 = 13
        self.assertEqual(body["penalty"], 13)
        self.assertEqual(body["score"], 87)
        self.assertEqual(body["hosts"][0]["findings"], 3)

    def test_missing_file_gives_503(self):
        os.environ["RESULTS_FILE"] = os.path.join(self.tmp.name, "nope.json")
        response = self.client.get("/api/summary")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.get_json(),
                         {"error": "No pipeline results yet: run the pipeline first"})


if __name__ == "__main__":
    unittest.main()
