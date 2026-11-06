# Read-only Flask app that serves the pipeline results. Run from week2/:
#   .venv/bin/python webapp/app.py
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request

sys.path.insert(0, str(Path(__file__).resolve().parent))
import results

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

app = Flask(__name__)
# Not used yet (no sessions), so only set it when given. Never printed.
if os.environ.get("FLASK_SECRET_KEY"):
    app.secret_key = os.environ["FLASK_SECRET_KEY"]


def error(message, status):
    return jsonify({"error": message}), status


@app.errorhandler(results.NoResultsError)
def no_results(exc):
    return error("No pipeline results yet: run the pipeline first", 503)


@app.get("/")
def dashboard():
    return render_template("dashboard.html")


@app.get("/api/summary")
def api_summary():
    return jsonify(results.summary(results.load_results()))


@app.get("/api/assets")
def api_assets():
    data = results.load_results()
    return jsonify({"generated_at": data.get("generated_at"),
                    "assets": results.get_assets(data)})


@app.get("/api/findings")
def api_findings():
    data = results.load_results()
    severity = request.args.get("severity")
    confidence = request.args.get("confidence")
    protocol = request.args.get("protocol")
    port_text = request.args.get("port")

    if severity is not None and severity not in results.SEVERITIES:
        return error("Invalid severity", 400)
    if confidence is not None and confidence not in results.CONFIDENCES:
        return error("Invalid confidence", 400)
    if protocol is not None and protocol not in ("tcp", "udp"):
        return error("Invalid protocol", 400)
    port = None
    if port_text is not None:
        try:
            port = int(port_text)
        except ValueError:
            return error("Invalid port: must be an integer", 400)

    found = results.filter_findings(results.get_findings(data), severity, confidence, protocol, port)
    found = results.sort_findings(found)
    return jsonify({"count": len(found), "findings": found})


@app.get("/api/score")
def api_score():
    return jsonify(results.score(results.load_results()))


if __name__ == "__main__":
    host = os.environ.get("WEBAPP_HOST") or "127.0.0.1"
    port = int(os.environ.get("WEBAPP_PORT") or 5000)
    app.run(host=host, port=port, debug=False)
