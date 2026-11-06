# Legacy lab API: no authentication, wildcard CORS, leaky endpoints. All data is fake.
from flask import Flask, jsonify

app = Flask(__name__)

USERS = [
    {"id": 1, "username": "admin", "email": "admin@seclab.test", "role": "admin"},
    {"id": 2, "username": "hr.manager", "email": "hr@seclab.test", "role": "hr"},
]


@app.after_request
def add_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["X-Powered-By"] = "SecLab-API/0.9-beta"
    return response


@app.route("/")
def index():
    return jsonify(service="seclab-legacy-api", version="0.9-beta",
                   endpoints=["/api/v1/users", "/api/v1/config", "/health"])


@app.route("/health")
def health():
    return jsonify(status="ok")


@app.route("/api/v1/users")
def users():
    return jsonify(USERS)


@app.route("/api/v1/config")
def config():
    # leaks internal settings, a classic API exposure
    return jsonify(db_host="redis.seclab.internal", db_password="changeme",
                   search_url="http://192.168.1.250:9200", debug=True)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
