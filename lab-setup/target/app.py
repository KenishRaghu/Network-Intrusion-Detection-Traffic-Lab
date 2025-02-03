"""
Minimal target web service for IDS lab traffic.
Accepts GET/POST on any path so attack scripts have something to hit.
"""
from flask import Flask, request

app = Flask(__name__)


@app.route("/healthz", methods=["GET"])
def healthz():
    return {"status": "healthy"}, 200


@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "HEAD"])
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "HEAD"])
def catch_all(path):
    # Echo a tiny JSON-style body hint for POST (useful when debugging captures)
    if request.method == "POST" and request.data:
        return (
            {"status": "ok", "bytes": len(request.data)},
            200,
            {"Content-Type": "application/json"},
        )
    return {"status": "ok", "path": "/" + path}, 200, {"Content-Type": "application/json"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80, threaded=True)
