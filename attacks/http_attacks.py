#!/usr/bin/env python3
"""
HTTP-layer attack strings aligned with rules/http_rules.rules.

SIDs: 1000101–1000114 (see rules/http_rules.rules header comments).

Live mode uses `requests` against a local Flask target (docker compose publishes 8080).
"""
from __future__ import annotations

import argparse
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import List
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import requests  # noqa: E402

from attacks.pcaplib import build_tcp_http_exchange, stamp_times  # noqa: E402


def _target_url() -> str:
    return os.environ.get("IDS_LAB_HTTP_TARGET", "http://127.0.0.1:8080").rstrip("/")


def build_http_attack_packets() -> List:
    """Synthetic PCAP payloads (loopback) for Suricata HTTP parser."""
    pkts: List = []
    sport = 32000

    def add(req: str, resp: bytes = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"):
        nonlocal sport
        pkts.extend(
            build_tcp_http_exchange(
                sport=sport,
                dport=8080,
                request=req,
                response=resp,
                client_isn=1_000_000 + sport,
                server_isn=2_000_000 + sport,
            )
        )
        sport += 1

    # 1000101
    add(
        "GET /search?q=union+select+null+from+users HTTP/1.1\r\n"
        "Host: 127.0.0.1:8080\r\n"
        "Accept: */*\r\n"
    )
    # 1000102 (normalized URI should contain the literal `or 1=1`)
    add(
        "GET /item?id=1%20or%201%3D1 HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nAccept: */*\r\n"
    )
    # 1000103 (percent-encoded so the HTTP line stays valid on the wire)
    add(
        "GET /login?user=x%27%2Bor%2B%271%27%3D%271 HTTP/1.1\r\n"
        "Host: 127.0.0.1:8080\r\nAccept: */*\r\n"
    )
    # 1000104 (UNION near --)
    add(
        "GET /vuln?q=union+select+password+from+admins-- HTTP/1.1\r\n"
        "Host: 127.0.0.1:8080\r\nAccept: */*\r\n"
    )
    # 1000105
    add(
        "GET /reflect?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1\r\n"
        "Host: 127.0.0.1:8080\r\nAccept: */*\r\n"
    )
    # 1000106
    add(
        "GET /go?next=javascript:alert(1) HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nAccept: */*\r\n"
    )
    # 1000107
    add(
        "GET /p?x=%3Cimg+src%3dx+onerror%3dalert(1)%3E HTTP/1.1\r\n"
        "Host: 127.0.0.1:8080\r\nAccept: */*\r\n"
    )
    # 1000108
    add(
        "GET /static?f=../../etc/passwd HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nAccept: */*\r\n"
    )
    # 1000109
    add(
        "GET /dl?p=..%2f..%2f..%2fetc%2fpasswd HTTP/1.1\r\n"
        "Host: 127.0.0.1:8080\r\nAccept: */*\r\n"
    )
    # 1000110
    add(
        "GET / HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n"
        "User-Agent: sqlmap/1.8.8#stable (http://sqlmap.org)\r\nAccept: */*\r\n"
    )
    # 1000111
    add(
        "GET / HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n"
        "User-Agent: Mozilla/5.00 (Nikto/2.1.6) (Evil.com)\r\nAccept: */*\r\n"
    )
    # 1000112
    add(
        "GET / HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n"
        "User-Agent: gobuster/3.6\r\nAccept: */*\r\n"
    )
    # 1000114 POST body union select
    body = "username=admin&payload=union+select+password+from+users--+"
    add(
        f"POST /login HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n\r\n{body}"
    )

    # 1000113 — many HTTP 403 responses to the same client
    forbidden = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 9\r\n\r\nForbidden"
    for i in range(28):
        add(
            f"GET /brute-{i} HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nAccept: */*\r\n",
            resp=forbidden,
        )

    return stamp_times(pkts, start=1.0, step=0.0001)


def run_live_http() -> None:
    base = _target_url()
    sess = requests.Session()
    paths = [
        "/search?q=union+select+null",
        "/item?id=1+or+1=1",
        "/login?user=" + quote("x' OR '1'='1"),
        "/vuln?q=union+select+1--",
        "/reflect?q=<script>alert(1)</script>",
        "/go?next=javascript:alert(1)",
        "/p?x=" + quote("<img src=x onerror=alert(1)>"),
        "/static?f=../../etc/passwd",
        "/dl?p=" + quote("..%2f..%2fetc%2fpasswd"),
    ]
    for p in paths:
        sess.get(base + p, timeout=5)
    sess.get(
        base + "/",
        headers={"User-Agent": "sqlmap/1.8.8#stable (http://sqlmap.org)"},
        timeout=5,
    )
    sess.get(
        base + "/",
        headers={"User-Agent": "Mozilla/5.00 (Nikto/2.1.6) (Evil.com)"},
        timeout=5,
    )
    sess.get(base + "/", headers={"User-Agent": "gobuster/3.6"}, timeout=5)
    sess.post(
        base + "/login",
        data={"username": "admin", "payload": "union select password from users--"},
        timeout=5,
    )


def _serve_403_burst() -> None:
    class _ForbiddenHandler(BaseHTTPRequestHandler):
        def log_message(self, *args):  # noqa: D401
            return

        def do_GET(self):  # noqa: N802
            self.send_response(403)
            self.send_header("Content-Length", "0")
            self.end_headers()

    srv = HTTPServer(("127.0.0.1", 18080), _ForbiddenHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.3)
    for i in range(30):
        try:
            requests.get(f"http://127.0.0.1:18080/try-{i}", timeout=2)
        except requests.RequestException:
            pass
    srv.shutdown()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", action="store_true")
    args = ap.parse_args()
    if args.live:
        run_live_http()
        _serve_403_burst()
    else:
        print("Dry run: use generate_attack_pcaps.py or --live with target up.")


if __name__ == "__main__":
    main()
