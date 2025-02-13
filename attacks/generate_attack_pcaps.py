#!/usr/bin/env python3
"""
Generate all lab PCAPs under pcaps/ using Scapy (no live capture privileges).

Maps to validation/test_rules.py expected SID sets (see comments per section).

Attack script → rule SID traceability:
  port_scan.pcap      → port_scan.build_port_scan_pcap_packets  → tcp_rules 1000001–1000005
  http_attacks.pcap   → http_attacks.build_http_attack_packets   → http_rules 1000101–1000114
  dns_attacks.pcap    → dns_attacks.build_dns_attack_packets     → dns_rules 1000201–1000205
  mixed_attack.pcap   → merges baseline + tcp/http/dns + TLS hello → includes tls_rules 1000303, 1000306
  baseline_clean.pcap → benign DNS + HTTP only                   → (expect no alerts)
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scapy.all import wrpcap  # noqa: E402

from attacks.dns_attacks import build_dns_attack_packets  # noqa: E402
from attacks.http_attacks import build_http_attack_packets  # noqa: E402
from attacks.pcaplib import (  # noqa: E402
    build_dns_udp_query,
    build_tcp_http_exchange,
    build_tcp_tls_client_hello,
    stamp_times,
)
from attacks.port_scan import build_port_scan_pcap_packets  # noqa: E402
from attacks.tls_lab_clienthello import build_lab_client_hello  # noqa: E402


def _merge_time_ordered(chunks: list, step: float = 0.00001) -> list:
    out = []
    t = 0.0
    for chunk in chunks:
        for p in chunk:
            p.time = t
            t += step
            out.append(p)
    return out


def build_baseline_packets() -> list:
    """Benign DNS + HTTP only (no TLS) to exercise false-positive posture."""
    pkts = []
    pkts.extend(
        build_dns_udp_query("www.wikipedia.org", sport=40000, dport=53)
    )
    pkts.extend(
        build_dns_udp_query("one.one.one.one", qtype="AAAA", sport=40001, dport=53)
    )
    pkts.extend(
        build_tcp_http_exchange(
            sport=21000,
            dport=8080,
            request=(
                "GET / HTTP/1.1\r\n"
                "Host: 127.0.0.1:8080\r\n"
                "User-Agent: Mozilla/5.0 IDS-Lab-Baseline/1.0\r\n"
                "Accept: text/html\r\n"
            ),
            client_isn=8_000_000,
            server_isn=8_100_000,
        )
    )
    return stamp_times(pkts, start=0.0, step=0.0001)


def build_tls_lab_packets() -> list:
    """Single ClientHello on TCP/443 for JA3 + SNI rules."""
    tls = build_lab_client_hello()
    return stamp_times(
        build_tcp_tls_client_hello(
            sport=51111,
            dport=443,
            tls_record=tls,
            client_isn=9_000_000,
            server_isn=9_100_000,
        ),
        start=50.0,
        step=0.0001,
    )


def main() -> None:
    out_dir = ROOT / "pcaps"
    out_dir.mkdir(parents=True, exist_ok=True)

    baseline = build_baseline_packets()
    port_pkts = build_port_scan_pcap_packets()
    http_pkts = build_http_attack_packets()
    dns_pkts = build_dns_attack_packets()
    tls_pkts = build_tls_lab_packets()

    wrpcap(str(out_dir / "baseline_clean.pcap"), baseline)
    wrpcap(str(out_dir / "port_scan.pcap"), port_pkts)
    wrpcap(str(out_dir / "http_attacks.pcap"), http_pkts)
    wrpcap(str(out_dir / "dns_attacks.pcap"), dns_pkts)

    mixed = _merge_time_ordered(
        [baseline, port_pkts, http_pkts, dns_pkts, tls_pkts],
        step=0.000005,
    )
    wrpcap(str(out_dir / "mixed_attack.pcap"), mixed)

    print("Wrote PCAPs to", out_dir)
    print(
        "  baseline_clean.pcap, port_scan.pcap, http_attacks.pcap, "
        "dns_attacks.pcap, mixed_attack.pcap"
    )


if __name__ == "__main__":
    main()
