#!/usr/bin/env python3
"""
DNS-layer simulations aligned with rules/dns_rules.rules.

SIDs:
  1000201 — very long QNAME (tunneling-style)
  1000202 — burst of queries under *.txt-exfil.lab.invalid (threshold)
  1000203 — AXFR pattern on UDP/53 (wire bytes for x.lab)
  1000204 — malware_dropper.placeholder.invalid
  1000205 — same AXFR bytes carried over TCP/53 (content match)

Live mode sends crafted UDP DNS to 127.0.0.1:53 (may ICMP refuse); PCAP
generation is the supported path.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scapy.all import send  # noqa: E402

from attacks.pcaplib import build_dns_tcp_query, build_dns_udp_query, stamp_times  # noqa: E402


def _long_tunnel_qname() -> str:
    # Valid labels (<=63 octets each), total dotted name > 96 chars for SID 1000201.
    chunks = [f"{i:02d}" + "b" * 58 for i in range(3)]
    return ".".join(chunks) + ".tunnel.lab.invalid"


def build_dns_attack_packets() -> List:
    pkts: List = []
    sport = 60_000

    # 1000201
    pkts.extend(
        build_dns_udp_query(_long_tunnel_qname(), sport=sport, dport=53)
    )
    sport += 1

    # 1000202 — 30 queries (threshold 28 in 6s on same src)
    for i in range(30):
        name = f"chunk{i:04d}.txt-exfil.lab.invalid"
        pkts.extend(build_dns_udp_query(name, qtype="TXT", sport=sport, dport=53))
        sport += 1

    # 1000203 — AXFR on UDP
    pkts.extend(
        build_dns_udp_query("x.lab", qtype="AXFR", sport=sport, dport=53)
    )
    sport += 1

    # 1000204
    pkts.extend(
        build_dns_udp_query(
            "malware_dropper.placeholder.invalid", sport=sport, dport=53
        )
    )
    sport += 1

    # 1000205 — TCP framing (single segment with length prefix + DNS payload)
    pkts.extend(build_dns_tcp_query("x.lab", qtype="AXFR", sport=sport, dport=53))

    return stamp_times(pkts, start=10.0, step=0.00005)


def run_live() -> None:
    for p in build_dns_attack_packets():
        try:
            send(p, verbose=0)
        except Exception as exc:  # noqa: BLE001
            print("send failed (expected without root/socket):", exc)
            break


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", action="store_true")
    args = ap.parse_args()
    if args.live:
        run_live()
    else:
        print("Dry run: use generate_attack_pcaps.py for pcaps/ output.")


if __name__ == "__main__":
    main()
