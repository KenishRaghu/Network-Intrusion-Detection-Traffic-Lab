#!/usr/bin/env python3
"""
TCP reconnaissance traffic aligned with rules/tcp_rules.rules.

SID mapping (see comment blocks in rules):
  1000001 — SYN spike (threshold by_src)
  1000002 — many distinct destination ports with SYN
  1000003 — XMAS (FIN+PSH+URG)
  1000004 — NULL (no flags)
  1000005 — FIN probes to many ports

Run live (requires root on some platforms for raw sockets):
  sudo python3 attacks/port_scan.py --live --target 127.0.0.1
"""
from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path
from typing import List

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scapy.all import IP, TCP, send  # noqa: E402

from attacks.pcaplib import stamp_times  # noqa: E402


def _base(dst: str, dport: int, sport: int, flags: str | int, seq: int | None = None) -> object:
    fl = flags
    if seq is None:
        seq = random.randint(1, 2**31 - 1)
    return IP(dst=dst) / TCP(
        dport=dport,
        sport=sport,
        flags=fl,
        seq=seq,
        window=2048,
    )


def build_port_scan_pcap_packets(target: str = "127.0.0.1") -> List:
    """Return ordered Scapy packets for offline replay."""
    pkts: List = []
    step = 0.00005

    # 1000001: >=80 SYN in <=3s from one source (use 85)
    sport = 45000
    for i in range(85):
        pkts.append(_base(target, 80, sport + (i % 5), "S"))

    # 1000002: >=18 distinct dports with SYN in <=4s
    for dp in range(3000, 3000 + 20):
        pkts.append(_base(target, dp, 46000 + dp, "S"))

    # 1000003: XMAS to a few ports
    for dp in (22, 80, 443):
        pkts.append(_base(target, dp, 47000 + dp, "FPU"))

    # 1000004: NULL scan
    for dp in (111, 135, 445):
        pkts.append(_base(target, dp, 48000 + dp, 0))

    # 1000005: >=14 FIN to distinct dports in <=4s
    for dp in range(5000, 5000 + 16):
        pkts.append(_base(target, dp, 49000 + dp, "F"))

    return stamp_times(pkts, start=0.0, step=step)


def run_live(target: str) -> None:
    for p in build_port_scan_pcap_packets(target):
        send(p, verbose=0)


def main() -> None:
    ap = argparse.ArgumentParser(description="TCP scan simulator for IDS lab")
    ap.add_argument("--live", action="store_true", help="Send packets (needs raw socket access)")
    ap.add_argument("--target", default="127.0.0.1", help="Destination IP")
    args = ap.parse_args()
    if args.live:
        run_live(args.target)
    else:
        print("Dry run: use generate_attack_pcaps.py to write pcaps/, or pass --live to transmit.")


if __name__ == "__main__":
    main()
