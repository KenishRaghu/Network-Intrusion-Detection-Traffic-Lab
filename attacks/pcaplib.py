"""
Small Scapy helpers to synthesize loopback PCAPs with valid TCP handshakes so
Suricata's stream engine can parse HTTP and TLS records.

These builders intentionally avoid live sockets so PCAP generation works in CI.
"""
from __future__ import annotations

from typing import Iterable, List, Optional

import struct

from scapy.all import IP, Raw, TCP, UDP, raw
from scapy.layers.dns import DNS, DNSQR


def _ip_tcp_base(src: str, dst: str, sport: int, dport: int) -> type:
    return IP(src=src, dst=dst) / TCP(sport=sport, dport=dport)


def build_tcp_http_exchange(
    *,
    sport: int,
    dport: int,
    request: str,
    response: bytes = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK",
    src: str = "127.0.0.1",
    dst: str = "127.0.0.1",
    client_isn: int = 1_000_000,
    server_isn: int = 2_000_000,
) -> List:
    """Minimal 3WHS + client request + server response + ACKs."""
    pkts = []
    c_isn = client_isn
    s_isn = server_isn
    syn = IP(src=src, dst=dst) / TCP(
        sport=sport, dport=dport, flags="S", seq=c_isn, window=65535
    )
    synack = IP(src=dst, dst=src) / TCP(
        sport=dport,
        dport=sport,
        flags="SA",
        seq=s_isn,
        ack=c_isn + 1,
        window=65535,
    )
    ack = IP(src=src, dst=dst) / TCP(
        sport=sport,
        dport=dport,
        flags="A",
        seq=c_isn + 1,
        ack=s_isn + 1,
        window=65535,
    )
    pkts.extend([syn, synack, ack])
    req_b = request.encode() if isinstance(request, str) else request
    psh = IP(src=src, dst=dst) / TCP(
        sport=sport,
        dport=dport,
        flags="PA",
        seq=c_isn + 1,
        ack=s_isn + 1,
        window=65535,
    ) / Raw(load=req_b)
    ack2 = IP(src=dst, dst=src) / TCP(
        sport=dport,
        dport=sport,
        flags="A",
        seq=s_isn + 1,
        ack=c_isn + 1 + len(req_b),
        window=65535,
    )
    pkts.extend([psh, ack2])
    rsp = IP(src=dst, dst=src) / TCP(
        sport=dport,
        dport=sport,
        flags="PA",
        seq=s_isn + 1,
        ack=c_isn + 1 + len(req_b),
        window=65535,
    ) / Raw(load=response)
    ack3 = IP(src=src, dst=dst) / TCP(
        sport=sport,
        dport=dport,
        flags="A",
        seq=c_isn + 1 + len(req_b),
        ack=s_isn + 1 + len(response),
        window=65535,
    )
    pkts.extend([rsp, ack3])
    return pkts


def build_tcp_tls_client_hello(
    *,
    sport: int,
    dport: int = 443,
    tls_record: bytes,
    src: str = "127.0.0.1",
    dst: str = "127.0.0.1",
    client_isn: int = 5_000_000,
    server_isn: int = 6_000_000,
) -> List:
    """3WHS + single PSH carrying raw TLS record (e.g. ClientHello)."""
    pkts: List = []
    c, s = client_isn, server_isn
    pkts.append(
        IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S", seq=c)
    )
    pkts.append(
        IP(src=dst, dst=src)
        / TCP(sport=dport, dport=sport, flags="SA", seq=s, ack=c + 1)
    )
    pkts.append(
        IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, flags="A", seq=c + 1, ack=s + 1)
    )
    psh = (
        IP(src=src, dst=dst)
        / TCP(
            sport=sport,
            dport=dport,
            flags="PA",
            seq=c + 1,
            ack=s + 1,
        )
        / Raw(load=tls_record)
    )
    pkts.append(psh)
    pkts.append(
        IP(src=dst, dst=src)
        / TCP(
            sport=dport,
            dport=sport,
            flags="A",
            seq=s + 1,
            ack=c + 1 + len(tls_record),
        )
    )
    return pkts


def build_dns_udp_query(
    qname: str,
    qtype: str | int = "A",
    *,
    sport: int = 53_000,
    dport: int = 53,
    src: str = "127.0.0.1",
    dst: str = "127.0.0.1",
) -> List:
    """Single DNS query over UDP (no response required for these IDS rules)."""
    pkt = (
        IP(src=src, dst=dst)
        / UDP(sport=sport, dport=dport)
        / DNS(rd=1, qd=DNSQR(qname=qname, qtype=qtype))
    )
    return [pkt]


def build_dns_tcp_query(
    qname: str,
    qtype: str | int = "A",
    *,
    sport: int = 53_100,
    dport: int = 53,
    src: str = "127.0.0.1",
    dst: str = "127.0.0.1",
) -> List:
    """DNS over TCP with 2-byte RFC 1035 length prefix (for SID 1000205)."""
    dns = DNS(rd=1, qd=DNSQR(qname=qname, qtype=qtype))
    b = raw(dns)
    framed = struct.pack("!H", len(b)) + b
    pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="PA", seq=1, ack=1) / Raw(
        load=framed
    )
    return [pkt]


def stamp_times(packets: Iterable, start: float = 0.0, step: float = 0.0001) -> List:
    """Assign monotonic pkt.time for deterministic merge ordering."""
    out = []
    t = start
    for p in packets:
        p.time = t
        t += step
        out.append(p)
    return out
