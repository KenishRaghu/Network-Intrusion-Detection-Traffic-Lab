"""
Build a minimal, deterministic TLS 1.2 ClientHello (SNI + fixed cipher/ext order)
so Suricata's JA3 hash matches the Salesforce JA3 reference implementation.

SID map: 1000303 (ja3.hash), 1000306 (tls.sni) — see rules/tls_rules.rules.

JA3 string for this hello (reference): 771,47,0-11-10-13-23-65281,23,0
MD5: 4e6327d6b4b699766c1250b3356cfde4
"""
from __future__ import annotations

import struct
from hashlib import md5
from typing import List

import dpkt

# SNI hostname must match tls_rules.rules (SID 1000306).
LAB_TLS_SNI = b"malware-c2.placeholder.invalid"


def _u16_be(x: int) -> bytes:
    return struct.pack("!H", x)


def _ext_server_name(host: bytes) -> bytes:
    inner = b"\x00" + _u16_be(len(host)) + host
    return _u16_be(0) + _u16_be(len(inner)) + inner


def _ext_ec_point_formats() -> bytes:
    body = b"\x01\x00"
    return _u16_be(11) + _u16_be(len(body)) + body


def _ext_supported_groups() -> bytes:
    body = b"\x00\x02" + _u16_be(0x0017)
    return _u16_be(10) + _u16_be(len(body)) + body


def _ext_signature_algorithms() -> bytes:
    algs = b"\x04\x01\x04\x03"
    body = _u16_be(len(algs)) + algs
    return _u16_be(13) + _u16_be(len(body)) + body


def _ext_extended_master_secret() -> bytes:
    return _u16_be(23) + _u16_be(0)


def _ext_renegotiation_info() -> bytes:
    body = b"\x00"
    return _u16_be(0xFF01) + _u16_be(len(body)) + body


def build_lab_client_hello() -> bytes:
    """TLS record bytes: one handshake record containing ClientHello."""
    version = b"\x03\x03"
    random = b"\x42" * 32
    session_id = b"\x00"
    ciphers = _u16_be(2) + _u16_be(0x002F)
    compression = b"\x01\x00"
    extensions: List[bytes] = [
        _ext_server_name(LAB_TLS_SNI),
        _ext_ec_point_formats(),
        _ext_supported_groups(),
        _ext_signature_algorithms(),
        _ext_extended_master_secret(),
        _ext_renegotiation_info(),
    ]
    ext_block = b"".join(extensions)
    extensions_field = _u16_be(len(ext_block)) + ext_block
    body = version + random + session_id + ciphers + compression + extensions_field
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16" + b"\x03\x01" + _u16_be(len(handshake)) + handshake


def _parse_variable_array(buf: bytes, byte_len: int) -> tuple[bytes, int]:
    _SIZE_FORMATS = ["!B", "!H", "!I", "!I"]
    size_format = _SIZE_FORMATS[byte_len - 1]
    padding = b"\x00" if byte_len == 3 else b""
    size = struct.unpack(size_format, padding + buf[:byte_len])[0]
    data = buf[byte_len : byte_len + size]
    return data, size + byte_len


def _convert_to_ja3_segment(data: bytes, element_width: int) -> str:
    ints: List[int] = []
    if element_width == 1:
        fmt = "!B"
    elif element_width == 2:
        fmt = "!H"
    else:
        fmt = "!I"
    step = element_width
    for i in range(0, len(data), step):
        ints.append(struct.unpack(fmt, data[i : i + step])[0])
    return "-".join(str(x) for x in ints)


def _grease(val: int) -> bool:
    return val in {
        0x0A0A,
        0x1A1A,
        0x2A2A,
        0x3A3A,
        0x4A4A,
        0x5A5A,
        0x6A6A,
        0x7A7A,
        0x8A8A,
        0x9A9A,
        0xAAAA,
        0xBABA,
        0xCACA,
        0xDADA,
        0xEAEA,
        0xFAFA,
    }


def _process_extensions(client_handshake: dpkt.ssl.TLSClientHello) -> list[str]:
    if not hasattr(client_handshake, "extensions"):
        return ["", "", ""]
    exts: List[int] = []
    elliptic_curve = ""
    elliptic_curve_point_format = ""
    for ext_val, ext_data in client_handshake.extensions:
        if not _grease(ext_val):
            exts.append(ext_val)
        if ext_val == 0x0A:
            a, _ = _parse_variable_array(ext_data, 2)
            elliptic_curve = _convert_to_ja3_segment(a, 2)
        elif ext_val == 0x0B:
            a, _ = _parse_variable_array(ext_data, 1)
            elliptic_curve_point_format = _convert_to_ja3_segment(a, 1)
    return ["-".join(str(x) for x in exts), elliptic_curve, elliptic_curve_point_format]


def lab_ja3_string_and_md5() -> tuple[str, str]:
    """Return (ja3_string, md5_hex) matching Suricata/Salesforce JA3 for this hello."""
    ch = build_lab_client_hello()
    records, _ = dpkt.ssl.tls_multi_factory(ch)
    if not records:
        raise ValueError("Could not parse TLS records from lab ClientHello")
    record = records[0]
    hs = dpkt.ssl.TLSHandshake(record.data)
    if not isinstance(hs.data, dpkt.ssl.TLSClientHello):
        raise ValueError("Expected ClientHello")
    cl = hs.data
    buf, ptr = _parse_variable_array(cl.data, 1)
    buf, _ = _parse_variable_array(cl.data[ptr:], 2)
    parts = [str(cl.version), _convert_to_ja3_segment(buf, 2)] + _process_extensions(cl)
    ja3s = ",".join(parts)
    return ja3s, md5(ja3s.encode()).hexdigest()
