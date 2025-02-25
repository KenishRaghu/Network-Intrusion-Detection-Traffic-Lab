# PCAP analysis — `mixed_attack.pcap`

This walk-through mirrors what I would present in a technical interview: start from the **mixed** capture (attacks plus benign traffic), isolate each abuse class with **Wireshark display filters**, then compare what I can prove manually versus what the **Suricata rules** assert automatically.

Regenerate the file with `pcaps/generate_all.sh` if you need to follow along on your laptop.

## Baseline isolation

| Goal | Display filter (examples) | What stands out |
| --- | --- | --- |
| DNS only | `dns` | A handful of A/AAAA questions to benign names (`www.wikipedia.org`, `one.one.one.one`) and the long synthetic tunnel name used for SID **1000201**. |
| HTTP only | `http` | Multiple small TCP streams on **8080** with `GET` and `POST` methods; response codes mix **200** and **403** bursts. |
| TLS only | `tcp.port == 443 && tls.handshake.type == 1` | A single **ClientHello** on loopback with SNI `malware-c2.placeholder.invalid` (SID **1000306**). |

## TCP reconnaissance

| Attack flavor | Filter ideas | Packet-level story |
| --- | --- | --- |
| SYN spike / scan | `tcp.flags.syn == 1 && tcp.flags.ack == 0` | A train of SYNs from **127.0.0.1** toward many destination ports or repeated attempts — no completed handshakes for the scan portion. |
| XMAS | `tcp.flags.fin == 1 && tcp.flags.push == 1 && tcp.flags.urg == 1` | Rare flag triplet that legitimate stacks almost never originate toward random services. |
| NULL | `tcp.flags == 0x000` | Zero flags set while still addressed to service ports — classic fingerprint probe. |
| FIN scan | `tcp.flags.fin == 1 && tcp.flags.syn == 0 && tcp.flags.ack == 0` | Bare FINs toward many ports, distinct from graceful shutdown inside established flows when you follow stream indexes. |

**IDS comparison:** Wireshark proves the odd flags and timing; **SIDs 1000001–1000005** automate that story with thresholds so I do not have to count packets by hand during an incident.

## HTTP abuse

| Theme | Filter / technique | Visible details |
| --- | --- | --- |
| SQLi / XSS / traversal | `http.request.uri contains "union"` (and similar substrings) | Query strings carry `union`, `select`, `javascript:`, `onerror=`, `../`, and `%2f` encodings — each lines up with a dedicated SID in `http_rules.rules`. |
| Tooling User-Agent | `http.user_agent contains "sqlmap" \|\| http.user_agent contains "Nikto" \|\| http.user_agent contains "gobuster"` | Clear automation breadcrumbs (trivial to spoof, but valuable for internal drill attribution). |
| 403 storm | `http.response.code == 403` | Many small transactions where the server returns **403** to the same client IP — the visual pattern is a vertical stack of red lines in the HTTP conversation list. |

**IDS comparison:** Manual analysis catches the **semantics** (“this query is ugly”). The IDS rules operationalize **repeatability** — especially the 403 threshold (**1000113**) which is painful to eyeball at scale.

## DNS abuse

| Theme | Filter | Visible details |
| --- | --- | --- |
| Long QNAME | `dns.qry.name` column or `dns.len > 90` style analysis | Extremely long dotted names built from repeated labels — typical of tunneling experiments. |
| TXT volume | `dns.qry.type == 16` | Bursts of TXT queries sharing the `.txt-exfil.lab.invalid` suffix. |
| AXFR | `dns.qry.type == 252` or read the opcode/type columns | Zone-transfer questions aimed at `x.lab` in the simulator; also duplicated inside DNS-over-TCP segments for SID **1000205**. |
| Placeholder IOC | `dns.qry.name contains "malware_dropper"` | Demonstrates how a static domain IOC would look on the wire. |

**IDS comparison:** Wireshark shows the encoding; **dns.query**-anchored rules and the UDP/TCP content fallback for AXFR make the detections robust even when a resolver refuses to answer.

## TLS (cleartext handshake only)

| Check | Filter | Visible details |
| --- | --- | --- |
| SNI | `tls.handshake.extensions_server_name` | Cleartext hostname matching the malicious placeholder. |
| JA3 | Export JA3 from Wireshark’s expert details or compare to `eve.json` | Fingerprint should match **4e6327d6b4b699766c1250b3356cfde4** for the lab ClientHello. |

**IDS comparison:** Wireshark is perfect for one-off inspection; **ja3.hash** and **tls.sni** rules scale that logic to every flow.

## Screenshots as text

In a slide deck I would include:

1. **Statistics → Conversations → TCP**, sorted by packet count, highlighting the short 403-heavy HTTP streams.
2. **Follow → TCP Stream** on a single SQLi `GET`, showing the percent-encoded parameters after URL decoding in the “Export Objects” or HTTP dissector view.
3. **DNS** tree expanded for the AXFR question, with type **252** visible.

## Manual vs automated takeaway

Wireshark answers “**show me the bytes**.” Suricata answers “**tell me every time this pattern crosses the sensor under these thresholds**.” This lab keeps both: the PCAPs justify the signatures, and `validation/test_rules.py` proves the signatures actually fire on replay (see `validation/detection_matrix.md` for the expectation table and `validation/detection_matrix.measured.md` after a successful run).
