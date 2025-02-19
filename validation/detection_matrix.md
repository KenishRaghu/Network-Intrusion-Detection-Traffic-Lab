# Detection matrix (expected coverage)

This table is the **design contract**: when you replay the PCAPs through Suricata 7 with `lab-setup/suricata/suricata.yaml`, **Y** means “expect at least one alert for that SID,” and empty means “no expectation for that PCAP.”

Measured replay output (parsed from Suricata `eve.json`) is written to **`detection_matrix.measured.md`** when you run:

```bash
python3 validation/test_rules.py
```

The script asserts:

- For each attack PCAP, every SID marked **Y** below fired at least once (true-positive check).
- `baseline_clean.pcap` produced **no** alerts (false-positive check).

## SID × PCAP (expected contract)

| SID | Rule theme | baseline | port_scan | http_attacks | dns_attacks | mixed_attack |
| --- | --- | --- | --- | --- | --- | --- |
| 1000001 | SYN spike threshold | | Y | | | Y |
| 1000002 | SYN port scan threshold | | Y | | | Y |
| 1000003 | XMAS scan | | Y | | | Y |
| 1000004 | NULL scan | | Y | | | Y |
| 1000005 | FIN scan threshold | | Y | | | Y |
| 1000101 | SQLi UNION SELECT (URI) | | | Y | | Y |
| 1000102 | SQLi OR 1=1 (URI) | | | Y | | Y |
| 1000103 | SQLi quoted OR fragment | | | Y | | Y |
| 1000104 | SQLi UNION + comment | | | Y | | Y |
| 1000105 | XSS `<script` | | | Y | | Y |
| 1000106 | XSS `javascript:` | | | Y | | Y |
| 1000107 | XSS `onerror=` | | | Y | | Y |
| 1000108 | Traversal `../` | | | Y | | Y |
| 1000109 | Encoded traversal | | | Y | | Y |
| 1000110 | UA sqlmap | | | Y | | Y |
| 1000111 | UA Nikto | | | Y | | Y |
| 1000112 | UA gobuster | | | Y | | Y |
| 1000113 | 403 burst threshold | | | Y | | Y |
| 1000114 | SQLi POST body | | | Y | | Y |
| 1000201 | Long DNS name | | | | Y | Y |
| 1000202 | TXT burst threshold | | | | Y | Y |
| 1000203 | AXFR UDP pattern | | | | Y | Y |
| 1000204 | Placeholder malicious domain | | | | Y | Y |
| 1000205 | AXFR TCP payload pattern | | | | Y | Y |
| 1000301 | TLS cert expired | | | | | |
| 1000302 | Demo self-signed issuer string | | | | | |
| 1000303 | JA3 lab ClientHello | | | | | Y |
| 1000304 | JA3 illustrative (sqlmap-era) | | | | | |
| 1000305 | JA3 illustrative (Metasploit-era) | | | | | |
| 1000306 | TLS SNI placeholder | | | | | Y |
| 1000307 | JA3S illustrative | | | | | |

Rows **1000301**, **1000302**, **1000304**, **1000305**, and **1000307** are documented in `rules/tls_rules.rules` but are **not** exercised by the default synthetic PCAPs (no matching certificate chain or JA3/JA3S on the wire). Capture real TLS handshakes or swap in hashes from your PCAPs to light them up.

## Scenario checklist

| PCAP | Intent |
| --- | --- |
| `baseline_clean.pcap` | Benign DNS + HTTP only — expect **zero** alerts. |
| `port_scan.pcap` | Exercises `tcp_rules.rules` thresholds and flag combos. |
| `http_attacks.pcap` | Exercises `http_rules.rules` request/response logic. |
| `dns_attacks.pcap` | Exercises `dns_rules.rules` tunneling, AXFR, and IOC placeholder. |
| `mixed_attack.pcap` | Realistic interleave plus TLS ClientHello for **1000303** / **1000306**. |
