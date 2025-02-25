# Network Intrusion Detection & Traffic Lab

Hands-on portfolio work focused on **writing, testing, tuning, and proving** IDS detection logic. Every signature in `rules/` is **hand-authored** for this project — not downloaded from Proofpoint ET, Snort Community Rules, or PulledPork-style bundles. Suricata is the primary engine because it containerizes cleanly; Snort is supported via a minimal `lab-setup/snort/snort.conf` and manual runbook for apples-to-apples comparisons.

## What this demonstrates

1. **Custom detection** across TCP, HTTP, DNS, and TLS metadata (JA3, SNI, certificate keywords).
2. **Attack simulation** with Scapy and Python that maps **one-to-one** to rule SIDs (traceability for interviews).
3. **PCAP replay validation** — the same workflow as production tuning: generate traffic → capture or synthesize PCAPs → `suricata -r` → inspect EVE JSON.
4. **Accuracy story** — `validation/test_rules.py` checks **true positives** (expected SIDs fire on attack PCAPs) and **false positives** (baseline PCAP stays silent).

Pipeline in one line:

> **write rules → simulate attacks → replay PCAPs → validate alerts → tune → document**

## Repository map

| Path | Role |
| --- | --- |
| `lab-setup/` | Docker Compose (Suricata + Flask target), Suricata YAML, Snort reference config |
| `rules/` | `tcp_rules.rules`, `http_rules.rules`, `dns_rules.rules`, `tls_rules.rules` |
| `attacks/` | Scapy/`requests` generators + `generate_attack_pcaps.py` |
| `pcaps/` | Synthetic captures (`baseline_clean`, attack sets, `mixed_attack`) |
| `validation/` | `test_rules.py`, `detection_matrix.md` (expectations), `tuning_notes.md` |
| `analysis/` | Wireshark-oriented narrative for the mixed PCAP |
| `docs/` | Rule syntax primer + deployment playbook |

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
chmod +x pcaps/generate_all.sh
./pcaps/generate_all.sh
```

Bring up the optional Docker lab (Flask on **host port 8080**, Suricata idle for `docker exec`):

```bash
cd lab-setup && docker compose up -d --build
```

### Prove the rules fire

Install **Suricata** locally *or* install **Docker**, then:

```bash
python3 validation/test_rules.py
```

- Expectations live in `validation/detection_matrix.md`.
- Fresh replay output is written to `validation/detection_matrix.measured.md` (gitignored).

## Rule ↔ attack traceability

| Artifact | Points to |
| --- | --- |
| `attacks/port_scan.py` | `1000001`–`1000005` |
| `attacks/http_attacks.py` | `1000101`–`1000114` |
| `attacks/dns_attacks.py` | `1000201`–`1000205` |
| `attacks/tls_lab_clienthello.py` + merge in `generate_attack_pcaps.py` | `1000303`, `1000306` (in `mixed_attack.pcap`) |

TLS rules **1000301**, **1000302**, **1000304**, **1000305**, and **1000307** document production-style detections (expired/self-signed certs, intel JA3/JA3S). Only the subset above is exercised by default PCAPs; the comments explain how to extend captures.

## Non-goals (by design)

No Splunk/ELK, no Terraform, no ML classifiers, no SOC dashboards, no PulledPork. Alerts stay in **EVE JSON** and Python parsing — the skill being showcased is **detection engineering**, not SIEM plumbing.

## Further reading

- `docs/rule_writing_guide.md` — Snort/Suricata syntax with examples from this repo.
- `docs/ids_deployment_playbook.md` — tap vs inline, tuning cadence, log handling without a SIEM.
- `validation/tuning_notes.md` — narrative of thresholds, buffers, and TLS hashing decisions.
