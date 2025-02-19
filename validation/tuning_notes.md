# Tuning notes — how the lab rules evolved

This file is the narrative companion to `validation/test_rules.py` and `validation/detection_matrix.md`. It explains what I changed while moving from “rules that look right on paper” to “rules that survive replay against synthetic PCAPs without crying wolf on the baseline.”

## Starting point

I began with permissive TCP recon rules: any odd flag combination would have fired on almost every malformed packet. That teaches Wireshark skills, but it is useless for a portfolio story about **accuracy**. I tightened the model around two ideas: **thresholds** for floods and scans, and **sticky buffers** (`http.uri`, `dns.query`, `ja3.hash`, `tls.sni`) so inspection stays anchored to the right protocol field.

## TCP thresholds

SYN floods and horizontal port scans are intentionally ambiguous signatures. A misconfigured health checker or a NATed campus network can look like an attacker if the numbers are too low. I settled on **80 SYN in 3 seconds** for the SYN spike rule and **18 destination ports in 4 seconds** for the SYN scan rule after watching smaller counts trip during mixed PCAP merges where unrelated flows shared the same second boundaries. FIN scans used the same philosophy: count **distinct destination ports** rather than single FINs, because teardown FINs are normal but **fourteen different ports** in a few seconds is not.

The XMAS and NULL rules stay **non-thresholded** on purpose: those flag combinations are rare enough that a single packet is worth a look, with the false-positive story called out in the rule comments (middleboxes and capture artifacts).

## HTTP depth and encodings

Early URI rules used only `content:"or 1=1"` against `id=1+or+1=1` style parameters. Suricata’s normalized URI buffer often maps `+` to space, but not always in the way I expected across every generator revision, so I standardized the synthetic request on **percent-encoded spaces** (`%20`) and equals (`%3D`) for the OR-tautology test. That keeps the traffic valid on the wire and predictable in the IDS buffer.

The quoted-OR rule originally used a PCRE with flexible whitespace. PCRE is powerful but expensive, and my first expression did not match the compact `'+or+'` encoding the attack script emitted. I replaced it with a short literal `content:"'+or+'"; nocase;` anchored in `http.uri`, which is easier to explain in an interview and matches the lab traffic exactly.

For SQL comment detection, matching bare `--` and `#` in one rule produced ridiculous false positives on any URL with a fragment. I rewrote the signature to require **`union` within 96 bytes of `--`**, which tracks how automated UNION-based probes often terminate the original query.

The mass-403 rule needed careful direction: it must key off **responses** (`flow:established,from_server`) and threshold on **`track by_dst`** so we count denials **to the same client**, not from the same server port. The lab generator fires twenty-eight sequential HTTP exchanges, each with a 403 body, so the threshold (22 hits in 8 seconds) clears with margin.

## DNS on Suricata 7

Suricata 7’s documented DNS keywords in this lab are basically **`dns.query`** and **`dns.opcode`**. There is no portable `dns.rrtype:252` in the 7.0 doc set I targeted, so the AXFR coverage uses a **fixed wire pattern** for the QNAME `x.lab` plus QTYPE 252, which the Scapy generator emits deterministically. A comment in `dns_rules.rules` points future readers at `dns.rrtype` once they move to Suricata 8+.

The “TXT tunnel” rule is deliberately **threshold + label suffix** (`.txt-exfil.lab.invalid`) instead of a blind “many TXT anywhere” alert, because resolvers and mail security stacks legitimately hammer TXT records.

## TLS without decryption

JA3 is ideal for portfolio storytelling because it stays entirely in the handshake. I locked cipher suites and extension order in `attacks/tls_lab_clienthello.py`, hashed the resulting JA3 string with the same algorithm Suricata uses (Salesforce JA3 semantics), and embedded the MD5 **`4e6327d6b4b699766c1250b3356cfde4`** in **SID 1000303**. If a Suricata upgrade ever disagrees with that hash, the fix is to replay `mixed_attack.pcap`, read `eve.json`, and paste the observed `ja3.hash` — that is intentional workflow documentation, not a failure mode to hide.

Certificate-based rules (**1000301**, **1000302**) remain loaded because they matter in production, but they are not satisfied by default PCAPs. I would capture `openssl s_client` sessions against **badssl.com**-style endpoints if I wanted to extend the automated matrix without inventing fake DER.

The extra JA3/JA3S rows (**1000304**, **1000305**, **1000307**) are **threat-intel exemplars**: they show how you bolt community hashes onto the same syntax as the lab print. They are expected to stay silent in local replay until you feed PCAPs that match those fingerprints.

## What I would do next in a real network

- Promote thresholds into `suppress` / `threshold` config snippets per subnet role (DMZ vs user VLAN).
- Split HTTP rules into “block” vs “alert-only” policies based on FP review from a week of NetFlow-backed baselines.
- Replace placeholder malicious domains with a **local** threat feed you are allowed to redistribute, and document rotation.
