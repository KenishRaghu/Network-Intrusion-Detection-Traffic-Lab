# IDS deployment playbook (practical, non-SIEM)

This is the field-guide complement to the lab: where to **tap** traffic, how to **tune** without drowning in noise, and how to **handle logs** when you are not shipping to Splunk or Elastic.

## Placement patterns

| Mode | What you get | Trade-offs |
| --- | --- | --- |
| **Passive SPAN/RSPAN** | Copy of switch traffic to an IDS port. | No automatic blocking; oversubscription can drop packets under load; VLAN tagging must be understood. |
| **Network TAP (fiber/copper)** | Inline passive copy with very low loss on quality taps. | Cost and physical access; still passive-only unless paired with a bridge. |
| **Inline bridge** | IDS can `drop` malicious sessions when policy allows. | Latency budget and failure modes matter — clarify whether the appliance fails open or closed. |
| **Host-based** | Suricata on the endpoint (rare but real for high-risk servers). | Visibility into local loopback and container east-west if configured carefully. |

**Rule of thumb:** start **passive** on a **core VLAN mirror** that carries client-to-internet and client-to-data paths. Only move **inline** once the false-positive rate is boringly low for your environment.

## Sensor placement checklist

1. **Define `HOME_NET` honestly** — it should match RFC1918 space you defend, not `any`.
2. **Document asymmetric routes** — if return path bypasses the sensor, TCP state and HTTP reassembly degrade.
3. **MTU and encapsulation** — GRE, GENEVE, or PPPoE headers can shift where Suricata thinks L4 starts; adjust `decode` sections in `suricata.yaml` when needed.
4. **DNS visibility** — internal resolvers concentrate queries; placing sensors **between clients and resolver** shows original QNAME, while resolver-to-root traffic looks different.

## Tuning strategy (the boring part that wins)

1. **Load only what you wrote** (this repo’s philosophy) or a **minimal** vendor subset — not forty thousand blind copies of public rules.
2. **Run PCAP replays** (`suricata -r`) before you go live, exactly like `validation/test_rules.py`.
3. **Promote thresholds gradually** — start permissive on internal nets, tighten after you know your baseline (patch Tuesday, backup windows, scanner cadence).
4. **Bucket alerts** — for each noisy SID, decide: *tune*, *suppress by src*, *drop rule*, or *convert to flowbit multi-stage*.

## Inline vs passive policy

- **Passive** — optimize for **signal quality** and **full capture** (PCAP slices on alerts).
- **Inline** — pair signatures with **risk tiers**: `alert` first, then selective `drop` on SIDs with near-zero legitimate use (exploit shellcode, known C2 JA3 + SNI pairing).

Never inline a rule you have not **PCAP-proven** against representative traffic.

## Log management without a SIEM

Suricata **EVE JSON** is newline-delimited JSON — easy to `jq`, Python, or `gzip` rotate.

Basics:

- **Rotate by size or time** (`logrotate`, container volume policies).
- **Keep raw EVE for 7–30 days** on hot storage, ship compressed archives to object storage if compliance requires longer retention.
- **Extract pcaps** for investigations using `suricata -r` or live `unix-socket` commands when enabled.

This repository’s `validation/test_rules.py` is a miniature of what you would cron in production: **replay → parse JSON → assert**.

## When you outgrow files

You do not need Terraform or Elastic to improve hygiene:

- Push JSON lines to **S3 + Athena**, **BigQuery**, or a **tiny SQLite** warehouse for weekly reporting.
- Track **SID counts per VLAN** in pandas or a notebook — still not a SOC, still valuable.

## Hand-written rules in production

Commercial feeds are fantastic for commodity malware, but interviews (and incidents) reward engineers who can **derive** a signature from a PCAP. Keep a private Git repo like this one: **rule change → PCAP proof → deployment note**. That is the same discipline as code review, just for detection logic.
