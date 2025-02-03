# Running Snort locally (not containerized)

Snort is intentionally **not** Dockerized in this lab: kernel capture, DAQ modules, and Snort 2 vs 3 packaging differ too much across hosts for a one-size compose file. Use Suricata in Docker for the quickest path; use these steps when you want the same **hand-written** rules on Snort.

## 1. Install Snort

- **macOS**: often via Homebrew builds or source; confirm `snort -V`.
- **Linux**: use your distro package or Cisco/Talos guidance for Snort 3.

## 2. Point `snort.conf` at this repo’s rules

Edit `lab-setup/snort/snort.conf` and set:

```text
var RULE_PATH /absolute/path/to/Network-Intrusion-Detection-Traffic-Lab/rules
```

## 3. Test the config

```bash
snort -T -c lab-setup/snort/snort.conf
```

## 4. Read a PCAP (matches the validation workflow)

```bash
snort -c lab-setup/snort/snort.conf -r pcaps/http_attacks.pcap -A fast
```

Snort’s alert format differs from Suricata’s EVE JSON; this repo’s automated validation targets **Suricata EVE** output. For Snort, compare alerts manually or adapt the Python parser.

## 5. Syntax notes

Most rules here use **Suricata-compatible** keywords (`dns.query`, `ja3.hash`, `tls.sni`, etc.). Snort 3’s rule language overlaps but is not identical: if a rule fails to load, check Snort’s error for unsupported options and trim or rewrite that line for your Snort version.
