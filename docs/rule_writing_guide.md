# Snort / Suricata rule writing — teammate cheat sheet

This guide matches what this repository actually uses: **Suricata 7** grammar, **EVE JSON** logging, and **hand-authored** signatures in `rules/*.rules`. Snort 3 can load many of the same bodies, but always fix up engine-specific keywords after `snort -T`.

## Anatomy of a rule

```text
action proto src_ip src_port -> dst_ip dst_port (msg:"..."; keyword:value; sid:1; rev:1;)
```

- **action** — `alert`, `pass`, `drop` (drop requires inline deployment).
- **header** — constrains L3/L4 before bracket options run.
- **options** — semicolon-terminated `key:value` or bare keywords (`tls_cert_expired;`).

Keep **`sid`** unique per sensor configuration and bump **`rev`** when you touch logic. This lab uses a private block (`1000xxx`) so you never collide with vendor feeds you might load later.

## Sticky buffers (where matching happens)

Modern Suricata prefers explicit buffers instead of raw `pkt` grepping:

| Layer | Examples in this repo |
| --- | --- |
| HTTP request | `http.uri`, `http.user_agent`, `http.request_body` |
| HTTP response | `http.stat_code`, `http.stat_msg` |
| DNS | `dns.query` (normalized dotted string) |
| TLS | `tls.sni`, `tls.cert_issuer`, `ja3.hash`, `ja3s.hash` |

Pattern: declare the buffer once, then chain `content` matches that apply to it until you switch buffers or end the rule.

```text
alert http any any -> $HOME_NET any (
    flow:established,to_server;
    http.uri;
    content:"union";
    nocase;
    content:"select";
    nocase;
    distance:0;
    within:64;
    sid:1000101;
    rev:1;
)
```

## Content matching essentials

- **`content:"literal"`** — binary-safe string match; use `|de ad be ef|` hex for non-printables.
- **`nocase`** — case-insensitive ASCII comparison on the preceding content.
- **`fast_pattern`** — hint the engine which content to use for the initial MPM pass (put on a rare-ish atom).
- **`depth` / `offset` / `distance` / `within`** — bound how far the engine searches relative to the start of the buffer or the previous match. Great for performance and for avoiding accidental hits deep in giant URIs.

## PCRE when you truly need it

Use `pcre:"/regex/flags";` sparingly — it is slower than content chains and harder to fast-pattern. In this repo PCRE was almost used for SQLi, but literal `content` won for clarity. Reach for PCRE when you need alternation or character classes that would explode into dozens of content keywords.

## Flow and direction

- **`flow:established`** — skip handshake noise when you only care about application data.
- **`flow:to_server` / `from_server`** — split requests from responses on protocols that support it (HTTP especially).
- **`flowint`** — stateful counters per flow (not used in the final tcp rules after simplification, but handy when you want multi-packet state machines).

## Thresholds and rate limiting

Suricata `threshold` inside a rule options block is perfect for floods and scans:

```text
threshold:type both, track by_src, count 80, seconds 3;
```

- **`track by_src` / `by_dst`** — choose the atom you want to protect (victim vs aggressor perspective).
- **`type limit|threshold|both`** — `both` is the usual choice for “alert once per bucket” semantics.

For global suppression of noisy SIDs, move the knob into **`threshold.config`** or use **`suppress gen_id,sig_id`** stanzas in production — this repo keeps thresholds inline so each rule file is self-contained for teaching.

## Flowbits (when one packet is not enough)

`flowbits:set`, `flowbits:isset`, `flowbits:noalert` let you model multi-step protocols (“saw login POST” → “saw 500 with SQL error”). None of the lab rules require flowbits yet, but the pattern is:

1. `flowbits:set,foo;` on the first match (often with `flowbits:noalert` on that rule).
2. `flowbits:isset,foo;` on the second-stage rule that raises the real alert.

## DNS and TLS keywords worth memorizing

- **`dns.query;`** — all following `content` hits the question name until reset.
- **`tls.sni;`** — cleartext hostname from ClientHello.
- **`ja3.hash;`** — MD5 of the JA3 string; pair with `content:"..."` for exact matches.
- **`tls_cert_expired;`** — boolean match on parsed certificate validity (no `content` needed).

## Suppress vs disable

- **`suppress gen_id 1, sig_id 1000101, track by_src, ip 10.0.0.5`** — still load the rule, but silence a known noisy source (dev subnet, scanner VLAN).
- Commenting out a rule — fine for labs; in production prefer **`pass`** rules with narrow scope or threshold tuning so you retain visibility into what you intentionally ignore.

## Snort-specific footnote

Snort 3’s rule parser overlaps with Suricata on many `content` idioms, but keywords such as **`ja3.hash`**, **`dns.query`**, or **`http.request_body`** may differ or require alternate modules. When Snort rejects a line, treat it as a **compatibility shim** task, not a signal that the idea is wrong.

## How this repo stays honest

Every rule file begins with comment blocks that answer three interview questions: **what**, **why**, and **what would false positive**. Pair that with `validation/test_rules.py` so the story is not aspirational — it is replay-verified on PCAPs you can regenerate anytime.
