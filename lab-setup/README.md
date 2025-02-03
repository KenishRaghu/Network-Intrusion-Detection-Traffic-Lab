# Lab environment setup

Two ways to work through this project:

1. **Suricata + target app (Docker)** — recommended for a quick, repeatable environment.
2. **Snort on the host** — optional; see `snort/MANUAL_SETUP.md` and `snort/snort.conf`.

## Prerequisites

- Docker and Docker Compose
- (Optional) Suricata installed on the host for `suricata -r` without Docker
- (Optional) Snort installed locally if you want to compare engines

## Start Suricata and the target service

From the `lab-setup` directory:

```bash
docker compose up -d --build
```

- **Target (Flask)** listens on **container port 80**, published as **host port 8080** by default.
- **Suricata** container stays idle (`sleep infinity`) so you can `docker exec` and run commands.

### Quick check against the web app

```bash
curl -s http://127.0.0.1:8080/healthz || curl -s http://127.0.0.1:8080/
```

(Add a `/healthz` route to app or just use `/` — the sample app serves `/` only; use `/`).

### Run Suricata inside the container

```bash
docker exec -it ids-lab-suricata suricata -V
```

Replay a PCAP (mount `pcaps` into the container or copy a file in):

```bash
docker cp ../pcaps/http_attacks.pcap ids-lab-suricata:/tmp/
docker exec ids-lab-suricata suricata -r /tmp/http_attacks.pcap -l /var/log/suricata
docker exec ids-lab-suricata tail -20 /var/log/suricata/eve.json
```

## Live capture caveat

Traffic from your **host** to `localhost:8080` is proxied by Docker Desktop and may not look like classic Ethernet captures inside the Suricata container. For portfolio work, treat **PCAP replay** (`suricata -r`) as the source of truth for rule validation, and use Wireshark on the host for packet-level storytelling.

## Snort (manual)

See `snort/MANUAL_SETUP.md`. Update `RULE_PATH` in `snort/snort.conf` to your absolute path to the repo’s `rules/` directory.
