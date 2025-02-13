#!/usr/bin/env bash
# Regenerate every synthetic PCAP from the repo root.
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ -d .venv ]]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
fi
python3 attacks/generate_attack_pcaps.py
