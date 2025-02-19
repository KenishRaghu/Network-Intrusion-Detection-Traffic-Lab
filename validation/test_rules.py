#!/usr/bin/env python3
"""
Replay PCAPs through Suricata and verify expected alert SIDs (true positives)
and baseline cleanliness (false positives).

Prefers a local `suricata` binary; otherwise uses Docker (`jasonish/suricata:7.0.3`)
if available. Install Suricata or Docker, then run from repo root:

  python3 validation/test_rules.py

On success, writes `validation/detection_matrix.measured.md` with replay results.
See `detection_matrix.md` for the static expectation table.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple

REPO = Path(__file__).resolve().parents[1]
PCAPS = REPO / "pcaps"
RULES = REPO / "rules"
SURICATA_YAML = REPO / "lab-setup" / "suricata" / "suricata.yaml"
MATRIX_OUT = REPO / "validation" / "detection_matrix.measured.md"
DOCKER_IMAGE = "jasonish/suricata:7.0.3"

# PCAP → SIDs we expect to see at least once (true-positive contract).
EXPECTED: Dict[str, Set[int]] = {
    "baseline_clean.pcap": set(),
    "port_scan.pcap": {1000001, 1000002, 1000003, 1000004, 1000005},
    "http_attacks.pcap": {
        1000101,
        1000102,
        1000103,
        1000104,
        1000105,
        1000106,
        1000107,
        1000108,
        1000109,
        1000110,
        1000111,
        1000112,
        1000113,
        1000114,
    },
    "dns_attacks.pcap": {1000201, 1000202, 1000203, 1000204, 1000205},
    "mixed_attack.pcap": {
        1000001,
        1000002,
        1000003,
        1000004,
        1000005,
        1000101,
        1000102,
        1000103,
        1000104,
        1000105,
        1000106,
        1000107,
        1000108,
        1000109,
        1000110,
        1000111,
        1000112,
        1000113,
        1000114,
        1000201,
        1000202,
        1000203,
        1000204,
        1000205,
        1000303,
        1000306,
    },
}

# Every hand-written SID in this repo (for matrix rows / documentation).
ALL_SIDS = sorted(
    {
        1000001,
        1000002,
        1000003,
        1000004,
        1000005,
        1000101,
        1000102,
        1000103,
        1000104,
        1000105,
        1000106,
        1000107,
        1000108,
        1000109,
        1000110,
        1000111,
        1000112,
        1000113,
        1000114,
        1000201,
        1000202,
        1000203,
        1000204,
        1000205,
        1000301,
        1000302,
        1000303,
        1000304,
        1000305,
        1000306,
        1000307,
    }
)


def _parse_eve_sids(eve_path: Path) -> Set[int]:
    sids: Set[int] = set()
    if not eve_path.is_file():
        return sids
    with eve_path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            alert = obj.get("alert")
            if not alert:
                continue
            sid = alert.get("signature_id")
            if isinstance(sid, int):
                sids.add(sid)
    return sids


def _run_suricata_docker(pcap: Path, log_dir: Path) -> None:
    repo = str(REPO)
    cmd = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{repo}/rules:/etc/suricata/rules:ro",
        "-v",
        f"{repo}/lab-setup/suricata/suricata.yaml:/etc/suricata/suricata.yaml:ro",
        "-v",
        f"{repo}/pcaps:/pcaps:ro",
        "-v",
        f"{log_dir}:/out",
        DOCKER_IMAGE,
        "suricata",
        "-r",
        f"/pcaps/{pcap.name}",
        "-l",
        "/out",
    ]
    subprocess.run(cmd, check=True, capture_output=True, text=True)


def _run_suricata_local(pcap: Path, log_dir: Path) -> None:
    cmd = [
        "suricata",
        "-r",
        str(pcap),
        "-l",
        str(log_dir),
        "-c",
        str(SURICATA_YAML),
    ]
    env = None
    # Homebrew Suricata on macOS often keeps *.config next to suricata.yaml.
    # If classification fails, users should symlink or use Docker.
    subprocess.run(cmd, check=True, capture_output=True, text=True)


def run_suricata_on_pcap(pcap: Path, log_dir: Path, use_docker: bool) -> None:
    log_dir.mkdir(parents=True, exist_ok=True)
    for old in log_dir.glob("*.json"):
        old.unlink()
    if use_docker:
        _run_suricata_docker(pcap, log_dir)
    else:
        _run_suricata_local(pcap, log_dir)


def choose_backend() -> Tuple[str, bool]:
    if shutil.which("suricata"):
        return ("local suricata", False)
    if shutil.which("docker"):
        return (f"docker {DOCKER_IMAGE}", True)
    return ("", False)


def write_matrix(
    results: Dict[str, Set[int]],
    passes: Dict[str, bool],
    backend: str,
) -> None:
    pcaps = list(EXPECTED.keys())
    lines: List[str] = [
        "# Detection matrix (measured)",
        "",
        f"Generated by `validation/test_rules.py` using **{backend}**.",
        "",
        "Rows are rule SIDs. Columns are PCAPs. **Y** = at least one alert with that SID on replay.",
        "",
    ]
    header = "| SID | " + " | ".join(pcaps) + " | Notes |"
    sep = "| --- | " + " | ".join(["---"] * len(pcaps)) + " | --- |"
    lines.extend([header, sep])
    for sid in ALL_SIDS:
        cells = []
        for pcap_name in pcaps:
            triggered = sid in results.get(pcap_name, set())
            cells.append("Y" if triggered else "")
        note = ""
        if sid in {1000301, 1000302, 1000304, 1000305, 1000307}:
            note = "Optional / intel-only in default PCAP set."
        lines.append("| " + str(sid) + " | " + " | ".join(cells) + f" | {note} |")
    lines.append("")
    lines.append("## Scenario pass/fail (expected ⊆ triggered)")
    lines.append("")
    lines.append("| PCAP | Pass |")
    lines.append("| --- | --- |")
    for name, ok in passes.items():
        lines.append(f"| {name} | {'yes' if ok else 'no'} |")
    lines.append("")
    MATRIX_OUT.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    backend_name, use_docker = choose_backend()
    if not backend_name:
        print(
            "Neither `suricata` nor `docker` found in PATH. "
            "Install Suricata or Docker, then re-run.",
            file=sys.stderr,
        )
        print("Expected coverage reference: validation/detection_matrix.md", file=sys.stderr)
        return 1

    results: Dict[str, Set[int]] = {}
    passes: Dict[str, bool] = {}
    work = REPO / ".suricata-validation-logs"
    work.mkdir(exist_ok=True)

    for pcap_name in EXPECTED:
        pcap = PCAPS / pcap_name
        if not pcap.is_file():
            print(f"Missing PCAP {pcap}; run pcaps/generate_all.sh first.", file=sys.stderr)
            return 1
        log_d = work / pcap_name.replace(".pcap", "")
        if log_d.exists():
            shutil.rmtree(log_d)
        try:
            run_suricata_on_pcap(pcap, log_d, use_docker)
        except subprocess.CalledProcessError as exc:
            print(f"Suricata failed on {pcap_name}:\n{exc.stderr}", file=sys.stderr)
            return 1
        eve = log_d / "eve.json"
        triggered = _parse_eve_sids(eve)
        results[pcap_name] = triggered
        exp = EXPECTED[pcap_name]
        if pcap_name == "baseline_clean.pcap":
            passes[pcap_name] = len(triggered) == 0
        else:
            passes[pcap_name] = exp.issubset(triggered)

    write_matrix(results, passes, backend_name)

    ok = all(passes.values())
    print(f"Wrote {MATRIX_OUT.relative_to(REPO)}")
    if ok:
        print("All scenario checks passed.")
    else:
        print("Some scenarios failed — see detection_matrix.md and stderr details.", file=sys.stderr)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
