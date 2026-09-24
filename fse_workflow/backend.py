"""Isolated invocation of the unchanged, frozen FedFence analyzer and replay path."""
from __future__ import annotations
import json
import sys
from dataclasses import asdict
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "artifact"))
from fedfence.analyzer import analyze_case
from fedfence.certificate import certificate_for_case, verify_certificate


def main():
    case = json.load(sys.stdin)
    result = analyze_case(case)
    cert = certificate_for_case(case)
    ok, notes = verify_certificate(cert)
    print(json.dumps({"analysis": asdict(result), "certificate": cert,
                      "replay_ok": ok, "replay_notes": notes}, sort_keys=True))

if __name__ == "__main__":
    main()
