#!/usr/bin/env python3
from __future__ import annotations
import csv, json, os, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from fedfence.analyzer import load_case, analyze_case  # noqa: E402
from fedfence.certificate import certificate_for_case, verify_certificate  # noqa: E402


def main() -> int:
    out_dir = ROOT / "results" / "certificates"
    out_dir.mkdir(parents=True, exist_ok=True)
    rows = []
    limit = int(os.environ.get("FEDFENCE_CERT_LIMIT", os.environ.get("FEDFENCE_CASE_LIMIT", "0")))
    paths = sorted((ROOT / "cases").glob("*.json"))
    if limit > 0:
        paths = paths[:limit]
    for path in paths:
        case = load_case(path)
        cert = certificate_for_case(case)
        ok, msg = verify_certificate(cert)
        analyzer_result = analyze_case(case)
        analyzer_agrees = (("safe" if analyzer_result.safe else "unsafe") == cert.get("verdict"))
        ok = bool(ok) and analyzer_agrees
        cpath = out_dir / f"{path.stem}.effective.certificate.json"
        cpath.write_text(json.dumps(cert, indent=2, sort_keys=True) + "\n")
        msg_text = "; ".join(msg) if isinstance(msg, list) else str(msg)
        rows.append({
            "case": path.stem,
            "judgment": cert.get("judgment", ""),
            "verdict": cert.get("verdict", ""),
            "verified": bool(ok),
            "analyzer_agrees": bool(analyzer_agrees),
            "message": msg_text,
            "blocking_kinds": ";".join(cert.get("replay_summary", {}).get("blocking_kinds", [])),
            "num_findings": len(cert.get("replay_summary", {}).get("all_kinds", [])),
        })
    with (ROOT / "results" / "certificate_summary.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)
    if not all(r["verified"] for r in rows):
        raise SystemExit("certificate verification failed")
    print(json.dumps({
        "certificates": len(rows),
        "verified": sum(1 for r in rows if r["verified"]),
        "safe_certificates": sum(1 for r in rows if r["verdict"] == "safe"),
        "unsafe_or_boundary_certificates": sum(1 for r in rows if r["verdict"] != "safe"),
    }, indent=2), flush=True)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
