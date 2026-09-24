#!/usr/bin/env python3
from __future__ import annotations
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from fedfence.analyzer import analyze_case, load_case, result_to_json  # noqa: E402


def main() -> int:
    cases_dir = ROOT / "hardening_cases"
    out_dir = ROOT / "results"
    out_dir.mkdir(exist_ok=True)
    paths = sorted(cases_dir.glob("*.json"))
    rows = []
    for path in paths:
        case = load_case(path)
        res = analyze_case(case)
        expected = case.get("expected_safe")
        (out_dir / f"{path.stem}.hardening_result.json").write_text(result_to_json(res) + "\n")
        rows.append({
            "case": res.name,
            "expected_safe": expected if expected is not None else "",
            "safe": res.safe,
            "correct": (bool(res.safe) == bool(expected)) if expected is not None else True,
            "num_findings": len(res.findings),
            "finding_kinds": ";".join(f.kind for f in res.findings),
            "first_witness": next((f.witness for f in res.findings if f.witness), ""),
            "registered_profile": False,
        })
    if rows:
        with (out_dir / "hardening_case_summary.csv").open("w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader(); w.writerows(rows)
    else:
        (out_dir / "hardening_case_summary.csv").write_text("case,expected_safe,safe,correct,num_findings,finding_kinds,first_witness,registered_profile\n")
    ok = all(bool(r["correct"]) for r in rows)
    for r in rows:
        verdict = "SAFE" if r["safe"] else "UNSAFE"
        mark = "" if r["correct"] else " EXPECTED-MISMATCH"
        print(f"{r['case']}: {verdict} ({r['finding_kinds'] or 'no findings'}){mark}")
    print(f"\nWrote {out_dir/'hardening_case_summary.csv'} ({len(rows)} optional boundary rows)")
    return 0 if ok else 1

if __name__ == "__main__":
    raise SystemExit(main())
