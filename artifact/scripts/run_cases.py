#!/usr/bin/env python3
from __future__ import annotations
import csv
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from fedfence.analyzer import analyze_case, load_case, result_to_json  # noqa: E402


def main() -> int:
    cases_dir = ROOT / "cases"
    out_dir = ROOT / "results"
    out_dir.mkdir(exist_ok=True)
    rows = []
    paths = sorted(cases_dir.glob("*.json"))
    limit = int(os.environ.get("FEDFENCE_CASE_LIMIT", "0"))
    if limit > 0:
        paths = paths[:limit]
    for path in paths:
        case = load_case(path)
        res = analyze_case(case)
        expected = case.get("expected_safe")
        (out_dir / f"{path.stem}.result.json").write_text(result_to_json(res) + "\n")
        rows.append({
            "case": res.name,
            "expected_safe": expected if expected is not None else "",
            "safe": res.safe,
            "correct": (bool(res.safe) == bool(expected)) if expected is not None else True,
            "num_findings": len(res.findings),
            "finding_kinds": ";".join(f.kind for f in res.findings),
            "first_witness": next((f.witness for f in res.findings if f.witness), ""),
            "allow_subject_states": res.allow_subject_states,
            "intended_subject_states": res.intended_subject_states,
        })
    with (out_dir / "case_summary.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)
    ok = all(bool(r["correct"]) for r in rows)
    for r in rows:
        verdict = "SAFE" if r["safe"] else "UNSAFE"
        mark = "" if r["correct"] else " EXPECTED-MISMATCH"
        print(f"{r['case']}: {verdict} ({r['finding_kinds'] or 'no findings'}){mark}")
    print(f"\nWrote {out_dir/'case_summary.csv'}")
    return 0 if ok else 1

if __name__ == "__main__":
    raise SystemExit(main())
