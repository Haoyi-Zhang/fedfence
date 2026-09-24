#!/usr/bin/env python3
from __future__ import annotations
import csv, json, os, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from fedfence.analyzer import load_case  # noqa: E402
from fedfence.repair import repair_outcome, synthesize_repair  # noqa: E402

def main() -> int:
    rows = []
    repaired_dir = ROOT / "results" / "repairs"
    repaired_dir.mkdir(parents=True, exist_ok=True)
    paths = sorted((ROOT / "cases").glob("*.json"))
    limit = int(os.environ.get("FEDFENCE_REPAIR_LIMIT", os.environ.get("FEDFENCE_CASE_LIMIT", "0")))
    if limit > 0:
        paths = paths[:limit]
    for path in paths:
        case = load_case(path)
        outcome = repair_outcome(case)
        rows.append({
            "case": path.stem,
            "original_safe": outcome["original_safe"],
            "original_findings": ";".join(outcome["original_findings"]),
            "policy_repair_safe": outcome["policy_repair_safe"],
            "policy_repair_findings": ";".join(outcome["policy_repair_findings"]),
            "governance_repair_safe": outcome["governance_repair_safe"],
            "governance_required": ";".join(outcome["policy_meta"]["environment_governance_required"]),
        })
        repaired, meta = synthesize_repair(case, add_governance=True)
        repaired_dir.joinpath(path.stem + ".repaired.json").write_text(json.dumps({"case": repaired, "repair": meta}, indent=2, sort_keys=True))
    with (ROOT / "results" / "repair_summary.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)
    print(json.dumps({
        "cases": len(rows),
        "original_safe": sum(1 for r in rows if r["original_safe"]),
        "policy_repaired_safe": sum(1 for r in rows if r["policy_repair_safe"]),
        "governance_repaired_safe": sum(1 for r in rows if r["governance_repair_safe"]),
        "governance_cuts_required": sum(1 for r in rows if r["governance_required"]),
    }, indent=2), flush=True)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
