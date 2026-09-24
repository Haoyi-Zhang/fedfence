#!/usr/bin/env python3
from __future__ import annotations
import csv
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from fse_workflow.io import load_json, save_json
from fse_workflow.public_changes import analyze_corpus

corpus = load_json(ROOT / "study" / "public_change_corpus.json")
result = analyze_corpus(corpus)
out = ROOT / "fse" / "results" / "public_change_study.json"
save_json(out, result)

csv_path = ROOT / "fse" / "results" / "public_change_study.csv"
with csv_path.open("w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=[
        "id", "repository", "commit", "change_kind", "source_snapshot", "source_snapshot_verified",
        "before", "after", "transition", "source_alignment", "before_witness", "after_witness",
        "required_tokens", "required_satisfied_after",
        "presence_before", "presence_after", "wildcard_ban_before", "wildcard_ban_after",
        "exact_ref_before", "exact_ref_after",
    ])
    writer.writeheader()
    for row in result["changes"]:
        writer.writerow({
            "id": row["id"],
            "repository": row["repository"],
            "commit": row["commit"],
            "change_kind": row["change_kind"],
            "source_snapshot": row["source_snapshot"],
            "source_snapshot_verified": row["source_snapshot_verified"],
            "before": row["before"]["verdict"],
            "after": row["after"]["verdict"],
            "transition": row["transition"],
            "source_alignment": row["source_alignment"],
            "before_witness": row["before"]["witnesses"][0] if row["before"]["witnesses"] else "",
            "after_witness": row["after"]["witnesses"][0] if row["after"]["witnesses"] else "",
            "required_tokens": len(row["required_tokens"]),
            "required_satisfied_after": row["after"]["required_token_checks"]["satisfied"],
            "presence_before": row["before"]["baselines"]["presence"],
            "presence_after": row["after"]["baselines"]["presence"],
            "wildcard_ban_before": row["before"]["baselines"]["wildcard_ban"],
            "wildcard_ban_after": row["after"]["baselines"]["wildcard_ban"],
            "exact_ref_before": row["before"]["baselines"]["exact_ref_only"],
            "exact_ref_after": row["after"]["baselines"]["exact_ref_only"],
        })

print(json.dumps(result["summary"], indent=2, sort_keys=True))
