#!/usr/bin/env python3
"""Audit governance premises from exported repository-settings snapshots.

FedFence proofs use governance facts only as explicit premises. This harness makes
that premise mechanically reviewable for exported settings: a positive premise is
accepted only when the snapshot contains the corresponding protected branch, tag,
environment, or pinned reusable-workflow rule. No network or live account access is
used, and missing/ambiguous exports fail closed.
"""
from __future__ import annotations
import fnmatch, json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "governance_exports"
OUT = ROOT / "results"


def as_list(x: Any) -> list[Any]:
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def branch_protected(exports: dict[str, Any], branch: str) -> bool:
    for row in as_list(exports.get("branches")):
        if row.get("name") == branch:
            return bool(row.get("protected")) and int(row.get("required_reviews", 0)) > 0
    return False


def tag_protected(exports: dict[str, Any], tag: str) -> bool:
    for row in as_list(exports.get("tags")):
        if not row.get("protected"):
            continue
        pat = str(row.get("pattern", ""))
        if fnmatch.fnmatchcase(tag, pat) and int(row.get("required_reviews", 0)) > 0:
            return True
    return False


def environment_protected(exports: dict[str, Any], env: str, branch: str) -> bool:
    for row in as_list(exports.get("environments")):
        if row.get("name") != env:
            continue
        reviewers = int(row.get("reviewers", 0))
        branches = [str(x) for x in as_list(row.get("deployment_branches"))]
        exact_branch = branch in branches and "*" not in branches
        return reviewers > 0 and exact_branch and bool(row.get("prevent_self_review", False))
    return False


def reusable_workflow_pinned(exports: dict[str, Any], workflow_ref: str, caller: str) -> bool:
    for row in as_list(exports.get("reusable_workflows")):
        if row.get("workflow_ref") == workflow_ref:
            return bool(row.get("pinned_ref")) and caller in [str(x) for x in as_list(row.get("allowed_callers"))]
    return False


def eval_premise(exports: dict[str, Any], premise: dict[str, Any]) -> bool:
    kind = premise.get("kind")
    if kind == "protected_branch":
        return branch_protected(exports, str(premise.get("branch", "")))
    if kind == "protected_environment":
        return environment_protected(exports, str(premise.get("environment", "")), str(premise.get("branch", "")))
    if kind == "protected_tag":
        return tag_protected(exports, str(premise.get("tag", "")))
    if kind == "pinned_reusable_workflow":
        return reusable_workflow_pinned(exports, str(premise.get("workflow_ref", "")), str(premise.get("caller", "")))
    return False


def main() -> int:
    OUT.mkdir(exist_ok=True)
    rows: list[dict[str, Any]] = []
    failures: list[str] = []
    files = sorted(p for p in SRC.glob("*.json"))
    for p in files:
        doc = json.loads(p.read_text())
        exports = doc.get("exports") or {}
        for idx, premise in enumerate(as_list(doc.get("premises"))):
            observed = eval_premise(exports, premise)
            expected = bool(premise.get("expected"))
            ok = observed == expected
            row = {
                "fixture": doc.get("name", p.stem),
                "premise_index": idx,
                "kind": premise.get("kind"),
                "expected": expected,
                "observed": observed,
                "ok": ok,
            }
            rows.append(row)
            if not ok:
                failures.append(f"{p.name}:{idx} expected {expected} observed {observed}")
    result = {
        "passed": not failures,
        "fixtures": len(files),
        "premises": len(rows),
        "verified": sum(1 for r in rows if r["ok"]),
        "failures": failures,
        "mode": "exported-snapshot governance audit; no live account access",
    }
    (OUT / "governance_export_audit.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    with (OUT / "governance_export_rows.csv").open("w") as f:
        f.write("fixture,premise_index,kind,expected,observed,ok\n")
        for r in rows:
            f.write(f"{r['fixture']},{r['premise_index']},{r['kind']},{r['expected']},{r['observed']},{r['ok']}\n")
    print(json.dumps(result, indent=2, sort_keys=True), flush=True)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
