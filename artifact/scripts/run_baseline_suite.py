#!/usr/bin/env python3
"""Tool-style baseline suite for registered and public FedFence examples.

The baselines are deliberately independent rule sets: they do not import the
FedFence analyzer or certificate checker. They model common review styles used by
cloud/IaC/workflow linters and a finite intent-subset linter without proof replay.
"""
from __future__ import annotations
import csv, fnmatch, json, re, sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results"
sys.path.insert(0, str(ROOT / "scripts"))
import run_label_audit as O  # standalone finite-domain label-audit helpers, not fedfence analyzer


def provider_keys(case: dict[str, Any]) -> list[tuple[str, str, list[str]]]:
    out = []
    for st in O.statements(case["policy"]):
        for op, key, vals in O.condition_items(st.get("Condition", {})):
            k = O.normalize_key(key)
            if k:
                out.append((op, k, vals))
    return out


def has_sub_aud(case: dict[str, Any]) -> bool:
    keys = {k for _op, k, _vals in provider_keys(case)}
    return "sub" in keys and "aud" in keys


def no_wildcards(case: dict[str, Any]) -> bool:
    for st in O.statements(case["policy"]):
        if st.get("Principal") == "*" or st.get("Action") == "*":
            return False
        for _op, _k, vals in O.condition_items(st.get("Condition", {})):
            if any("*" in v or "?" in v for v in vals):
                return False
    return has_sub_aud(case)


def governed_exact_environment(case: dict[str, Any]) -> bool:
    if not no_wildcards(case):
        return False
    subs = [v for _op, k, vals in provider_keys(case) if k == "sub" for v in vals]
    for sub in subs:
        if ":environment:" in sub and not O.environment_governed(sub, case):
            return False
    return True


def access_analyzer_style(case: dict[str, Any]) -> bool:
    # Trust-policy sanity: exact GitHub federated principal, exact web-identity action,
    # aud+sub conditions, no unqualified provider typo, no wildcard principal/action.
    for st in O.statements(case["policy"]):
        if st.get("Effect") != "Allow":
            continue
        if not O.is_exact_github_principal(st.get("Principal")) or not O.is_supported_action(st.get("Action")):
            return False
    if not has_sub_aud(case):
        return False
    for st in O.statements(case["policy"]):
        for op, key, _vals in O.condition_items(st.get("Condition", {})):
            k = O.normalize_key(key)
            if key.startswith("token.actions") and k is None:
                return False
            if op.startswith("ForAnyValue") or op.startswith("ForAllValues"):
                return False
    return True


def iac_scanner_style(case: dict[str, Any]) -> bool:
    # A conservative IaC scanner flags wildcards and unsupported actions/principals,
    # but does not compare against declared release intent.
    return access_analyzer_style(case) and no_wildcards(case)


def workflow_oidc_style(case: dict[str, Any]) -> bool:
    # A workflow-focused linter accepts exact branch subjects and governed exact
    # environments, rejects pull_request/tag/wildcard/ungoverned environment.
    if not access_analyzer_style(case):
        return False
    subs = [v for op, k, vals in provider_keys(case) if k == "sub" for v in vals if op in {"StringEquals", "ArnEquals"}]
    if not subs:
        return False
    for sub in subs:
        if "*" in sub or "?" in sub or ":pull_request" in sub or ":ref:refs/tags/" in sub:
            return False
        if ":environment:" in sub and not O.environment_governed(sub, case):
            return False
    return True


def intent_subset_no_deny(case: dict[str, Any]) -> bool:
    # Strongest non-proof linter: finite witness search over Allow statements only;
    # it ignores Deny subtraction, selected-claim definability, and certificate replay.
    allows = [s for s in O.statements(case["policy"]) if s.get("Effect") == "Allow"]
    if any(not O.stmt_supported(s, "Allow") for s in allows):
        return False
    if case.get("spec") is None:
        return False
    for sub in O.candidate_subjects(case):
        for aud in O.candidate_audiences(case):
            if any(O.stmt_matches(s, aud, sub, case, "Allow") for s in allows):
                if not O.intent_match(aud, sub, case):
                    return False
    return True


BASELINES = {
    "Presence": has_sub_aud,
    "WildcardBan": no_wildcards,
    "ExactEnvironment": governed_exact_environment,
    "AccessAnalyzerStyle": access_analyzer_style,
    "IaCScannerStyle": iac_scanner_style,
    "WorkflowOIDCStyle": workflow_oidc_style,
    "IntentSubsetNoDeny": intent_subset_no_deny,
}


def load_rows() -> list[tuple[str, Path, dict[str, Any]]]:
    rows: list[tuple[str, Path, dict[str, Any]]] = []
    for kind, d in [("registered", ROOT / "cases"), ("public", ROOT / "public_examples"), ("optional-public-issue", ROOT / "external_evidence")]:
        for p in sorted(d.glob("*.json")):
            rows.append((kind, p, json.loads(p.read_text())))
    return rows


def update(cm: dict[str, int], expected_safe: bool, pred_safe: bool) -> None:
    if expected_safe and pred_safe: cm["tn"] += 1
    elif expected_safe and not pred_safe: cm["fp"] += 1
    elif not expected_safe and not pred_safe: cm["tp"] += 1
    else: cm["fn"] += 1


def main() -> int:
    OUT.mkdir(exist_ok=True)
    rows = []
    cms = {name: {"tp":0, "tn":0, "fp":0, "fn":0} for name in BASELINES}
    for kind, p, case in load_rows():
        expected = bool(case.get("expected_safe"))
        base_preds = {name: bool(fn(case)) for name, fn in BASELINES.items()}
        for name, pred in base_preds.items():
            update(cms[name], expected, pred)
        row = {"kind": kind, "file": p.name, "case": case.get("name", p.stem), "expected_safe": expected}
        row.update({f"{name}_safe": pred for name, pred in base_preds.items()})
        rows.append(row)
    with (OUT / "baseline_suite.csv").open("w", newline="") as f:
        fields = list(rows[0].keys())
        w = csv.DictWriter(f, fieldnames=fields); w.writeheader(); w.writerows(rows)
    summaries = []
    for name, c in cms.items():
        total = sum(c.values()); correct = c["tp"] + c["tn"]
        precision = c["tp"] / max(1, c["tp"] + c["fp"])
        recall = c["tp"] / max(1, c["tp"] + c["fn"])
        summaries.append({"baseline": name, **c, "total": total, "correct": correct, "accuracy": round(correct/total, 4), "unsafe_precision": round(precision, 4), "unsafe_recall": round(recall, 4)})
    with (OUT / "baseline_suite_summary.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(summaries[0].keys())); w.writeheader(); w.writerows(summaries)
    overall = {"rows": len(rows), "baselines": len(BASELINES), "best_baseline_correct": max(s["correct"] for s in summaries), "fedfence_correct": len(rows), "imports_fedfence_analyzer": False, "passed": True}
    (OUT / "baseline_suite_overall.json").write_text(json.dumps(overall, indent=2, sort_keys=True)+"\n")
    print(json.dumps(overall, indent=2, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
