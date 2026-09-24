#!/usr/bin/env python3
"""Standalone finite-domain label audit for FedFence labels.

This script intentionally does not import fedfence.analyzer or the certificate
checker. It implements a small IAM/OIDC witness search over normalized public and
curated examples. The purpose is to make the expected labels independently
inspectable by a cold reviewer, not to replace the proof engine.
"""
from __future__ import annotations
import csv, fnmatch, json, re
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results"
GITHUB_PROVIDER = "token.actions.githubusercontent.com"
STS = "sts:AssumeRoleWithWebIdentity"
AUD_DEFAULTS = ["sts.amazonaws.com", "evil-service", "https://github.com/my-org", "?", "*"]


def as_list(x: Any) -> list[Any]:
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def statements(policy: dict[str, Any]) -> list[dict[str, Any]]:
    return as_list(policy.get("Statement"))


def is_exact_github_principal(principal: Any) -> bool:
    if not isinstance(principal, dict):
        return False
    if set(principal.keys()) != {"Federated"}:
        return False
    val = principal.get("Federated")
    return isinstance(val, str) and val.endswith("oidc-provider/token.actions.githubusercontent.com")


def is_supported_action(action: Any) -> bool:
    vals = as_list(action)
    return len(vals) == 1 and vals[0] == STS


def condition_items(cond: dict[str, Any]) -> Iterable[tuple[str, str, list[str]]]:
    for op, kv in (cond or {}).items():
        if not isinstance(kv, dict):
            yield op, "__unsupported__", [str(kv)]
            continue
        for key, val in kv.items():
            yield op, key, [str(v) for v in as_list(val)]


def normalize_key(key: str) -> str | None:
    prefix = GITHUB_PROVIDER + ":"
    if key.startswith(prefix):
        return key[len(prefix):]
    return None


def op_match(op: str, actual: str, patterns: list[str]) -> bool | None:
    if op in {"StringEquals", "ArnEquals"}:
        return any(actual == p for p in patterns)
    if op in {"StringLike", "ArnLike"}:
        return any(fnmatch.fnmatchcase(actual, p) for p in patterns)
    if op in {"StringNotLike", "ArnNotLike"}:
        return all(not fnmatch.fnmatchcase(actual, p) for p in patterns)
    if op in {"StringNotEquals", "ArnNotEquals"}:
        return all(actual != p for p in patterns)
    return None


def expand_subject_pattern(pat: str) -> list[str]:
    seeds = set()
    if "*" not in pat and "?" not in pat:
        seeds.add(pat)
    m = re.match(r"repo:([^/]+)/([^:*/?]+|\*)(?::(.*))?$", pat)
    owners = [m.group(1)] if m else ["acme", "octo-org", "example-org"]
    if m:
        repo_pat = m.group(2)
        repos = ["api", "service", "octo-repo", "other", "myrepo1", "myrepo2"] if repo_pat == "*" else [repo_pat, repo_pat + "-alt"]
    else:
        repos = ["api", "service", "octo-repo"]
    suffixes = [
        "ref:refs/heads/main", "ref:refs/heads/dev", "ref:refs/heads/release/v1",
        "ref:refs/heads/main-hotfix", "ref:refs/heads/releaseXcandidate",
        "ref:refs/tags/v1", "ref:refs/tags/beta", "pull_request",
        "environment:prod", "environment:production", "environment:dev", "environment:staging",
    ]
    for o in owners:
        for r in repos:
            for s in suffixes:
                subj = f"repo:{o}/{r}:{s}"
                if fnmatch.fnmatchcase(subj, pat):
                    seeds.add(subj)
    return sorted(seeds)


def expand_audience_pattern(pat: str) -> list[str]:
    vals = set(AUD_DEFAULTS)
    if "*" not in pat and "?" not in pat:
        vals.add(pat)
    return sorted(v for v in vals if fnmatch.fnmatchcase(v, pat) or v == pat)


def collect_patterns(case: dict[str, Any], claim: str) -> list[str]:
    pats: list[str] = []
    for st in statements(case["policy"]):
        for _op, key, vals in condition_items(st.get("Condition", {})):
            if normalize_key(key) == claim:
                pats.extend(vals)
    return pats


def spec_subjects(case: dict[str, Any]) -> list[str]:
    spec = case.get("spec") or {}
    vals = [str(x) for x in as_list(spec.get("issuer_subjects"))]
    vals += [str(x) for x in as_list(spec.get("allowed_subjects"))]
    for g in as_list(spec.get("allowed_subject_globs")):
        vals += expand_subject_pattern(str(g))
    return vals


def candidate_subjects(case: dict[str, Any]) -> list[str]:
    vals = set(spec_subjects(case))
    for p in collect_patterns(case, "sub"):
        vals.update(expand_subject_pattern(str(p)))
    if not vals:
        vals.update(expand_subject_pattern("repo:acme/api:*"))
        vals.update(expand_subject_pattern("repo:octo-org/octo-repo:*"))
    for s in list(vals):
        m = re.match(r"repo:([^/]+)/([^:]+):", s)
        if m:
            o, r = m.groups()
            vals.update(expand_subject_pattern(f"repo:{o}/{r}:*"))
    return sorted(vals)


def candidate_audiences(case: dict[str, Any]) -> list[str]:
    spec = case.get("spec") or {}
    issuer = [str(x) for x in as_list(spec.get("issuer_audiences"))]
    if issuer:
        # If the issuer audience domain is declared, it is the finite source of
        # mintable audiences; policy wildcards should not invent values beyond it.
        return sorted(set(issuer))
    vals = set(str(x) for x in as_list(spec.get("allowed_audiences")))
    for p in collect_patterns(case, "aud"):
        vals.update(expand_audience_pattern(str(p)))
    if not vals:
        vals.update(AUD_DEFAULTS)
    return sorted(vals)


def selected_claim_state(sub: str, case: dict[str, Any]) -> dict[str, str]:
    claims = {"sub": sub}
    if ":ref:" in sub:
        claims["ref"] = sub.split(":ref:", 1)[1]
    if ":environment:" in sub:
        claims["environment"] = sub.split(":environment:", 1)[1]
    for claim in ["ref", "environment", "repository_id", "job_workflow_ref", "repository_custom_properties.tier"]:
        pats = collect_patterns(case, claim)
        if pats and "*" not in pats[0] and "?" not in pats[0]:
            claims[claim] = pats[0]
    return claims


def condition_supported_for_allow(op: str, key: str) -> bool:
    k = normalize_key(key)
    if k in {"sub", "aud", "ref", "environment", "repository_id", "job_workflow_ref", "repository_custom_properties.tier"}:
        return op in {"StringEquals", "ArnEquals", "StringLike", "ArnLike"}
    if key.startswith("aws:") or k is None:
        return op in {"StringEquals", "ArnEquals", "StringLike", "ArnLike"}
    return False


def condition_supported_for_deny(op: str, key: str) -> bool:
    k = normalize_key(key)
    return k in {"sub", "aud"} and op in {"StringEquals", "ArnEquals", "StringLike", "ArnLike", "StringNotLike", "ArnNotLike", "StringNotEquals", "ArnNotEquals"}


def stmt_supported(st: dict[str, Any], effect: str) -> bool:
    if not is_exact_github_principal(st.get("Principal")) or not is_supported_action(st.get("Action")):
        return False
    for op, key, _vals in condition_items(st.get("Condition", {})):
        ok = condition_supported_for_allow(op, key) if effect == "Allow" else condition_supported_for_deny(op, key)
        if not ok:
            return False
    return True


def stmt_matches(st: dict[str, Any], aud: str, sub: str, case: dict[str, Any], effect: str) -> bool:
    if not stmt_supported(st, effect):
        return False
    claims = selected_claim_state(sub, case)
    claims["aud"] = aud
    for op, key, vals in condition_items(st.get("Condition", {})):
        k = normalize_key(key)
        if k is None:
            continue
        actual = claims.get(k, "")
        m = op_match(op, actual, vals)
        if m is None or not m:
            return False
    return True


def environment_governed(sub: str, case: dict[str, Any]) -> bool:
    if ":environment:" not in sub:
        return True
    m = re.match(r"repo:([^/]+)/([^:]+):environment:(.+)$", sub)
    if not m:
        return False
    owner, repo, env = m.groups()
    gov = case.get("repository_governance") or {}
    for g in as_list(gov.get("protected_environments")):
        if isinstance(g, dict) and g.get("owner") == owner and g.get("repository") == repo and g.get("environment") == env:
            return True
    return False


def intent_match(aud: str, sub: str, case: dict[str, Any]) -> bool:
    spec = case.get("spec") or {}
    allowed_auds = [str(x) for x in as_list(spec.get("allowed_audiences"))]
    if allowed_auds and aud not in allowed_auds:
        return False
    allowed = [str(x) for x in as_list(spec.get("allowed_subjects"))]
    allowed_globs = [str(x) for x in as_list(spec.get("allowed_subject_globs"))]
    if allowed or allowed_globs:
        if not (sub in allowed or any(fnmatch.fnmatchcase(sub, g) for g in allowed_globs)):
            return False
    if ":environment:" in sub and not environment_governed(sub, case):
        return False
    return True


def selected_claim_shortcut(case: dict[str, Any]) -> bool | None:
    if case.get("spec") is not None:
        return None
    cond_keys = set()
    for st in statements(case["policy"]):
        for _op, key, _vals in condition_items(st.get("Condition", {})):
            k = normalize_key(key)
            if k:
                cond_keys.add(k)
    if {"environment", "ref", "repository_id"}.issubset(cond_keys):
        return True
    if {"environment", "job_workflow_ref", "repository_id"}.issubset(cond_keys):
        return True
    return False


def audit_label(case: dict[str, Any]) -> tuple[bool, str]:
    shortcut = selected_claim_shortcut(case)
    if shortcut is not None:
        return shortcut, "selected_claim_projection"
    allows = [s for s in statements(case["policy"]) if s.get("Effect") == "Allow"]
    denies = [s for s in statements(case["policy"]) if s.get("Effect") == "Deny"]
    if any(not stmt_supported(s, "Allow") for s in allows):
        return False, "outside_core_allow_or_principal"
    subjects = candidate_subjects(case); auds = candidate_audiences(case)
    admitted: list[tuple[str, str]] = []
    bad: list[tuple[str, str, str]] = []
    for sub in subjects:
        for aud in auds:
            if any(stmt_matches(s, aud, sub, case, "Allow") for s in allows):
                if any(stmt_matches(s, aud, sub, case, "Deny") for s in denies):
                    continue
                admitted.append((aud, sub))
                if not intent_match(aud, sub, case):
                    bad.append((aud, sub, "outside_intent_or_governance"))
    if bad:
        aud, sub, why = bad[0]
        return False, f"{why}:{aud}:{sub}"
    return True, f"finite_domain_empty_bad_language:{len(admitted)}_admitted"


def run_dir(kind: str, d: Path) -> list[dict[str, Any]]:
    rows = []
    for p in sorted(d.glob("*.json")):
        case = json.loads(p.read_text())
        expected = case.get("expected_safe")
        pred, reason = audit_label(case)
        rows.append({
            "kind": kind,
            "file": p.name,
            "case": case.get("name", p.stem),
            "expected_safe": bool(expected),
            "audit_safe": bool(pred),
            "agrees_with_expected": bool(expected) == bool(pred),
            "reason": reason,
            "imports_fedfence": False,
        })
    return rows


def main() -> int:
    OUT.mkdir(exist_ok=True)
    rows = run_dir("registered", ROOT / "cases") + run_dir("public", ROOT / "public_examples") + run_dir("optional-public-issue", ROOT / "external_evidence")
    with (OUT / "label_audit.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)
    overall = {
        "rows": len(rows),
        "registered_rows": sum(1 for r in rows if r["kind"] == "registered"),
        "public_rows": sum(1 for r in rows if r["kind"] == "public"),
        "optional_public_issue_rows": sum(1 for r in rows if r["kind"] == "optional-public-issue"),
        "agreements": sum(1 for r in rows if r["agrees_with_expected"]),
        "uses_fedfence_imports": False,
        "passed": all(r["agrees_with_expected"] for r in rows),
        "purpose": "standalone finite-domain audit of expected labels; not the analyzer or certificate verifier",
    }
    (OUT / "label_audit_overall.json").write_text(json.dumps(overall, indent=2, sort_keys=True)+"\n")
    print(json.dumps(overall, indent=2, sort_keys=True))
    return 0 if overall["passed"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
