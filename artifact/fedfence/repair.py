"""Repair synthesis for the FedFence policy fragment."""
from __future__ import annotations
from copy import deepcopy
from typing import Any, Dict, Iterable, List, Mapping, Tuple
from .analyzer import analyze_case
from .github import parse_github_subject
from .spec import subject_intent_parts, audience_intent_parts
PREFIX = "token.actions.githubusercontent.com:"

def _as_list(x: Any) -> List[str]:
    if x is None:
        return []
    if isinstance(x, list):
        return [str(v) for v in x]
    return [str(x)]

def environment_facts(subjects: Iterable[str]) -> List[Dict[str, str]]:
    """Repository-scoped governance facts needed by exact environment intents."""
    out: List[Dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for s in subjects:
        atom = parse_github_subject(str(s))
        if atom is None or atom.kind != "environment" or not atom.environment:
            continue
        key = (atom.owner, atom.repository, atom.environment)
        if key not in seen:
            seen.add(key)
            out.append({"owner": atom.owner, "repository": atom.repository, "environment": atom.environment})
    return out

def _fact_key(x: Any) -> tuple[str, str, str] | None:
    if isinstance(x, dict):
        owner = str(x.get("owner", x.get("org", "")))
        repo = str(x.get("repository", x.get("repo", "")))
        env = str(x.get("environment", x.get("env", "")))
        return (owner, repo, env) if owner and repo and env else None
    atom = parse_github_subject(str(x))
    if atom is not None and atom.kind == "environment" and atom.environment:
        return (atom.owner, atom.repository, atom.environment)
    if ":" in str(x) and "/" in str(x).split(":", 1)[0]:
        left, env = str(x).split(":", 1)
        owner, repo = left.split("/", 1)
        return (owner, repo, env) if owner and repo and env else None
    return None

def _one_or_many(xs: List[str]) -> Any:
    return xs[0] if len(xs) == 1 else xs

def canonical_policy(subject_literals: List[str], audience_literals: List[str],
                     subject_globs: List[str] | None = None, audience_globs: List[str] | None = None) -> Dict[str, Any]:
    subject_globs = subject_globs or []
    audience_globs = audience_globs or []
    cond: Dict[str, Dict[str, Any]] = {}
    eq: Dict[str, Any] = {}
    like: Dict[str, Any] = {}
    if subject_literals:
        eq[PREFIX + "sub"] = _one_or_many(subject_literals)
    if audience_literals:
        eq[PREFIX + "aud"] = _one_or_many(audience_literals)
    if subject_globs:
        like[PREFIX + "sub"] = _one_or_many(subject_globs)
    if audience_globs:
        like[PREFIX + "aud"] = _one_or_many(audience_globs)
    if eq:
        cond["StringEquals"] = eq
    if like:
        cond["StringLike"] = like
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Federated": "arn:aws:iam::000000000000:oidc-provider/token.actions.githubusercontent.com"},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": cond,
        }],
    }

def synthesize_repair(case: Mapping[str, Any], add_governance: bool = False) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    spec = dict(case.get("spec", {}) or {})
    subjects, subject_globs = subject_intent_parts(spec)
    audiences, audience_globs = audience_intent_parts(spec)
    repaired = deepcopy(dict(case))
    repaired["policy"] = canonical_policy(subjects, audiences, subject_globs, audience_globs)
    repaired["spec"] = spec
    gov = deepcopy(dict(case.get("repository_governance", {}) or {}))
    envs = environment_facts(subjects)
    existing_raw = _as_list(gov.get("protected_environments"))
    existing = {k for k in (_fact_key(x) for x in existing_raw) if k is not None}
    added: List[Dict[str, str]] = []
    if add_governance:
        merged = [x for x in gov.get("protected_environments", [])] if isinstance(gov.get("protected_environments", []), list) else existing_raw
        for fact in envs:
            key = (fact["owner"], fact["repository"], fact["environment"])
            if key not in existing:
                added.append(fact)
                merged.append(fact)
                existing.add(key)
        gov["protected_environments"] = merged
    repaired["repository_governance"] = gov
    meta = {
        "kind": "intent-exact-repair",
        "subject_count": len(subjects),
        "audience_count": len(audiences),
        "environment_governance_required": [f"{f["owner"]}/{f["repository"]}:{f["environment"]}" for f in envs if (f["owner"], f["repository"], f["environment"]) not in {k for k in (_fact_key(x) for x in _as_list((case.get("repository_governance", {}) or {}).get("protected_environments"))) if k is not None}],
        "environment_governance_added": added,
        "policy_language": "finite intent basis",
    }
    return repaired, meta

def repair_outcome(case: Mapping[str, Any]) -> Dict[str, Any]:
    original = analyze_case(case)
    policy_repair, policy_meta = synthesize_repair(case, add_governance=False)
    policy_res = analyze_case(policy_repair)
    gov_repair, gov_meta = synthesize_repair(case, add_governance=True)
    gov_res = analyze_case(gov_repair)
    return {
        "name": str(case.get("name", "unnamed")),
        "original_safe": bool(original.safe),
        "original_findings": [f.kind for f in original.findings],
        "policy_repair_safe": bool(policy_res.safe),
        "policy_repair_findings": [f.kind for f in policy_res.findings],
        "governance_repair_safe": bool(gov_res.safe),
        "governance_repair_findings": [f.kind for f in gov_res.findings],
        "policy_meta": policy_meta,
        "governance_meta": gov_meta,
    }
