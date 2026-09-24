"""Analysis of source-backed public trust-policy changes.

This module deliberately distinguishes three notions:

* source-stated intent: a developer's commit message/tests/README say what the
  change was meant to restrict;
* FedFence outcome: pass/fail/unknown under the normalized packet encoded in the
  corpus record;
* owner confirmation: a separate signal that is NOT implied by a public commit.

The corpus is therefore evidence about real configuration changes and extractor
shapes, not a prevalence sample and not an independently adjudicated accuracy
benchmark.
"""
from __future__ import annotations

from dataclasses import asdict
from typing import Any, Mapping, Sequence
import hashlib

from .io import digest
from .conformance import check_required_tokens

# Import the frozen checker through the same isolated package path used elsewhere.
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "artifact"))
from fedfence.analyzer import analyze_case  # type: ignore  # noqa: E402
from fedfence.certificate import certificate_for_case, verify_certificate  # type: ignore  # noqa: E402


class CorpusError(ValueError):
    pass


def _strings(value: Any, field: str, *, nonempty: bool = True) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(x, str) or (nonempty and not x) for x in value):
        raise CorpusError(f"{field} must be a list of strings")
    return list(value)


def _policy(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    if set(snapshot) != {"operator", "subjects", "audience"}:
        raise CorpusError("policy snapshot requires operator, subjects, and audience")
    operator = snapshot["operator"]
    if operator not in {"StringEquals", "StringLike"}:
        raise CorpusError(f"unsupported corpus operator: {operator}")
    subjects = _strings(snapshot["subjects"], "subjects")
    if not subjects:
        raise CorpusError("at least one subject is required")
    audience = snapshot["audience"]
    if audience is not None and (not isinstance(audience, str) or not audience):
        raise CorpusError("audience must be a string or null")
    cond: dict[str, dict[str, Any]] = {operator: {"token.actions.githubusercontent.com:sub": subjects}}
    if audience is not None:
        cond.setdefault("StringEquals", {})["token.actions.githubusercontent.com:aud"] = audience
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Federated": "arn:aws:iam::000000000000:oidc-provider/token.actions.githubusercontent.com"},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": cond,
        }],
    }


def _spec(intent: Mapping[str, Any]) -> dict[str, Any]:
    allowed = {"subject_literals", "subject_globs", "audiences", "issuer_subjects"}
    if set(intent) - allowed:
        raise CorpusError("unknown intent field")
    literals = _strings(intent.get("subject_literals", []), "subject_literals")
    globs = _strings(intent.get("subject_globs", []), "subject_globs")
    audiences = _strings(intent.get("audiences", []), "audiences")
    if not literals and not globs:
        raise CorpusError("intent needs a literal or glob subject")
    if not audiences:
        raise CorpusError("intent needs at least one audience")
    spec: dict[str, Any] = {
        "allowed_subjects": literals,
        "allowed_subject_globs": globs,
        "allowed_audiences": audiences,
    }
    issuer_subjects = intent.get("issuer_subjects")
    if issuer_subjects is not None:
        spec["issuer_subjects"] = _strings(issuer_subjects, "issuer_subjects")
    return spec


def _baseline_presence(policy: Mapping[str, Any]) -> str:
    condition = policy["Statement"][0]["Condition"]
    values = [v for group in condition.values() for k, v in group.items() if k.endswith(":sub")]
    audiences = [v for group in condition.values() for k, v in group.items() if k.endswith(":aud")]
    return "pass" if values and audiences else "fail"


def _baseline_wildcard_ban(policy: Mapping[str, Any]) -> str:
    condition = policy["Statement"][0]["Condition"]
    vals: list[str] = []
    for group in condition.values():
        for key, value in group.items():
            if key.endswith(":sub"):
                vals.extend(value if isinstance(value, list) else [value])
    return "fail" if any("*" in value or "?" in value for value in vals) else "pass"


def _baseline_exact_ref(policy: Mapping[str, Any]) -> str:
    condition = policy["Statement"][0]["Condition"]
    vals: list[str] = []
    for group in condition.values():
        for key, value in group.items():
            if key.endswith(":sub"):
                vals.extend(value if isinstance(value, list) else [value])
    ok = vals and all(":ref:refs/heads/" in value and "*" not in value and "?" not in value for value in vals)
    return "pass" if ok else "fail"


def _verdict(case: Mapping[str, Any], required_tokens: Sequence[Mapping[str, str]]) -> dict[str, Any]:
    result = analyze_case(dict(case))
    cert = certificate_for_case(dict(case))
    replay_ok, replay_notes = verify_certificate(cert)
    findings = [asdict(item) for item in result.findings]
    conformance = check_required_tokens(case["policy"], case["spec"], required_tokens)
    for item in conformance["missing"]:
        findings.append({
            "kind": "required-token-not-admitted",
            "severity": "high",
            "message": item["reason"],
            "witness": f"sub={item['sub']}; aud={item['aud']}",
            "statement": None,
            "blocking": True,
        })
    for item in conformance["invalid"]:
        findings.append({
            "kind": "required-token-outside-contract-model",
            "severity": "medium",
            "message": item["reason"],
            "witness": f"sub={item['sub']}; aud={item['aud']}",
            "statement": None,
            "blocking": True,
        })
    has_overgrant = any(
        item.get("kind") in {"subject-overgrant", "audience-overgrant"} and item.get("witness")
        for item in findings
    )
    if not replay_ok:
        verdict = "unknown"
    elif has_overgrant or conformance["missing"]:
        verdict = "fail"
    elif conformance["invalid"]:
        verdict = "unknown"
    elif result.safe:
        verdict = "pass"
    else:
        verdict = "unknown"
    witnesses = [item["witness"] for item in findings if item.get("witness")]
    return {
        "verdict": verdict,
        "safe_boolean": result.safe,
        "findings": findings,
        "witnesses": witnesses,
        "required_token_checks": conformance,
        "certificate_verdict": cert.get("verdict"),
        "certificate_sha256": digest(cert),
        "replay_ok": bool(replay_ok),
        "replay_notes": replay_notes,
    }


def analyze_change(row: Mapping[str, Any]) -> dict[str, Any]:
    required = {"id", "repository", "commit", "url", "commit_message", "files", "source_snapshot", "source_sha256", "source_assertions", "intent_evidence", "change_kind", "intent", "required_tokens", "governance", "before", "after", "expected"}
    if set(row) != required:
        raise CorpusError(f"{row.get('id', '<unknown>')}: missing or unknown fields")
    if not all(isinstance(row.get(k), str) and row[k] for k in ("id", "repository", "commit", "url", "commit_message")):
        raise CorpusError("identifier/source fields must be nonempty strings")
    if not isinstance(row["files"], list) or not row["files"]:
        raise CorpusError("files must be a nonempty list")
    snapshot = row["source_snapshot"]
    source_sha = row["source_sha256"]
    assertions = row["source_assertions"]
    if not isinstance(snapshot, str) or not snapshot or Path(snapshot).is_absolute() or ".." in Path(snapshot).parts:
        raise CorpusError("source_snapshot must be a repository-relative path")
    source_path = ROOT / snapshot
    if not source_path.is_file():
        raise CorpusError(f"missing source snapshot: {snapshot}")
    raw_source = source_path.read_bytes()
    if hashlib.sha256(raw_source).hexdigest() != source_sha:
        raise CorpusError(f"source snapshot digest mismatch: {snapshot}")
    try:
        source_text = raw_source.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CorpusError(f"source snapshot is not UTF-8: {snapshot}") from exc
    if not isinstance(assertions, dict) or set(assertions) != {"removed", "added"}:
        raise CorpusError("source_assertions requires removed and added")
    for kind in ("removed", "added"):
        values = _strings(assertions[kind], f"source_assertions.{kind}")
        if not values:
            raise CorpusError(f"source_assertions.{kind} cannot be empty")
        for value in values:
            if value not in source_text:
                raise CorpusError(f"source assertion absent from {snapshot}: {value}")
    evidence = row["intent_evidence"]
    if not isinstance(evidence, dict) or evidence.get("provenance") != "developer-stated-public-commit":
        raise CorpusError("intent evidence must be developer-stated-public-commit")
    if evidence.get("owner_confirmed") is not False or evidence.get("independently_adjudicated") is not False:
        raise CorpusError("public commit evidence must not be promoted to owner-confirmed or independent ground truth")
    if row["change_kind"] not in {"security-hardening", "compatibility-repair", "cross-plane-hardening"}:
        raise CorpusError("invalid change_kind")
    required_tokens = row["required_tokens"]
    if not isinstance(required_tokens, list):
        raise CorpusError("required_tokens must be a list")
    seen_required = set()
    for index, token in enumerate(required_tokens):
        if not isinstance(token, dict) or set(token) != {"sub", "aud", "reason"}:
            raise CorpusError(f"required_tokens[{index}] needs sub, aud, and reason")
        if any(not isinstance(token[key], str) or not token[key] for key in ("sub", "aud", "reason")):
            raise CorpusError(f"required_tokens[{index}] fields must be nonempty strings")
        key = (token["sub"], token["aud"])
        if key in seen_required:
            raise CorpusError("duplicate required token")
        seen_required.add(key)
    expected = row["expected"]
    if not isinstance(expected, dict) or set(expected) != {"before", "after"}:
        raise CorpusError("expected requires before and after")
    if expected["before"] not in {"pass", "fail", "unknown"} or expected["after"] not in {"pass", "fail", "unknown"}:
        raise CorpusError("invalid expected verdict")
    governance = row["governance"]
    if not isinstance(governance, dict):
        raise CorpusError("governance must be an object")
    spec = _spec(row["intent"])
    outputs: dict[str, Any] = {}
    for phase in ("before", "after"):
        policy = _policy(row[phase])
        case = {
            "name": f"{row['id']}:{phase}",
            "policy": policy,
            "spec": spec,
            "repository_governance": governance,
        }
        analyzed = _verdict(case, required_tokens)
        analyzed["policy_sha256"] = digest(policy)
        analyzed["baselines"] = {
            "presence": _baseline_presence(policy),
            "wildcard_ban": _baseline_wildcard_ban(policy),
            "exact_ref_only": _baseline_exact_ref(policy),
        }
        analyzed["matches_source_stated_expectation"] = analyzed["verdict"] == expected[phase]
        outputs[phase] = analyzed
    return {
        "id": row["id"],
        "repository": row["repository"],
        "commit": row["commit"],
        "url": row["url"],
        "files": row["files"],
        "source_snapshot": snapshot,
        "source_sha256": source_sha,
        "source_snapshot_verified": True,
        "source_assertions": assertions,
        "intent_evidence": evidence,
        "change_kind": row["change_kind"],
        "required_tokens": required_tokens,
        "expected": expected,
        "before": outputs["before"],
        "after": outputs["after"],
        "transition": f"{outputs['before']['verdict']}->{outputs['after']['verdict']}",
        "source_alignment": outputs["before"]["matches_source_stated_expectation"] and outputs["after"]["matches_source_stated_expectation"],
        "claim_boundary": "source-backed change alignment, not prevalence, independent accuracy, or owner-confirmed vulnerability",
    }


def analyze_corpus(corpus: Mapping[str, Any]) -> dict[str, Any]:
    if corpus.get("schema") != "fedfence-public-change-corpus-v2":
        raise CorpusError("unexpected corpus schema")
    rows = corpus.get("changes")
    if not isinstance(rows, list) or not rows:
        raise CorpusError("corpus requires changes")
    selection = corpus.get("selection")
    required_selection = {"kind", "sampling_claim", "screening_manifest", "screening_sha256", "candidates_screened", "changes_included"}
    if not isinstance(selection, dict) or set(selection) != required_selection:
        raise CorpusError("selection metadata is incomplete")
    screening_path = selection["screening_manifest"]
    if not isinstance(screening_path, str) or Path(screening_path).is_absolute() or ".." in Path(screening_path).parts:
        raise CorpusError("invalid screening manifest path")
    screening_file = ROOT / screening_path
    if not screening_file.is_file() or hashlib.sha256(screening_file.read_bytes()).hexdigest() != selection["screening_sha256"]:
        raise CorpusError("screening manifest missing or digest mismatch")
    import json
    screening = json.loads(screening_file.read_text(encoding="utf-8"))
    if screening.get("schema") != "fedfence-public-change-screening-v1":
        raise CorpusError("unexpected screening manifest schema")
    ids = [row.get("id") for row in rows]
    screened_ids = [item.get("id") for item in screening.get("included", [])]
    if set(screened_ids) != set(ids) or selection["changes_included"] != len(rows):
        raise CorpusError("screening manifest and corpus disagree")
    if selection["candidates_screened"] != len(screening.get("included", [])) + len(screening.get("excluded", [])):
        raise CorpusError("screening candidate count mismatch")
    if len(ids) != len(set(ids)):
        raise CorpusError("duplicate change id")
    results = [analyze_change(row) for row in rows]
    transitions: dict[str, int] = {}
    for row in results:
        transitions[row["transition"]] = transitions.get(row["transition"], 0) + 1
    aligned = sum(bool(row["source_alignment"]) for row in results)
    snapshots_verified = sum(bool(row["source_snapshot_verified"]) for row in results)
    baseline_alignment: dict[str, dict[str, int]] = {}
    for baseline in ("presence", "wildcard_ban", "exact_ref_only"):
        baseline_aligned = 0
        baseline_total = 0
        for row in results:
            for phase in ("before", "after"):
                expected = row["expected"][phase]
                if expected not in {"pass", "fail"}:
                    continue
                baseline_total += 1
                baseline_aligned += int(row[phase]["baselines"][baseline] == expected)
        baseline_alignment[baseline] = {"aligned": baseline_aligned, "total": baseline_total}
    fedfence_phase_alignment = sum(
        int(row[phase]["verdict"] == row["expected"][phase])
        for row in results for phase in ("before", "after")
    )
    change_kinds: dict[str, int] = {}
    for row in results:
        change_kinds[row["change_kind"]] = change_kinds.get(row["change_kind"], 0) + 1
    required_total = sum(len(row["required_tokens"]) for row in results)
    required_satisfied_after = sum(row["after"]["required_token_checks"]["satisfied"] for row in results)
    return {
        "schema": "fedfence-public-change-results-v2",
        "selection": corpus.get("selection"),
        "changes": results,
        "summary": {
            "public_commits": len(results),
            "distinct_repositories": len({row["repository"] for row in results}),
            "source_aligned": aligned,
            "source_snapshots_verified": snapshots_verified,
            "transition_counts": transitions,
            "change_kinds": change_kinds,
            "required_tokens": {"declared": required_total, "satisfied_after": required_satisfied_after},
            "fedfence_phase_alignment": {"aligned": fedfence_phase_alignment, "total": 2 * len(results)},
            "baseline_alignment": baseline_alignment,
            "owner_confirmed": 0,
            "independently_adjudicated": 0,
            "prevalence_claim": False,
            "accuracy_claim": False,
            "interpretation": "alignment with explicit developer-stated hardening intent on a purposive public-change sample",
        },
    }
