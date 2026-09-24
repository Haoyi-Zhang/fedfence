"""Finite event-space checker for claim-projection refinements.

This module complements the infinite regular-language subject/audience checker.
When a provider exposes additional claims such as ref, environment, repository,
or job_workflow_ref, the safest semantics is over workflow events: evaluate the
trust predicate on each issuer-mintable event and check that every admitted event
satisfies the declared intent.  The finite model is also the executable witness
format for projection-definability experiments.
"""
from __future__ import annotations
from dataclasses import dataclass, asdict
from fnmatch import fnmatchcase
from typing import Any, Mapping, Sequence

from .policy import AWS_GITHUB_PRINCIPAL_RE, GITHUB_PREFIX

WEB_IDENTITY = "sts:assumerolewithwebidentity"
SUPPORTED_OPS = {"stringequals", "arnequals", "stringlike", "arnlike"}

@dataclass
class EventFinding:
    kind: str
    message: str
    state: str | None = None
    witness_claims: dict[str, str] | None = None

@dataclass
class EventResult:
    name: str
    safe: bool
    findings: list[EventFinding]
    states: int
    admitted: int
    intended_admitted: int


def _as_list(x: Any) -> list[str]:
    if x is None:
        return []
    if isinstance(x, list):
        return [str(v) for v in x]
    return [str(x)]


def _actions(st: Mapping[str, Any]) -> list[str]:
    return [x.lower() for x in _as_list(st.get("Action"))]


def _principal_ok(st: Mapping[str, Any]) -> bool:
    p = st.get("Principal")
    if not isinstance(p, Mapping):
        return False
    fed = p.get("Federated")
    vals = _as_list(fed)
    return len(vals) == 1 and AWS_GITHUB_PRINCIPAL_RE.match(vals[0]) is not None


def _normalize_key(raw: str) -> str | None:
    raw = str(raw)
    if not raw.startswith(GITHUB_PREFIX):
        return None
    claim = raw[len(GITHUB_PREFIX):]
    return claim if claim else None


def _op_name(op: str) -> str | None:
    parts = str(op).split(":")
    if len(parts) > 1 and parts[0].lower() in {"forallvalues", "foranyvalue"}:
        return None
    suffix = parts[-1].lower()
    if suffix.endswith("ifexists"):
        return None
    return suffix if suffix in SUPPORTED_OPS else None


def _match_value(op: str, claim_value: str, vals: Sequence[str]) -> bool:
    if op in {"stringequals", "arnequals"}:
        return any(claim_value == v for v in vals)
    return any(fnmatchcase(claim_value, v) for v in vals)


def _statement_matches(st: Mapping[str, Any], claims: Mapping[str, str]) -> tuple[bool, str | None]:
    if not _principal_ok(st):
        return False, "principal"
    acts = _actions(st)
    if acts != [WEB_IDENTITY]:
        return False, "action"
    cond = st.get("Condition", {}) or {}
    if not isinstance(cond, Mapping):
        return False, "condition"
    for op_raw, kv in cond.items():
        op = _op_name(str(op_raw))
        if op is None or not isinstance(kv, Mapping):
            return False, f"operator:{op_raw}"
        for raw_key, raw_vals in kv.items():
            key = _normalize_key(str(raw_key))
            if key is None:
                return False, f"key:{raw_key}"
            if not _match_value(op, str(claims.get(key, "")), _as_list(raw_vals)):
                return False, None
    return True, None


def _statements(policy: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    s = policy.get("Statement", [])
    if isinstance(s, Mapping):
        return [s]
    return [x for x in s if isinstance(x, Mapping)]


def analyze_event_case(case: Mapping[str, Any]) -> EventResult:
    name = str(case.get("name", "event-case"))
    policy = case.get("policy", {}) or {}
    states = case.get("states", []) or []
    findings: list[EventFinding] = []
    admitted = 0
    intended_admitted = 0
    unsupported: set[str] = set()
    for i, state in enumerate(states):
        if not bool(state.get("mintable", True)):
            continue
        claims = {str(k): str(v) for k, v in (state.get("claims", {}) or {}).items()}
        sid = str(state.get("id", f"s{i}"))
        allowed = False
        denied = False
        for st in _statements(policy):
            ok, reason = _statement_matches(st, claims)
            if reason:
                unsupported.add(reason)
            if ok and str(st.get("Effect", "Allow")).lower() == "allow":
                allowed = True
            if ok and str(st.get("Effect", "Allow")).lower() == "deny":
                denied = True
        if allowed and not denied:
            admitted += 1
            if bool(state.get("intended", False)):
                intended_admitted += 1
            else:
                findings.append(EventFinding(
                    kind="event-overgrant",
                    message="A mintable workflow event satisfies the effective trust predicate but is outside intent.",
                    state=sid,
                    witness_claims=dict(claims),
                ))
    for reason in sorted(unsupported):
        findings.append(EventFinding(kind="event-outside-core", message=f"unsupported finite-event condition boundary: {reason}"))
    return EventResult(name=name, safe=(not findings), findings=findings, states=len(states), admitted=admitted, intended_admitted=intended_admitted)


def result_dict(res: EventResult) -> dict[str, Any]:
    d = asdict(res)
    d["finding_kinds"] = [f.kind for f in res.findings]
    return d
