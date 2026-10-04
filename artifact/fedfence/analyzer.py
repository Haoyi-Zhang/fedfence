"""FedFence checker for GitHub Actions OIDC trust policies.

The checker verifies a two-claim admission judgment for the supported AWS/GitHub
OIDC fragment.  It uses exact federated-principal recognition, provider-qualified
claim keys, a typed GitHub subject issuer grammar, repository-scoped governance,
and effective Allow-minus-Deny semantics for supported Deny statements.
"""
from __future__ import annotations

import json
from functools import lru_cache
from collections import deque
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None

from .github import github_default_subject_nfa, issuer_subject_nfa, github_alphabet_from_patterns, GITHUB_SUPPORT_LITERALS, governance_key, parse_github_subject, governance_set
from .policy import StatementConstraints, allow_statements_for_web_identity, deny_statements_for_web_identity
from .spec import subject_intent_parts, audience_intent_parts, intent_nfa, intent_alphabet_inputs
from .regular import (
    DEFAULT_ALPHABET,
    NFA,
    validate_support,
    contains_witness,
    empty,
    intersect,
    intersection_globs,
    intersection_typed_groups,
    union,
    union_globs,
)

# Documentation-facing default forms.  The implementation does not use these as
# the default issuer automaton; it uses github_subject.default_github_subject_nfa,
# which is delimiter-aware.  They remain useful for compact certificates and for
# custom tests that intentionally use glob issuer templates.
ANY_GITHUB_SUBJECT = [
    "repo:?*/?*:ref:refs/heads/?*",
    "repo:?*/?*:ref:refs/tags/?*",
    "repo:?*/?*:pull_request",
    "repo:?*/?*:environment:?*",
]
ANY_GITHUB_AUDIENCE = ["?*"]

@lru_cache(maxsize=8)
def _default_github_subject_cached(alphabet_tuple: Tuple[str, ...]) -> NFA:
    return github_default_subject_nfa(alphabet_tuple)

@dataclass
class Finding:
    kind: str
    severity: str
    message: str
    witness: Optional[str] = None
    statement: Optional[int] = None
    blocking: bool = True

@dataclass
class AnalysisResult:
    name: str
    safe: bool
    findings: List[Finding]
    allow_subject_states: int = 0
    intended_subject_states: int = 0
    allow_subject_edges: int = 0
    intended_subject_edges: int = 0

@dataclass
class DenyRect:
    statement: int
    sub: NFA
    aud: NFA


def load_case(path: Path) -> Dict[str, Any]:
    text = path.read_text()
    if path.suffix.lower() in {".yaml", ".yml"}:
        if yaml is None:
            raise RuntimeError("PyYAML is required for YAML cases")
        return yaml.safe_load(text)
    return json.loads(text)


def _claim_nfa_from_statement(st: StatementConstraints, claim: str, alphabet: Sequence[str], default: NFA) -> NFA:
    groups = st.typed_groups_for(claim)
    return intersection_typed_groups(groups, alphabet) if groups else default


def _claim_nfa_optional(st: StatementConstraints, claim: str, alphabet: Sequence[str]) -> Optional[NFA]:
    groups = st.typed_groups_for(claim)
    return intersection_typed_groups(groups, alphabet) if groups else None


def _state_accepts(nfa: NFA, state) -> bool:
    return any(s in nfa.finals for s in state)


def _difference_member(base: NFA, blockers: Sequence[NFA], alphabet: Sequence[str]) -> Optional[str]:
    blocked = union(list(blockers), alphabet) if blockers else empty(alphabet)
    return contains_witness(base, blocked, alphabet)


def _find_subject_bad(issuer_sub: NFA, allow_sub: NFA, intent_sub: NFA,
                      aud_base: NFA, denies: Sequence[DenyRect],
                      alphabet: Sequence[str], max_states: int = 300000) -> Optional[Tuple[str, str]]:
    start = (issuer_sub.epsilon_closure({issuer_sub.start}),
             allow_sub.epsilon_closure({allow_sub.start}),
             intent_sub.epsilon_closure({intent_sub.start}),
             tuple(d.sub.epsilon_closure({d.sub.start}) for d in denies))
    q = deque([(start, "")])
    seen = {start}
    while q:
        (gi, pa, ii, dss), word = q.popleft()
        if _state_accepts(issuer_sub, gi) and _state_accepts(allow_sub, pa) and not _state_accepts(intent_sub, ii):
            blockers = [denies[k].aud for k, ds in enumerate(dss) if _state_accepts(denies[k].sub, ds)]
            aw = _difference_member(aud_base, blockers, alphabet)
            if aw is not None:
                return word, aw
        if len(seen) > max_states:
            raise RuntimeError("subject pair search exceeded determinized state budget")
        for ch in alphabet:
            gi1 = issuer_sub.step(gi, ch)
            pa1 = allow_sub.step(pa, ch)
            if not gi1 or not pa1:
                continue
            ii1 = intent_sub.step(ii, ch) if ii else frozenset()
            dss1 = tuple(d.sub.step(ds, ch) if ds else frozenset() for d, ds in zip(denies, dss))
            key = (gi1, pa1, ii1, dss1)
            if key not in seen:
                seen.add(key)
                q.append((key, word + ch))
    return None


def _find_audience_bad(issuer_aud: NFA, allow_aud: NFA, intent_aud: NFA,
                       sub_base: NFA, denies: Sequence[DenyRect],
                       alphabet: Sequence[str], max_states: int = 300000) -> Optional[Tuple[str, str]]:
    start = (issuer_aud.epsilon_closure({issuer_aud.start}),
             allow_aud.epsilon_closure({allow_aud.start}),
             intent_aud.epsilon_closure({intent_aud.start}),
             tuple(d.aud.epsilon_closure({d.aud.start}) for d in denies))
    q = deque([(start, "")])
    seen = {start}
    while q:
        (gi, pa, ii, das), aud = q.popleft()
        if _state_accepts(issuer_aud, gi) and _state_accepts(allow_aud, pa) and not _state_accepts(intent_aud, ii):
            blockers = [denies[k].sub for k, da in enumerate(das) if _state_accepts(denies[k].aud, da)]
            sw = _difference_member(sub_base, blockers, alphabet)
            if sw is not None:
                return sw, aud
        if len(seen) > max_states:
            raise RuntimeError("audience pair search exceeded determinized state budget")
        for ch in alphabet:
            gi1 = issuer_aud.step(gi, ch)
            pa1 = allow_aud.step(pa, ch)
            if not gi1 or not pa1:
                continue
            ii1 = intent_aud.step(ii, ch) if ii else frozenset()
            das1 = tuple(d.aud.step(da, ch) if da else frozenset() for d, da in zip(denies, das))
            key = (gi1, pa1, ii1, das1)
            if key not in seen:
                seen.add(key)
                q.append((key, aud + ch))
    return None



def _candidate_subjects(patterns: Sequence[str]) -> List[str]:
    out: List[str] = []
    for pat in patterns:
        if pat.endswith(":*"):
            out.extend([pat[:-1] + "pull_request", pat[:-1] + "environment:stage"])
        if ":ref:refs/heads/*" in pat:
            out.append(pat.replace("*", "feature-x"))
        if ":ref:refs/heads/?*" in pat:
            out.append(pat.replace("?*", "feature-x"))
        if ":ref:refs/tags/*" in pat:
            out.append(pat.replace("*", "v0"))
        if "repo:*/*:" in pat:
            out.append(pat.replace("*", "evil", 1).replace("*", "repo", 1))
        if "repo:?*/?*:" in pat:
            out.append(pat.replace("?*", "evil", 1).replace("?*", "repo", 1))
        if "/*:" in pat:
            out.append(pat.replace("*", "other"))
    seen: set[str] = set(); res: List[str] = []
    for x in out:
        if x not in seen:
            seen.add(x); res.append(x)
    return res


def _fast_subject_bad(candidates: Sequence[str], issuer_sub: NFA, allow_sub: NFA, intent_sub: NFA,
                      aud_base: NFA, denies: Sequence[DenyRect], alphabet: Sequence[str]) -> Optional[Tuple[str, str]]:
    for sw in candidates:
        if issuer_sub.accepts(sw) and allow_sub.accepts(sw) and not intent_sub.accepts(sw):
            blockers = [d.aud for d in denies if d.sub.accepts(sw)]
            aw = _difference_member(aud_base, blockers, alphabet)
            if aw is not None:
                return sw, aw
    return None


def _fast_audience_bad(candidates: Sequence[str], issuer_aud: NFA, allow_aud: NFA, intent_aud: NFA,
                       sub_base: NFA, denies: Sequence[DenyRect], alphabet: Sequence[str]) -> Optional[Tuple[str, str]]:
    for aw in candidates:
        if issuer_aud.accepts(aw) and allow_aud.accepts(aw) and not intent_aud.accepts(aw):
            blockers = [d.sub for d in denies if d.aud.accepts(aw)]
            sw = _difference_member(sub_base, blockers, alphabet)
            if sw is not None:
                return sw, aw
    return None

def _protected_keys(gov: Mapping[str, Any]) -> set[str]:
    """Normalize repository-scoped governance facts.

    Legacy unscoped environment names are intentionally not accepted as proof
    facts.  The only positive facts are owner/repository/environment triples or
    exact environment subject literals from which such a triple can be parsed.
    """
    out: set[str] = set()
    raw = gov.get("protected_environments", []) or []
    for owner, repo, env in governance_set(raw):
        out.add(governance_key(owner, repo, env))
    by_repo = gov.get("protected_environments_by_repo", {}) or {}
    if isinstance(by_repo, Mapping):
        for repo_text, envs in by_repo.items():
            vals = envs if isinstance(envs, list) else [envs]
            if "/" not in str(repo_text):
                continue
            owner, repo = str(repo_text).split("/", 1)
            for env in vals:
                if owner and repo and str(env):
                    out.add(governance_key(owner, repo, str(env)))
    return out


def _environment_governance_findings(patterns: Iterable[str], protected: set[str], idx: int) -> List[Finding]:
    out: List[Finding] = []
    for pat in patterns:
        if ":environment:" not in pat:
            continue
        parsed = parse_github_subject(pat)
        if parsed is None or parsed.kind != "environment" or not parsed.environment:
            out.append(Finding(
                kind="environment-wildcard", severity="high", statement=idx,
                message="Environment subject is not a single typed repository-scoped environment.",
                witness=pat.replace("*", "prod").replace("?", "p")))
            continue
        key = governance_key(parsed.owner, parsed.repository, parsed.environment)
        if key not in protected:
            out.append(Finding(
                kind="unprotected-environment", severity="high", statement=idx,
                message="Environment subject requires a repository-scoped protected-environment governance fact.",
                witness=f"sub={pat}; governance={key}"))
    return out


def _statement_boundary_findings(st: StatementConstraints, idx: int, effect: str = "Allow") -> List[Finding]:
    out: List[Finding] = []
    prefix = effect.lower()
    if st.unsupported_conditions:
        out.append(Finding(kind=f"unsupported-{prefix}-condition", severity="medium", statement=idx,
                           message=f"{effect} statement contains unsupported condition operators.  For Allow, FedFence erases them as monotone restrictions and proves the over-approximation.",
                           blocking=(effect.lower() != "allow")))
    if st.unsupported_claim_keys:
        out.append(Finding(kind=f"unsupported-{prefix}-claim-key", severity="high", statement=idx,
                           message=f"{effect} statement contains unqualified or unsupported claim keys.  For Allow, FedFence erases them and proves the over-approximation.",
                           blocking=(effect.lower() != "allow")))
    if st.unsupported_statement_fields:
        out.append(Finding(kind=f"unsupported-{prefix}-statement-field", severity="medium", statement=idx,
                           message=f"{effect} statement uses IAM fields outside the proof-carrying core: {sorted(set(st.unsupported_statement_fields))}."))
    if st.principal_wildcard:
        out.append(Finding(kind=f"wildcard-{prefix}-federated-principal", severity="high", statement=idx,
                           message="Federated principal is wildcarded and cannot be certified for one GitHub issuer."))
    elif st.mixed_principal:
        out.append(Finding(kind=f"mixed-{prefix}-principal", severity="high", statement=idx,
                           message="Statement mixes GitHub with another principal family or more than one federated provider."))
    elif st.unsupported_principal or st.malformed_principal or not st.exact_github_oidc_principal:
        out.append(Finding(kind=f"non-github-{prefix}-oidc-principal", severity="high", statement=idx,
                           message="Statement does not name exactly the GitHub Actions OIDC provider as its federated principal."))
    return out


def analyze_case(case: Mapping[str, Any]) -> AnalysisResult:
    name = str(case.get("name", "unnamed"))
    if isinstance(case.get("states"), list):
        from .event import analyze_event_case
        ev = analyze_event_case(case)
        findings = [Finding(kind=f.kind, severity="high", message=f.message,
                            witness=(json.dumps(f.witness_claims, sort_keys=True) if f.witness_claims else f.state),
                            blocking=True)
                    for f in ev.findings]
        return AnalysisResult(name=name, safe=ev.safe, findings=findings,
                              allow_subject_states=ev.states, intended_subject_states=ev.intended_admitted,
                              allow_subject_edges=ev.admitted, intended_subject_edges=len(ev.findings))
    policy = case.get("policy", {}) or {}
    spec = case.get("spec", {}) or {}
    intended_sub_lits, intended_sub_globs = subject_intent_parts(spec)
    intended_aud_lits, intended_aud_globs = audience_intent_parts(spec)
    issuer_sub_spec = spec.get("issuer_subjects")
    issuer_aud = list(spec.get("issuer_audiences", ANY_GITHUB_AUDIENCE) or ANY_GITHUB_AUDIENCE)
    protected_envs = _protected_keys(case.get("repository_governance", {}) or {})
    findings: List[Finding] = []
    total_allow_states = total_allow_edges = total_int_states = total_int_edges = 0

    stmts = allow_statements_for_web_identity(policy)
    deny_stmts = deny_statements_for_web_identity(policy)
    if not stmts:
        return AnalysisResult(name=name, safe=False, findings=[Finding(
            kind="no-web-identity-allow", severity="high",
            message="No Allow statement for sts:AssumeRoleWithWebIdentity was found in the supported fragment.")])

    alphabet_inputs: List[Any] = [ANY_GITHUB_SUBJECT, issuer_sub_spec or [], issuer_aud] + intent_alphabet_inputs(spec)
    for st in list(stmts) + list(deny_stmts):
        alphabet_inputs.extend(st.typed_groups_for("sub"))
        alphabet_inputs.extend(st.typed_groups_for("aud"))
    alphabet = github_alphabet_from_patterns(alphabet_inputs)
    covered, reason = validate_support(alphabet, ("equals", GITHUB_SUPPORT_LITERALS), alphabet_inputs)
    if not covered:
        raise ValueError("incomplete analysis character support: " + reason)

    issuer_sub_nfa = issuer_subject_nfa(list(issuer_sub_spec or []), alphabet)
    issuer_aud_nfa = union_globs(issuer_aud, alphabet)
    intended_sub_nfa = intent_nfa(intended_sub_lits, intended_sub_globs, alphabet) if (intended_sub_lits or intended_sub_globs) else None
    intended_aud_nfa = intent_nfa(intended_aud_lits, intended_aud_globs, alphabet) if (intended_aud_lits or intended_aud_globs) else None

    # Supported Deny statements are used to form effective admission language.
    # Unsupported Deny statements are ignored for positive safety (Deny cannot add
    # authority) but also cannot be used to discharge an unsafe Allow witness.
    deny_rects: List[DenyRect] = []
    for didx, dst in enumerate(deny_stmts):
        if dst.deny_exact_core:
            d_sub = _claim_nfa_from_statement(dst, "sub", alphabet, issuer_sub_nfa)
            d_aud = _claim_nfa_from_statement(dst, "aud", alphabet, issuer_aud_nfa)
            deny_rects.append(DenyRect(didx, d_sub, d_aud))

    for idx, st in enumerate(stmts):
        boundary = _statement_boundary_findings(st, idx, "Allow")
        findings.extend(boundary)
        if not st.allow_overapprox_core:
            # Unsupported principal/action structure cannot be safely projected
            # into the GitHub OIDC claim calculus.  Unsupported Allow conditions,
            # however, are monotone restrictions and are handled by erasure.
            continue

        sub_patterns = st.patterns_for("sub")
        aud_patterns = st.patterns_for("aud")
        sub_nfa_opt = _claim_nfa_optional(st, "sub", alphabet)
        aud_nfa_opt = _claim_nfa_optional(st, "aud", alphabet)
        allow_sub_nfa = sub_nfa_opt if sub_nfa_opt is not None else issuer_sub_nfa
        allow_aud_nfa = aud_nfa_opt if aud_nfa_opt is not None else issuer_aud_nfa

        if sub_nfa_opt is None:
            findings.append(Finding(kind="missing-sub", severity="high", statement=idx,
                                    message="Allow statement has no provider-qualified GitHub subject condition; it is not a positive proof by itself, and safety is decided on the issuer over-approximation.", blocking=False))
        if aud_nfa_opt is None:
            findings.append(Finding(kind="missing-aud", severity="medium", statement=idx,
                                    message="Allow statement has no provider-qualified audience condition; safety is decided on issuer audiences.", blocking=False))
        if intended_sub_nfa is None:
            findings.append(Finding(kind="missing-intent", severity="medium", statement=idx,
                                    message="No intended subject language was supplied."))
            continue
        if intended_aud_nfa is None:
            findings.append(Finding(kind="missing-audience-intent", severity="medium", statement=idx,
                                    message="No intended audience language was supplied."))
            continue

        admitted_sub_base = intersect(issuer_sub_nfa, allow_sub_nfa, alphabet)
        admitted_aud_base = intersect(issuer_aud_nfa, allow_aud_nfa, alphabet)
        total_allow_states += allow_sub_nfa.size[0]
        total_allow_edges += allow_sub_nfa.size[1]
        total_int_states += intended_sub_nfa.size[0]
        total_int_edges += intended_sub_nfa.size[1]

        sub_groups = st.groups_for("sub")
        aud_groups = st.groups_for("aud")
        # Fast path: only exact policy groups that are syntactically included in
        # exact intent literals can skip BFS.  Glob groups and glob intents still
        # go through the automata check, which preserves literal * and ? soundly.
        exact_intended_sub = set(intended_sub_lits)
        exact_intended_aud = set(intended_aud_lits)
        sub_tgroups = st.typed_groups_for("sub")
        aud_tgroups = st.typed_groups_for("aud")
        sub_subset_safe = bool(sub_tgroups) and all(op == "equals" and set(vals).issubset(exact_intended_sub) for op, vals in sub_tgroups)
        aud_subset_safe = bool(aud_tgroups) and all(op == "equals" and set(vals).issubset(exact_intended_aud) for op, vals in aud_tgroups)

        if not sub_subset_safe:
            sub_bad = _find_subject_bad(issuer_sub_nfa, allow_sub_nfa, intended_sub_nfa,
                                        admitted_aud_base, deny_rects, alphabet)
            if sub_bad is not None:
                sw, aw = sub_bad
                findings.append(Finding(kind="subject-overgrant", severity="high", statement=idx,
                                        message="Effective policy admits an issuer-mintable subject outside intent.",
                                        witness=f"sub={sw}; aud={aw}"))

        if not aud_subset_safe:
            aud_candidates = ["unexpected-service", "sigstore", "vault", "z"]
            for p in aud_patterns:
                if "*" in p or "?" in p:
                    aud_candidates.append(p.replace("*", "unexpected-service").replace("?", "x"))
            aud_bad = _find_audience_bad(issuer_aud_nfa, allow_aud_nfa, intended_aud_nfa,
                                         admitted_sub_base, deny_rects, alphabet)
            if aud_bad is not None:
                sw, aw = aud_bad
                findings.append(Finding(kind="audience-overgrant", severity="medium", statement=idx,
                                        message="Effective policy admits an issuer-mintable audience outside intent.",
                                        witness=f"sub={sw}; aud={aw}"))

        findings.extend(_environment_governance_findings(sub_patterns, protected_envs, idx))

    return AnalysisResult(name=name, safe=not any(f.blocking for f in findings), findings=findings,
                          allow_subject_states=total_allow_states,
                          intended_subject_states=total_int_states,
                          allow_subject_edges=total_allow_edges,
                          intended_subject_edges=total_int_edges)


def result_to_json(result: AnalysisResult) -> str:
    return json.dumps(asdict(result), indent=2, sort_keys=True)
