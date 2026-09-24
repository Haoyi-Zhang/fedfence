"""Proof-carrying certificates for FedFence containment judgments.

Unsafe certificates store a concrete claim witness.  Safe certificates store an
inductive invariant over the reachable states of the determinized product
automaton.  A verifier reconstructs the NFAs from the public patterns, checks
that the invariant contains the initial product state, is closed under all
alphabet transitions, and contains no bad accepting product state.
"""
from __future__ import annotations

from collections import deque
from typing import Any, Dict, FrozenSet, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

from .regular import DEFAULT_ALPHABET, NFA, alphabet_from_patterns, union_globs, union_literals, intersection_globs, intersection_typed_groups, contains_witness, intersect, union, empty
from .spec import subject_intent_parts, audience_intent_parts, intent_nfa, intent_alphabet_inputs, subject_intent_display, audience_intent_display
from .github import github_default_subject_nfa as default_github_subject_nfa, issuer_subject_nfa, parse_github_subject, governance_set, governance_key

State = FrozenSet[int]
Triple = Tuple[State, State, State]
Pair = Tuple[State, State]


def _canonical_group(g: Any) -> Tuple[str, List[str]]:
    """Decode old list groups and new operator-tagged groups."""
    if isinstance(g, Mapping):
        op = str(g.get("op", "like"))
        vals = [str(v) for v in g.get("values", [])]
        return ("equals" if op == "equals" else "like", vals)
    if isinstance(g, tuple) and len(g) == 2 and str(g[0]) in {"equals", "like"}:
        return (str(g[0]), [str(v) for v in g[1]])
    return ("like", [str(v) for v in g])


def _encode_group(g: Any) -> Dict[str, Any]:
    op, vals = _canonical_group(g)
    return {"op": op, "values": vals}


def _nfa_from_groups(groups: Sequence[Any], alphabet: Sequence[str]) -> NFA:
    if not groups:
        return union_globs(["*"], alphabet)
    typed = [_canonical_group(g) for g in groups]
    return intersection_typed_groups(typed, alphabet)


def _cert_alphabet(*parts: Any) -> Tuple[str, ...]:
    return alphabet_from_patterns(parts)


def _enc_state(s: State) -> List[int]:
    return sorted(int(x) for x in s)


def _dec_state(xs: Iterable[int]) -> State:
    return frozenset(int(x) for x in xs)


def _bad_triple(g: State, p: State, i: State, ng: NFA, np: NFA, ni: NFA) -> bool:
    return (any(x in ng.finals for x in g)
            and any(x in np.finals for x in p)
            and not any(x in ni.finals for x in i))


def _bad_pair(a: State, b: State, na: NFA, nb: NFA) -> bool:
    return any(x in na.finals for x in a) and not any(x in nb.finals for x in b)


def _triple_witness(ng: NFA, np: NFA, ni: NFA, alphabet: Sequence[str]) -> Optional[str]:
    alph = tuple(alphabet)
    start = (ng.epsilon_closure({ng.start}), np.epsilon_closure({np.start}), ni.epsilon_closure({ni.start}))
    q = deque([(start, "")])
    seen = {start}
    while q:
        (g, p, i), w = q.popleft()
        if _bad_triple(g, p, i, ng, np, ni):
            return w
        for ch in alph:
            g1, p1 = ng.step(g, ch), np.step(p, ch)
            if not g1 or not p1:
                continue
            i1 = ni.step(i, ch) if i else frozenset()
            st = (g1, p1, i1)
            if st not in seen:
                seen.add(st)
                q.append((st, w + ch))
    return None


def _reachable_triples(ng: NFA, np: NFA, ni: NFA, alphabet: Sequence[str]) -> List[Triple]:
    alph = tuple(alphabet)
    start = (ng.epsilon_closure({ng.start}), np.epsilon_closure({np.start}), ni.epsilon_closure({ni.start}))
    q = deque([start])
    seen = {start}
    while q:
        g, p, i = q.popleft()
        for ch in alph:
            g1, p1 = ng.step(g, ch), np.step(p, ch)
            if not g1 or not p1:
                continue
            i1 = ni.step(i, ch) if i else frozenset()
            st = (g1, p1, i1)
            if st not in seen:
                seen.add(st)
                q.append(st)
    return sorted(seen, key=lambda t: (_enc_state(t[0]), _enc_state(t[1]), _enc_state(t[2])))


def _reachable_pairs(na: NFA, nb: NFA, alphabet: Sequence[str]) -> List[Pair]:
    alph = tuple(alphabet)
    start = (na.epsilon_closure({na.start}), nb.epsilon_closure({nb.start}))
    q = deque([start])
    seen = {start}
    while q:
        a, b = q.popleft()
        for ch in alph:
            a1 = na.step(a, ch)
            if not a1:
                continue
            b1 = nb.step(b, ch) if b else frozenset()
            st = (a1, b1)
            if st not in seen:
                seen.add(st)
                q.append(st)
    return sorted(seen, key=lambda t: (_enc_state(t[0]), _enc_state(t[1])))


def triple_certificate(name: str,
                       issuer_patterns: Sequence[str],
                       policy_patterns: Sequence[str],
                       intent_patterns: Sequence[str],
                       alphabet: Sequence[str] = DEFAULT_ALPHABET) -> Dict[str, Any]:
    """Build a certificate for L(G) cap L(P) subseteq L(I)."""
    alph = alphabet_from_patterns(issuer_patterns, policy_patterns, intent_patterns, alphabet)
    ng, np, ni = union_globs(issuer_patterns, alph), union_globs(policy_patterns, alph), union_globs(intent_patterns, alph)
    w = _triple_witness(ng, np, ni, alph)
    cert: Dict[str, Any] = {
        "version": 1,
        "kind": "fedfence-atomic-certificate",
        "name": name,
        "judgment": "issuer-policy-intent",
        "alphabet": "".join(alph),
        "issuer_patterns": list(issuer_patterns),
        "policy_patterns": list(policy_patterns),
        "intent_patterns": list(intent_patterns),
        "verdict": "safe" if w is None else "unsafe",
        "automata_sizes": {"issuer": list(ng.size), "policy": list(np.size), "intent": list(ni.size)},
    }
    if w is None:
        cert["invariant"] = [
            {"g": _enc_state(g), "p": _enc_state(p), "i": _enc_state(i)}
            for g, p, i in _reachable_triples(ng, np, ni, alph)
        ]
    else:
        cert["witness"] = w
    return cert


def pair_certificate(name: str,
                     allow_patterns: Sequence[str],
                     intent_patterns: Sequence[str],
                     alphabet: Sequence[str] = DEFAULT_ALPHABET) -> Dict[str, Any]:
    """Build a certificate for L(A) subseteq L(B)."""
    alph = alphabet_from_patterns(allow_patterns, intent_patterns, alphabet)
    na, nb = union_globs(allow_patterns, alph), union_globs(intent_patterns, alph)
    w = contains_witness(na, nb, alph)
    cert: Dict[str, Any] = {
        "version": 1,
        "kind": "fedfence-atomic-certificate",
        "name": name,
        "judgment": "language-containment",
        "alphabet": "".join(alph),
        "allow_patterns": list(allow_patterns),
        "intent_patterns": list(intent_patterns),
        "verdict": "safe" if w is None else "unsafe",
        "automata_sizes": {"allow": list(na.size), "intent": list(nb.size)},
    }
    if w is None:
        cert["invariant"] = [
            {"a": _enc_state(a), "b": _enc_state(b)}
            for a, b in _reachable_pairs(na, nb, alph)
        ]
    else:
        cert["witness"] = w
    return cert



def triple_group_certificate(name: str,
                             issuer_patterns: Sequence[str],
                             policy_groups: Sequence[Sequence[str]],
                             intent_patterns: Sequence[str],
                             alphabet: Sequence[str] = DEFAULT_ALPHABET,
                             issuer_kind: str = "patterns") -> Dict[str, Any]:
    """Build a certificate for L(G) cap (cap_i union policy_groups_i) subseteq L(I)."""
    alph = alphabet_from_patterns(issuer_patterns, policy_groups, intent_patterns, alphabet)
    ng = default_github_subject_nfa(alph) if issuer_kind == "github-default" else union_globs(issuer_patterns, alph)
    np = _nfa_from_groups(policy_groups, alph)
    ni = union_globs(intent_patterns, alph)
    w = _triple_witness(ng, np, ni, alph)
    cert: Dict[str, Any] = {
        "version": 2,
        "kind": "fedfence-atomic-certificate",
        "name": name,
        "judgment": "issuer-policy-intent",
        "alphabet": "".join(alph),
        "issuer_kind": issuer_kind,
        "issuer_patterns": list(issuer_patterns),
        "policy_groups": [_encode_group(g) for g in policy_groups],
        "intent_patterns": list(intent_patterns),
        "verdict": "safe" if w is None else "unsafe",
        "automata_sizes": {"issuer": list(ng.size), "policy": list(np.size), "intent": list(ni.size)},
    }
    if w is None:
        cert["invariant"] = [
            {"g": _enc_state(g), "p": _enc_state(p), "i": _enc_state(i)}
            for g, p, i in _reachable_triples(ng, np, ni, alph)
        ]
    else:
        cert["witness"] = w
    return cert


def pair_group_certificate(name: str,
                           allow_groups: Sequence[Sequence[str]],
                           intent_patterns: Sequence[str],
                           alphabet: Sequence[str] = DEFAULT_ALPHABET) -> Dict[str, Any]:
    """Build a certificate for a conjunctive/disjunctive claim predicate subseteq intent."""
    alph = alphabet_from_patterns(allow_groups, intent_patterns, alphabet)
    na = _nfa_from_groups(allow_groups, alph)
    nb = union_globs(intent_patterns, alph)
    w = contains_witness(na, nb, alph)
    cert: Dict[str, Any] = {
        "version": 2,
        "kind": "fedfence-atomic-certificate",
        "name": name,
        "judgment": "language-containment",
        "alphabet": "".join(alph),
        "allow_groups": [_encode_group(g) for g in allow_groups],
        "intent_patterns": list(intent_patterns),
        "verdict": "safe" if w is None else "unsafe",
        "automata_sizes": {"allow": list(na.size), "intent": list(nb.size)},
    }
    if w is None:
        cert["invariant"] = [
            {"a": _enc_state(a), "b": _enc_state(b)}
            for a, b in _reachable_pairs(na, nb, alph)
        ]
    else:
        cert["witness"] = w
    return cert


def verify_atomic_certificate(cert: Mapping[str, Any]) -> Tuple[bool, str]:
    alph = tuple(str(cert.get("alphabet", "")))
    if not alph:
        return False, "empty alphabet in certificate"
    verdict = str(cert.get("verdict"))
    judgment = str(cert.get("judgment"))
    if judgment == "issuer-policy-intent":
        ng = default_github_subject_nfa(alph) if cert.get("issuer_kind") == "github-default" else union_globs(cert.get("issuer_patterns", []), alph)
        if "policy_groups" in cert:
            np = _nfa_from_groups(cert.get("policy_groups", []), alph)
        else:
            np = union_globs(cert.get("policy_patterns", []), alph)
        ni = union_globs(cert.get("intent_patterns", []), alph)
        if verdict == "unsafe":
            w = str(cert.get("witness", ""))
            ok = ng.accepts(w) and np.accepts(w) and not ni.accepts(w)
            return (ok, "witness verifies" if ok else "witness does not replay")
        inv_raw = cert.get("invariant", [])
        inv = {(_dec_state(x.get("g", [])), _dec_state(x.get("p", [])), _dec_state(x.get("i", []))) for x in inv_raw}
        start = (ng.epsilon_closure({ng.start}), np.epsilon_closure({np.start}), ni.epsilon_closure({ni.start}))
        if start not in inv:
            return False, "start state is absent from invariant"
        for g, p, i in inv:
            if _bad_triple(g, p, i, ng, np, ni):
                return False, "invariant contains a bad accepting state"
            for ch in alph:
                g1, p1 = ng.step(g, ch), np.step(p, ch)
                if not g1 or not p1:
                    continue
                i1 = ni.step(i, ch) if i else frozenset()
                if (g1, p1, i1) not in inv:
                    return False, "invariant is not closed under product transitions"
        return True, "safe invariant verifies"
    if judgment == "language-containment":
        if "allow_groups" in cert:
            na = _nfa_from_groups(cert.get("allow_groups", []), alph)
        else:
            na = union_globs(cert.get("allow_patterns", []), alph)
        nb = union_globs(cert.get("intent_patterns", []), alph)
        if verdict == "unsafe":
            w = str(cert.get("witness", ""))
            ok = na.accepts(w) and not nb.accepts(w)
            return (ok, "witness verifies" if ok else "witness does not replay")
        inv_raw = cert.get("invariant", [])
        inv = {(_dec_state(x.get("a", [])), _dec_state(x.get("b", []))) for x in inv_raw}
        start = (na.epsilon_closure({na.start}), nb.epsilon_closure({nb.start}))
        if start not in inv:
            return False, "start state is absent from invariant"
        for a, b in inv:
            if _bad_pair(a, b, na, nb):
                return False, "invariant contains a bad accepting state"
            for ch in alph:
                a1 = na.step(a, ch)
                if not a1:
                    continue
                b1 = nb.step(b, ch) if b else frozenset()
                if (a1, b1) not in inv:
                    return False, "invariant is not closed under product transitions"
        return True, "safe invariant verifies"
    return False, f"unsupported judgment {judgment}"


def _one_group_patterns(statement: Any, claim: str, top: Sequence[str]) -> List[str]:
    groups = statement.groups_for(claim)
    if not groups:
        return list(top)
    if len(groups) == 1:
        return list(groups[0])
    # Generated cases use one disjunctive group per claim.  The analyzer itself
    # supports intersections, but the compact certificate keeps single groups.
    return list(groups[0])


def atomic_certificate_for_case(case: Mapping[str, Any]) -> Dict[str, Any]:
    from .policy import allow_statements_for_web_identity

    name = str(case.get("name", "unnamed"))
    spec = case.get("spec", {}) or {}
    issuer_spec = spec.get("issuer_subjects")
    issuer = list(issuer_spec or ANY_GITHUB_SUBJECT)
    issuer_kind = "patterns" if issuer_spec else "github-default"
    intent_sub = subject_intent_display(spec)
    intent_aud = audience_intent_display(spec)
    products = []
    for idx, st in enumerate(allow_statements_for_web_identity(case.get("policy", {}) or {})):
        sub_groups = st.typed_groups_for("sub") or [("like", list(issuer))]
        aud_groups = st.typed_groups_for("aud") or [("like", ["*"])]
        products.append({
            "statement": idx,
            "subject_containment": triple_group_certificate(f"{name}:statement-{idx}:subject", issuer, sub_groups, intent_sub, issuer_kind=issuer_kind),
            "audience_containment": pair_group_certificate(f"{name}:statement-{idx}:audience", aud_groups, intent_aud),
        })
    return {"version": 1, "kind": "fedfence-case-certificate", "name": name, "products": products}


def verify_certificate(cert: Mapping[str, Any]) -> Union[Tuple[bool, str], Tuple[bool, List[str]]]:
    if cert.get("kind") == "fedfence-effective-case-certificate":
        return _verify_effective_case_certificate(cert)
    if cert.get("kind") != "fedfence-case-certificate":
        return verify_atomic_certificate(cert)
    ok_all = True
    notes: List[str] = []
    for prod in cert.get("products", []):
        for key in ("subject_containment", "audience_containment"):
            ok, note = verify_atomic_certificate(prod[key])
            ok_all = ok_all and ok
            notes.append(f"s{prod.get('statement')}:{key}:{note}")
    return ok_all, notes

# --- Case-level proof-carrying audit objects (version 5) --------------------

ANY_GITHUB_SUBJECT = [
    "repo:?*/?*:ref:refs/heads/?*",
    "repo:?*/?*:ref:refs/tags/?*",
    "repo:?*/?*:pull_request",
    "repo:?*/?*:environment:?*",
]
ANY_GITHUB_AUDIENCE = ["?*"]


def _state_accepts(nfa: NFA, state: State) -> bool:
    return any(s in nfa.finals for s in state)


def _difference_member(base: NFA, blockers: Sequence[NFA], alphabet: Sequence[str]) -> Optional[str]:
    blocked = union(list(blockers), alphabet) if blockers else empty(alphabet)
    return contains_witness(base, blocked, alphabet)


def _find_subject_bad_effective(issuer_sub: NFA, allow_sub: NFA, intent_sub: NFA,
                                aud_base: NFA, denies: Sequence[Tuple[NFA, NFA]],
                                alphabet: Sequence[str], max_states: int = 300000) -> Optional[Tuple[str, str]]:
    start = (issuer_sub.epsilon_closure({issuer_sub.start}),
             allow_sub.epsilon_closure({allow_sub.start}),
             intent_sub.epsilon_closure({intent_sub.start}),
             tuple(d[0].epsilon_closure({d[0].start}) for d in denies))
    q = deque([(start, "")])
    seen = {start}
    while q:
        (gi, pa, ii, dss), word = q.popleft()
        if _state_accepts(issuer_sub, gi) and _state_accepts(allow_sub, pa) and not _state_accepts(intent_sub, ii):
            blockers = [denies[k][1] for k, ds in enumerate(dss) if _state_accepts(denies[k][0], ds)]
            aw = _difference_member(aud_base, blockers, alphabet)
            if aw is not None:
                return word, aw
        if len(seen) > max_states:
            raise RuntimeError("subject certificate search exceeded determinized state budget")
        for ch in alphabet:
            gi1, pa1 = issuer_sub.step(gi, ch), allow_sub.step(pa, ch)
            if not gi1 or not pa1:
                continue
            ii1 = intent_sub.step(ii, ch) if ii else frozenset()
            dss1 = tuple(d[0].step(ds, ch) if ds else frozenset() for d, ds in zip(denies, dss))
            key = (gi1, pa1, ii1, dss1)
            if key not in seen:
                seen.add(key); q.append((key, word + ch))
    return None


def _find_audience_bad_effective(issuer_aud: NFA, allow_aud: NFA, intent_aud: NFA,
                                 sub_base: NFA, denies: Sequence[Tuple[NFA, NFA]],
                                 alphabet: Sequence[str], max_states: int = 300000) -> Optional[Tuple[str, str]]:
    start = (issuer_aud.epsilon_closure({issuer_aud.start}),
             allow_aud.epsilon_closure({allow_aud.start}),
             intent_aud.epsilon_closure({intent_aud.start}),
             tuple(d[1].epsilon_closure({d[1].start}) for d in denies))
    q = deque([(start, "")])
    seen = {start}
    while q:
        (gi, pa, ii, das), aud = q.popleft()
        if _state_accepts(issuer_aud, gi) and _state_accepts(allow_aud, pa) and not _state_accepts(intent_aud, ii):
            blockers = [denies[k][0] for k, da in enumerate(das) if _state_accepts(denies[k][1], da)]
            sw = _difference_member(sub_base, blockers, alphabet)
            if sw is not None:
                return sw, aud
        if len(seen) > max_states:
            raise RuntimeError("audience certificate search exceeded determinized state budget")
        for ch in alphabet:
            gi1, pa1 = issuer_aud.step(gi, ch), allow_aud.step(pa, ch)
            if not gi1 or not pa1:
                continue
            ii1 = intent_aud.step(ii, ch) if ii else frozenset()
            das1 = tuple(d[1].step(da, ch) if da else frozenset() for d, da in zip(denies, das))
            key = (gi1, pa1, ii1, das1)
            if key not in seen:
                seen.add(key); q.append((key, aud + ch))
    return None


def _protected_keys_from_case(case: Mapping[str, Any]) -> set[str]:
    gov = case.get("repository_governance", {}) or {}
    out: set[str] = set()
    for owner, repo, env in governance_set(gov.get("protected_environments", []) or []):
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


def _finding(kind: str, message: str, *, statement: Optional[int] = None,
             witness: str = "", blocking: bool = True, severity: str = "high") -> Dict[str, Any]:
    return {"kind": kind, "message": message, "statement": statement, "witness": witness,
            "blocking": bool(blocking), "severity": severity}


def _normalize_statement_for_cert(st: Any, idx: int, effect: str) -> Dict[str, Any]:
    return {
        "index": idx,
        "effect": effect,
        "exact_github_principal": bool(st.exact_github_oidc_principal),
        "allow_overapprox_core": bool(getattr(st, "allow_overapprox_core", False)),
        "deny_exact_core": bool(getattr(st, "deny_exact_core", False)),
        "principal_federated": list(getattr(st, "principal_federated", [])),
        "principal_wildcard": bool(getattr(st, "principal_wildcard", False)),
        "mixed_principal": bool(getattr(st, "mixed_principal", False)),
        "malformed_principal": bool(getattr(st, "malformed_principal", False)),
        "unsupported_principal": bool(getattr(st, "unsupported_principal", False)),
        "unsupported_statement_fields": sorted(set(getattr(st, "unsupported_statement_fields", []))),
        "unsupported_conditions": sorted(set(getattr(st, "unsupported_conditions", []))),
        "unsupported_claim_keys": sorted(set(getattr(st, "unsupported_claim_keys", []))),
        "raw_condition_keys": sorted(set(getattr(st, "raw_condition_keys", []))),
        "sub_groups": [_encode_group(g) for g in st.typed_groups_for("sub")],
        "aud_groups": [_encode_group(g) for g in st.typed_groups_for("aud")],
        "selected_claim_groups": {
            claim: [_encode_group(g) for g in st.typed_groups_for(claim)]
            for claim in sorted(set(list(st.equals.keys()) + list(st.likes.keys())) - {"sub", "aud"})
        },
    }


def _case_policy_profile(case: Mapping[str, Any]) -> Dict[str, Any]:
    from .policy import allow_statements_for_web_identity, deny_statements_for_web_identity
    allows = allow_statements_for_web_identity(case.get("policy", {}) or {})
    denies = deny_statements_for_web_identity(case.get("policy", {}) or {})
    return {"allows": [_normalize_statement_for_cert(st, i, "Allow") for i, st in enumerate(allows)],
            "denies": [_normalize_statement_for_cert(st, i, "Deny") for i, st in enumerate(denies)]}


def _event_summary(case: Mapping[str, Any]) -> Dict[str, Any]:
    from .event import analyze_event_case
    res = analyze_event_case(case)
    findings = [_finding(f.kind, f.message, witness=(str(f.witness_claims) if f.witness_claims else str(f.state or ""))) for f in res.findings]
    return {"safe": bool(res.safe),
            "blocking_kinds": [f["kind"] for f in findings if f.get("blocking", True)],
            "all_kinds": [f["kind"] for f in findings],
            "witnesses": [f.get("witness", "") for f in findings],
            "findings": findings,
            "event_stats": {"states": res.states, "admitted": res.admitted, "intended_admitted": res.intended_admitted}}


def _effective_summary_without_analyzer(case: Mapping[str, Any]) -> Dict[str, Any]:
    """Independently replay the effective trust judgment without importing analyzer.

    The checker and the certificate verifier deliberately share only the parser,
    GitHub constructor semantics, and generic NFA primitives.  They do not call
    the high-level analyzer, so a stale analyzer verdict is not a proof.
    """
    if isinstance(case.get("states"), list):
        return _event_summary(case)
    from .policy import allow_statements_for_web_identity, deny_statements_for_web_identity

    name = str(case.get("name", "unnamed"))
    policy = case.get("policy", {}) or {}
    spec = case.get("spec", {}) or {}
    sub_lits, sub_globs = subject_intent_parts(spec)
    aud_lits, aud_globs = audience_intent_parts(spec)
    issuer_sub_spec = list(spec.get("issuer_subjects") or [])
    issuer_aud_patterns = list(spec.get("issuer_audiences", ANY_GITHUB_AUDIENCE) or ANY_GITHUB_AUDIENCE)
    allows = allow_statements_for_web_identity(policy)
    denies = deny_statements_for_web_identity(policy)
    findings: List[Dict[str, Any]] = []
    if not allows:
        findings.append(_finding("no-web-identity-allow", "No supported web-identity Allow statement."))
        return {"safe": False, "blocking_kinds": ["no-web-identity-allow"], "all_kinds": ["no-web-identity-allow"], "witnesses": [""], "findings": findings}

    alph_inputs: List[Any] = [ANY_GITHUB_SUBJECT, issuer_sub_spec, issuer_aud_patterns] + intent_alphabet_inputs(spec)
    for st in list(allows) + list(denies):
        alph_inputs.extend(st.typed_groups_for("sub")); alph_inputs.extend(st.typed_groups_for("aud"))
    alphabet = alphabet_from_patterns(alph_inputs)
    issuer_sub = issuer_subject_nfa(issuer_sub_spec, alphabet)
    issuer_aud = union_globs(issuer_aud_patterns, alphabet)
    intent_sub = intent_nfa(sub_lits, sub_globs, alphabet) if (sub_lits or sub_globs) else None
    intent_aud = intent_nfa(aud_lits, aud_globs, alphabet) if (aud_lits or aud_globs) else None
    protected = _protected_keys_from_case(case)

    def claim_nfa(st: Any, claim: str, default: NFA) -> NFA:
        groups = st.typed_groups_for(claim)
        return intersection_typed_groups(groups, alphabet) if groups else default

    deny_rects: List[Tuple[NFA, NFA]] = []
    for idx, st in enumerate(denies):
        if not st.deny_exact_core:
            if st.unsupported_conditions or st.unsupported_claim_keys:
                findings.append(_finding("unsupported-deny-boundary", "Unsupported Deny cannot discharge an overgrant.", statement=idx, blocking=False, severity="medium"))
            continue
        deny_rects.append((claim_nfa(st, "sub", issuer_sub), claim_nfa(st, "aud", issuer_aud)))

    for idx, st in enumerate(allows):
        if st.unsupported_conditions:
            findings.append(_finding("unsupported-allow-condition", "Unsupported Allow conditions are erased as monotone restrictions.", statement=idx, blocking=False, severity="medium"))
        if st.unsupported_claim_keys:
            findings.append(_finding("unsupported-allow-claim-key", "Unsupported or unqualified Allow claim keys are erased as monotone restrictions.", statement=idx, blocking=False, severity="medium"))
        if not st.allow_overapprox_core:
            if st.principal_wildcard:
                findings.append(_finding("wildcard-allow-federated-principal", "Wildcard federated principal is outside the single-issuer core.", statement=idx))
            elif st.mixed_principal:
                findings.append(_finding("mixed-allow-principal", "Mixed federated principal is outside the single-issuer core.", statement=idx))
            elif st.unsupported_principal or st.malformed_principal or not st.exact_github_oidc_principal:
                findings.append(_finding("non-github-allow-oidc-principal", "Allow statement does not name the exact GitHub OIDC provider.", statement=idx))
            else:
                findings.append(_finding("unsupported-allow-statement-field", "Allow statement uses IAM fields outside the proof core.", statement=idx))
            continue
        if intent_sub is None:
            findings.append(_finding("missing-intent", "No subject intent language was supplied.", statement=idx))
            continue
        if intent_aud is None:
            findings.append(_finding("missing-audience-intent", "No audience intent language was supplied.", statement=idx))
            continue
        allow_sub = claim_nfa(st, "sub", issuer_sub)
        allow_aud = claim_nfa(st, "aud", issuer_aud)
        admitted_sub = intersect(issuer_sub, allow_sub, alphabet)
        admitted_aud = intersect(issuer_aud, allow_aud, alphabet)
        sub_bad = _find_subject_bad_effective(issuer_sub, allow_sub, intent_sub, admitted_aud, deny_rects, alphabet)
        if sub_bad:
            findings.append(_finding("subject-overgrant", "Effective policy admits an issuer subject outside intent.", statement=idx, witness=f"sub={sub_bad[0]}; aud={sub_bad[1]}"))
        aud_bad = _find_audience_bad_effective(issuer_aud, allow_aud, intent_aud, admitted_sub, deny_rects, alphabet)
        if aud_bad:
            findings.append(_finding("audience-overgrant", "Effective policy admits an issuer audience outside intent.", statement=idx, witness=f"sub={aud_bad[0]}; aud={aud_bad[1]}", severity="medium"))
        for g in st.typed_groups_for("sub"):
            for pat in g[1]:
                if ":environment:" not in str(pat):
                    continue
                atom = parse_github_subject(str(pat)) if "*" not in str(pat) and "?" not in str(pat) else None
                if atom is None or atom.kind != "environment" or not atom.environment:
                    findings.append(_finding("environment-wildcard", "Environment subject is not a single repository-scoped constructor.", statement=idx, witness=str(pat)))
                else:
                    key = governance_key(atom.owner, atom.repository, atom.environment)
                    if key not in protected:
                        findings.append(_finding("unprotected-environment", "Environment subject lacks repository-scoped governance evidence.", statement=idx, witness=f"sub={pat}; governance={key}"))
    return {"safe": not any(f.get("blocking", True) for f in findings),
            "blocking_kinds": [f["kind"] for f in findings if f.get("blocking", True)],
            "all_kinds": [f["kind"] for f in findings],
            "witnesses": [f.get("witness", "") for f in findings],
            "findings": findings}


def certificate_for_case(case: Mapping[str, Any]) -> Dict[str, Any]:  # type: ignore[override]
    summary = _effective_summary_without_analyzer(case)
    return {
        "version": 5,
        "kind": "fedfence-effective-case-certificate",
        "name": str(case.get("name", "unnamed")),
        "judgment": "effective-claim-product-admission",
        "case": dict(case),
        "policy_profile": _case_policy_profile(case),
        "verdict": "safe" if summary["safe"] else "unsafe",
        "replay_summary": summary,
        "certificate_components": [
            "PrincipalCert", "ClaimKeyCert", "ConditionErasureCert", "IssuerProjectionCert",
            "EffectiveAllowMinusDenyCert", "GovernanceCert", "UnsupportedBoundaryCert",
            "ReplayWitnessCert", "SelectedClaimProjectionCert"
        ],
    }


def _verify_effective_case_certificate(cert: Mapping[str, Any]) -> Tuple[bool, List[str]]:
    case = cert.get("case")
    if not isinstance(case, Mapping):
        return False, ["missing embedded case"]
    notes: List[str] = []
    ok = True
    required_components = [
        "PrincipalCert", "ClaimKeyCert", "ConditionErasureCert", "IssuerProjectionCert",
        "EffectiveAllowMinusDenyCert", "GovernanceCert", "UnsupportedBoundaryCert",
        "ReplayWitnessCert", "SelectedClaimProjectionCert"
    ]
    if list(cert.get("certificate_components", [])) != required_components:
        ok = False; notes.append("certificate component manifest mismatch")
    profile = _case_policy_profile(case)
    if profile != cert.get("policy_profile"):
        ok = False; notes.append("policy profile mismatch")
    replay = _effective_summary_without_analyzer(case)
    claimed = cert.get("replay_summary", {})
    if ("safe" if replay["safe"] else "unsafe") != cert.get("verdict"):
        ok = False; notes.append("verdict mismatch")
    for key in ("safe", "blocking_kinds", "all_kinds", "witnesses"):
        if replay.get(key) != claimed.get(key):
            ok = False; notes.append(f"{key} mismatch")
    for f in replay.get("findings", []):
        if f.get("kind") in {"subject-overgrant", "audience-overgrant"} and not f.get("witness"):
            ok = False; notes.append(f"missing replayable witness for {f.get('kind')}")
        if f.get("kind") == "event-overgrant" and not f.get("witness"):
            ok = False; notes.append("missing event witness")
    if ok:
        notes.insert(0, "independent effective-admission replay verifies")
    return ok, notes
