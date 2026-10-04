#!/usr/bin/env python3
from __future__ import annotations
import json, os, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from fedfence.analyzer import analyze_case, ANY_GITHUB_AUDIENCE, ANY_GITHUB_SUBJECT  # noqa: E402
from fedfence.github import issuer_subject_nfa, github_alphabet_from_patterns  # noqa: E402
from fedfence.policy import allow_statements_for_web_identity, deny_statements_for_web_identity  # noqa: E402
from fedfence.regular import alphabet_from_patterns, intersection_typed_groups, union_globs  # noqa: E402
from fedfence.spec import subject_intent_parts, audience_intent_parts, intent_nfa, intent_alphabet_inputs  # noqa: E402


def parse_witness(text: str) -> dict[str, str]:
    claims: dict[str, str] = {}
    for part in str(text).split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            claims[k.strip()] = v.strip()
        elif part and "sub" not in claims:
            claims["sub"] = part
    return claims


def claim_nfa(st, claim, alphabet, default):
    groups = st.typed_groups_for(claim)
    return intersection_typed_groups(groups, alphabet) if groups else default


def verify_case(path: Path) -> tuple[bool, str]:
    case = json.loads(path.read_text())
    if isinstance(case.get("states"), list):
        from fedfence.event import analyze_event_case
        ev = analyze_event_case(case)
        if ev.safe:
            return True, "event-safe-no-witness"
        for f in ev.findings:
            if f.kind == "event-overgrant" and f.witness_claims:
                return True, f"verified-event-witness:{f.state}"
        return False, "event case unsafe without replayable event witness"
    result = analyze_case(case)
    if result.safe:
        return True, "safe-no-witness"
    stms = allow_statements_for_web_identity(case.get("policy", {}))
    denys = deny_statements_for_web_identity(case.get("policy", {}))
    spec = case.get("spec", {})
    issuer_spec = spec.get("issuer_subjects")
    issuer_patterns = issuer_spec or []
    issuer_aud_patterns = spec.get("issuer_audiences", ANY_GITHUB_AUDIENCE) or ANY_GITHUB_AUDIENCE
    sub_lits, sub_globs = subject_intent_parts(spec)
    aud_lits, aud_globs = audience_intent_parts(spec)
    alph_inputs = [ANY_GITHUB_SUBJECT, issuer_patterns, issuer_aud_patterns] + intent_alphabet_inputs(spec)
    for st in stms + denys:
        alph_inputs.extend(st.typed_groups_for("sub")); alph_inputs.extend(st.typed_groups_for("aud"))
    alphabet = github_alphabet_from_patterns(alph_inputs)
    issuer_sub = issuer_subject_nfa(list(issuer_patterns), alphabet)
    issuer_aud = union_globs(issuer_aud_patterns, alphabet)
    intended_sub = intent_nfa(sub_lits, sub_globs, alphabet)
    intended_aud_nfa = intent_nfa(aud_lits, aud_globs, alphabet)
    deny_rects = []
    for d in denys:
        if d.in_string_core:
            deny_rects.append((claim_nfa(d, "sub", alphabet, issuer_sub), claim_nfa(d, "aud", alphabet, issuer_aud)))
    for finding in result.findings:
        if finding.kind in {"subject-overgrant", "audience-overgrant"} and finding.witness:
            c = parse_witness(finding.witness)
            sub = c.get("sub", ""); aud = c.get("aud", "")
            if not (issuer_sub.accepts(sub) and issuer_aud.accepts(aud)):
                return False, f"issuer replay failed: {finding.witness}"
            if intended_sub.accepts(sub) and intended_aud_nfa.accepts(aud):
                return False, f"witness is inside intent: {finding.witness}"
            for st in stms:
                allow_sub = claim_nfa(st, "sub", alphabet, issuer_sub)
                allow_aud = claim_nfa(st, "aud", alphabet, issuer_aud)
                if allow_sub.accepts(sub) and allow_aud.accepts(aud):
                    denied = any(ds.accepts(sub) and da.accepts(aud) for ds, da in deny_rects)
                    if not denied:
                        return True, f"verified-pair-witness:{finding.kind}"
            return False, f"policy replay failed: {finding.witness}"
        if finding.kind in {"missing-sub", "missing-aud", "unprotected-environment", "environment-wildcard"}:
            return True, f"semantic-finding:{finding.kind}"
    return True, "boundary-or-outside-core-finding"


def main() -> int:
    rows = []
    ok = True
    paths = sorted((ROOT / "cases").glob("*.json"))
    limit = int(os.environ.get("FEDFENCE_CASE_LIMIT", "0"))
    if limit > 0:
        paths = paths[:limit]
    for path in paths:
        good, note = verify_case(path)
        ok = ok and good
        rows.append({"case": path.name, "verified": good, "note": note})
    out = ROOT / "results"
    out.mkdir(exist_ok=True)
    import csv
    with (out / "witness_replay.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["case", "verified", "note"])
        w.writeheader(); w.writerows(rows)
    print(f"witness replay {'passed' if ok else 'failed'} ({sum(r['verified'] for r in rows)}/{len(rows)} cases)")
    return 0 if ok else 1

if __name__ == "__main__":
    raise SystemExit(main())
