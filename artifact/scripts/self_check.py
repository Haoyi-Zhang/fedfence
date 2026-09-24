#!/usr/bin/env python3
"""Small exhaustive cross-checks for the FedFence automata core.

The proof in the paper is language-theoretic. This script is not part of the
proof; it is a regression guard that compares the executable NFA routines with
brute-force enumeration over a tiny alphabet and bounded word length.
"""
from __future__ import annotations

import itertools
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from fedfence.analyzer import analyze_case  # noqa: E402
from fedfence.regular import (  # noqa: E402
    alphabet_from_patterns,
    contains_witness,
    glob,
    intersection_language_difference_witness,
    union_globs,
)

ALPH = tuple("ab:")
PATTERNS = ["", "a", "b", ":", "*", "?", "a*", "*b", "a?", "?:", "a*b", "*:*", "a:b"]
MAX_LEN = 4


def words():
    yield ""
    for n in range(1, MAX_LEN + 1):
        for tup in itertools.product(ALPH, repeat=n):
            yield "".join(tup)


def brute_glob(pattern: str, word: str) -> bool:
    if not pattern:
        return word == ""
    # Dynamic programming for glob matching.
    dp = [[False] * (len(word) + 1) for _ in range(len(pattern) + 1)]
    dp[0][0] = True
    for i, ch in enumerate(pattern, start=1):
        if ch == "*":
            dp[i][0] = dp[i - 1][0]
            for j in range(1, len(word) + 1):
                dp[i][j] = dp[i - 1][j] or dp[i][j - 1]
        elif ch == "?":
            for j in range(1, len(word) + 1):
                dp[i][j] = dp[i - 1][j - 1]
        else:
            for j in range(1, len(word) + 1):
                dp[i][j] = dp[i - 1][j - 1] and word[j - 1] == ch
    return dp[len(pattern)][len(word)]


def main() -> int:
    checked = 0
    for p in PATTERNS:
        nfa = glob(p, ALPH)
        for w in words():
            assert nfa.accepts(w) == brute_glob(p, w), (p, w)
            checked += 1

    for a in PATTERNS:
        for b in PATTERNS:
            nfa_a, nfa_b = glob(a, ALPH), glob(b, ALPH)
            witness = contains_witness(nfa_a, nfa_b, ALPH)
            brute = next((w for w in words() if brute_glob(a, w) and not brute_glob(b, w)), None)
            # If a brute witness exists up to the bound, the unbounded NFA search
            # must find some witness. If no NFA witness exists, brute enumeration
            # must find none.
            if brute is not None:
                assert witness is not None and brute_glob(a, witness) and not brute_glob(b, witness), (a, b, brute, witness)
            elif witness is None:
                pass
            checked += 1

    for p in PATTERNS:
        for q in PATTERNS:
            for i in PATTERNS:
                nfa_p, nfa_q, nfa_i = glob(p, ALPH), glob(q, ALPH), glob(i, ALPH)
                witness = intersection_language_difference_witness(nfa_p, nfa_q, nfa_i, ALPH)
                brute = next((w for w in words() if brute_glob(p, w) and brute_glob(q, w) and not brute_glob(i, w)), None)
                if brute is not None:
                    assert witness is not None and brute_glob(p, witness) and brute_glob(q, witness) and not brute_glob(i, witness), (p, q, i, brute, witness)
                elif witness is None:
                    pass
                checked += 1
    # Dynamic alphabet regression: a literal outside the default model alphabet
    # must still be explored by containment search when it appears in a pattern.
    dyn = alphabet_from_patterns(["tenant$prod"], ["tenant"], ["*"])
    assert "$" in dyn
    witness = contains_witness(union_globs(["tenant$prod"], dyn), union_globs(["tenant"], dyn), dyn)
    assert witness == "tenant$prod", witness
    checked += 1

    # Deny monotonicity regression: a supported Deny that only removes authority
    # cannot invalidate an Allow-only containment proof.
    principal = {"Federated": "arn:aws:iam::000000000000:oidc-provider/token.actions.githubusercontent.com"}
    deny_case = {
        "name": "deny-monotone",
        "policy": {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Principal": principal, "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {"StringEquals": {
                "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                "token.actions.githubusercontent.com:sub": "repo:acme/api:ref:refs/heads/main"}}},
            {"Effect": "Deny", "Principal": principal, "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {"StringEquals": {
                "token.actions.githubusercontent.com:sub": "repo:acme/api:ref:refs/heads/breakglass"}}}
        ]},
        "spec": {"allowed_subjects": ["repo:acme/api:ref:refs/heads/main"], "allowed_audiences": ["sts.amazonaws.com"]},
        "repository_governance": {"protected_environments": []}
    }
    res = analyze_case(deny_case)
    assert res.safe, [f.kind for f in res.findings]
    checked += 1



    # Operator-aware alphabet regression: in equality mode '*' and '?' are
    # literals, not glob metacharacters.  A previous implementation excluded
    # them from the finite support and could miss a concrete audience witness.
    eq_case = {
        "name": "literal-star-audience-regression",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": principal, "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {"StringEquals": {
                "token.actions.githubusercontent.com:aud": "*",
                "token.actions.githubusercontent.com:sub": "repo:acme/api:ref:refs/heads/main"}}
        }]},
        "spec": {"issuer_subjects": ["repo:acme/api:ref:refs/heads/main"], "issuer_audiences": ["*"],
                 "allowed_subjects": ["repo:acme/api:ref:refs/heads/main"], "allowed_audiences": ["sts.amazonaws.com"]},
        "repository_governance": {"protected_environments": []}
    }
    res = analyze_case(eq_case)
    assert not res.safe and any(f.kind == "audience-overgrant" and f.witness and "aud=*" in f.witness for f in res.findings), res
    checked += 1

    # Unsupported Allow conditions are monotone restrictions.  If the erased
    # over-approximation is safe, the original statement is safe even though the
    # artifact records the erasure boundary.
    erasure_case = {
        "name": "unsupported-allow-erasure-regression",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": principal, "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {"StringEquals": {
                "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                "token.actions.githubusercontent.com:sub": "repo:acme/api:ref:refs/heads/main",
                "aws:PrincipalTag/release": "approved"}}
        }]},
        "spec": {"allowed_subjects": ["repo:acme/api:ref:refs/heads/main"], "allowed_audiences": ["sts.amazonaws.com"]},
        "repository_governance": {"protected_environments": []}
    }
    res = analyze_case(erasure_case)
    assert res.safe and any(f.kind == "unsupported-allow-claim-key" and not f.blocking for f in res.findings), res
    checked += 1

    # Projection-calculus regression: branch-sensitive protected-environment
    # intent is not definable from the default GitHub subject alone, but becomes
    # definable when the visible claim basis includes the ref coordinate.
    from fedfence.projection import sample_space, prod_environment_main_branch_api, claim_definability_counterexample, github_default_subject, projection_from_fields
    states = sample_space()
    assert claim_definability_counterexample(states, github_default_subject, prod_environment_main_branch_api) is not None
    assert claim_definability_counterexample(states, projection_from_fields(["default_sub", "ref"]), prod_environment_main_branch_api) is None
    checked += 2

    print(f"self-check passed ({checked} bounded and symbolic comparisons)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
