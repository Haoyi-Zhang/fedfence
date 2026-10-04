"""Two-sided conformance checks for reviewed CI/CD trust changes.

The regular-language backend proves a *safety* upper bound: no issuer-mintable
identity admitted by the effective policy lies outside intent.  Change review
also needs a small availability/regression obligation: identities explicitly
required by the reviewed contract must remain mintable, intended, and admitted.

Required tokens are examples, not a complete lower-bound language.  They catch
concrete compatibility regressions without weakening the universal safety proof.
"""
from __future__ import annotations

import re
import time
from typing import Any, Mapping, Sequence

PREFIX = "token.actions.githubusercontent.com:"
SUPPORTED_OPERATORS = {"StringEquals", "StringLike"}


class ConformanceError(ValueError):
    """Raised when the strict scalar-token conformance profile is malformed."""


class ConformanceBudgetExceeded(ConformanceError):
    """The positive check did not finish within its declared local budget."""
    code = "positive-analysis-budget"


def _check_deadline(deadline: float | None) -> None:
    if deadline is not None and time.monotonic() >= deadline:
        raise ConformanceBudgetExceeded("positive conformance check exhausted the review budget")



def _as_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and value and all(isinstance(item, str) for item in value):
        return list(value)
    raise ConformanceError("condition values must be a string or a nonempty list of strings")


def _glob_matches(pattern: str, actual: str, *, deadline: float | None = None) -> bool:
    """Exact star/question-mark matching without regular-expression backtracking.

    The Boolean row stores matches between the consumed pattern prefix and each
    prefix of ``actual``. Brackets, slashes, backslashes and all other characters
    are literal. A star can match the empty string. Work is O(len(pattern) *
    len(actual)); auxiliary storage is O(len(actual)). A deterministic 2,000,000
    cell limit and the optional monotonic deadline make exhaustion explicit.
    Matching is code-point based over all Python str values, with no Unicode
    normalization or fixed ASCII pool. The symbolic path must use complete
    support for this same domain. This scalar oracle deliberately does not call
    its alphabet constructor. A code point is not a grapheme or a UTF-8 byte.
    """
    _check_deadline(deadline)
    if not isinstance(pattern, str) or not isinstance(actual, str):
        raise ConformanceError("glob pattern and value must be strings")
    if "*" not in pattern and "?" not in pattern:
        return pattern == actual
    if len(pattern) * (len(actual) + 1) > 2_000_000:
        raise ConformanceBudgetExceeded("positive glob match exceeds 2000000 cell budget")
    row = [True] + [False] * len(actual)
    for char in pattern:
        _check_deadline(deadline)
        nxt = [False] * (len(actual) + 1)
        if char == "*":
            nxt[0] = row[0]
            for j in range(1, len(nxt)):
                nxt[j] = row[j] or nxt[j - 1]
        else:
            for j in range(1, len(nxt)):
                nxt[j] = row[j - 1] and (char == "?" or char == actual[j - 1])
        row = nxt
    return row[-1]


def _value_matches(operator: str, pattern: str, actual: str, *, deadline: float | None = None) -> bool:
    _check_deadline(deadline)
    if operator == "StringEquals":
        return actual == pattern
    if operator == "StringLike":
        return _glob_matches(pattern, actual, deadline=deadline)
    raise ConformanceError(f"unsupported operator: {operator}")


def _statement_matches(statement: Mapping[str, Any], token: Mapping[str, str], *, deadline: float | None = None) -> bool:
    _check_deadline(deadline)
    condition = statement.get("Condition", {})
    if not isinstance(condition, Mapping):
        raise ConformanceError("statement condition must be an object")
    # AWS condition groups are conjunctive across keys/groups; values within one
    # key are alternatives.  The strict gate has already rejected all claims
    # outside sub/aud and all operators outside this scalar profile.
    for operator, predicates in condition.items():
        if operator not in SUPPORTED_OPERATORS or not isinstance(predicates, Mapping):
            raise ConformanceError("statement outside strict conformance profile")
        for key, raw_values in predicates.items():
            if key == PREFIX + "sub":
                actual = token["sub"]
            elif key == PREFIX + "aud":
                actual = token["aud"]
            else:
                raise ConformanceError(f"unsupported claim: {key}")
            values = _as_list(raw_values)
            if not any(_value_matches(operator, value, actual, deadline=deadline) for value in values):
                return False
    return True


def effective_policy_accepts(policy: Mapping[str, Any], token: Mapping[str, str], *, deadline: float | None = None) -> bool:
    """Return tuple-level Allow-minus-Deny membership for a strict token."""
    statements = policy.get("Statement")
    if isinstance(statements, Mapping):
        statements = [statements]
    if not isinstance(statements, list):
        raise ConformanceError("policy Statement must be a list")
    allow = False
    deny = False
    for statement in statements:
        if not isinstance(statement, Mapping):
            raise ConformanceError("statement must be an object")
        effect = statement.get("Effect")
        if effect not in {"Allow", "Deny"}:
            raise ConformanceError("explicit Allow/Deny required")
        if _statement_matches(statement, token, deadline=deadline):
            allow = allow or effect == "Allow"
            deny = deny or effect == "Deny"
    return allow and not deny


def intent_accepts(spec: Mapping[str, Any], token: Mapping[str, str], *, deadline: float | None = None) -> bool:
    literals = list(spec.get("allowed_subjects", [])) + list(spec.get("allowed_subject_literals", []))
    globs = list(spec.get("allowed_subject_globs", []))
    audiences = list(spec.get("allowed_audiences", [])) + list(spec.get("allowed_audience_literals", []))
    audience_globs = list(spec.get("allowed_audience_globs", []))
    subject_ok = token["sub"] in literals or any(_glob_matches(pattern, token["sub"], deadline=deadline) for pattern in globs)
    audience_ok = token["aud"] in audiences or any(_glob_matches(pattern, token["aud"], deadline=deadline) for pattern in audience_globs)
    return bool(subject_ok and audience_ok)


def issuer_accepts(spec: Mapping[str, Any], token: Mapping[str, str], *, deadline: float | None = None) -> bool:
    """Mirror the inherited typed issuer language and optional refinements.

    In the regular-language study interface, issuer_subjects narrows the default
    constructor language; it does not replace that language with arbitrary
    strings. The regex uses the exact finite exclusions also used by the typed
    NFA (/:*? for owner/repository, :*? for suffixes); no ASCII-only restriction
    is implied. This is an abstract issuer grammar, not live GitHub validation.
    Absent/empty refinement lists keep the inherited defaults. Custom
    finite issuer relations remain the separate normalized study adapter.
    """
    _check_deadline(deadline)
    refinements = {}
    for key in ("issuer_subjects", "issuer_audiences"):
        value = spec.get(key)
        if value is not None and (not isinstance(value, list) or any(not isinstance(item, str) for item in value)):
            raise ConformanceError(f"{key} must be a string list")
        refinements[key] = value or []
    component = r"[^/:*?]+"
    suffix = r"(?:ref:refs/(?:heads|tags)/[^:*?]+|environment:[^:*?]+|pull_request)"
    typed = bool(re.fullmatch(r"repo:" + component + "/" + component + ":" + suffix, token["sub"]))
    if not typed:
        return False
    subjects = refinements["issuer_subjects"]
    audiences = refinements["issuer_audiences"] or ["?*"]
    return bool((not subjects or any(_glob_matches(p, token["sub"], deadline=deadline) for p in subjects))
                and any(_glob_matches(p, token["aud"], deadline=deadline) for p in audiences))



def check_required_tokens(
    policy: Mapping[str, Any],
    spec: Mapping[str, Any],
    required_tokens: Sequence[Mapping[str, str]],
    *, deadline: float | None = None,
) -> dict[str, Any]:
    """Evaluate finite positive regression obligations.

    ``missing`` is a confirmed configuration regression only when the token is
    both issuer-mintable and allowed by the reviewed intent.  A token outside the
    issuer model or intent indicates an inconsistent review packet and therefore
    produces ``invalid`` rather than a false security finding.
    """
    _check_deadline(deadline)
    checks: list[dict[str, Any]] = []
    missing: list[dict[str, Any]] = []
    invalid: list[dict[str, Any]] = []
    for index, item in enumerate(required_tokens):
        _check_deadline(deadline)
        token = {"sub": item["sub"], "aud": item["aud"]}
        mintable = issuer_accepts(spec, token, deadline=deadline)
        intended = intent_accepts(spec, token, deadline=deadline)
        admitted = effective_policy_accepts(policy, token, deadline=deadline)
        record = {
            "index": index,
            "sub": token["sub"],
            "aud": token["aud"],
            "reason": item.get("reason", ""),
            "issuer_mintable": mintable,
            "inside_intent": intended,
            "policy_admitted": admitted,
            "satisfied": bool(mintable and intended and admitted),
        }
        checks.append(record)
        if not mintable or not intended:
            invalid.append(record)
        elif not admitted:
            missing.append(record)
    _check_deadline(deadline)
    return {
        "checks": checks,
        "required": len(checks),
        "satisfied": sum(int(item["satisfied"]) for item in checks),
        "missing": missing,
        "invalid": invalid,
        "all_satisfied": not missing and not invalid,
    }
