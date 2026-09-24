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
from typing import Any, Mapping, Sequence

PREFIX = "token.actions.githubusercontent.com:"
SUPPORTED_OPERATORS = {"StringEquals", "StringLike"}


class ConformanceError(ValueError):
    """Raised when the strict scalar-token conformance profile is malformed."""


def _as_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and value and all(isinstance(item, str) and item for item in value):
        return list(value)
    raise ConformanceError("condition values must be a nonempty string or string list")


def _glob_matches(pattern: str, actual: str) -> bool:
    """Match the paper's IAM-style ``*``/``?`` fragment.

    ``fnmatch`` is deliberately not used because it gives square brackets an
    extra character-class meaning that is absent from the modeled fragment.
    """
    parts: list[str] = []
    for char in pattern:
        if char == "*":
            parts.append(".*")
        elif char == "?":
            parts.append(".")
        else:
            parts.append(re.escape(char))
    return re.fullmatch("".join(parts), actual, flags=re.DOTALL) is not None


def _value_matches(operator: str, pattern: str, actual: str) -> bool:
    if operator == "StringEquals":
        return actual == pattern
    if operator == "StringLike":
        return _glob_matches(pattern, actual)
    raise ConformanceError(f"unsupported operator: {operator}")


def _statement_matches(statement: Mapping[str, Any], token: Mapping[str, str]) -> bool:
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
            if not any(_value_matches(operator, value, actual) for value in values):
                return False
    return True


def effective_policy_accepts(policy: Mapping[str, Any], token: Mapping[str, str]) -> bool:
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
        if _statement_matches(statement, token):
            allow = allow or effect == "Allow"
            deny = deny or effect == "Deny"
    return allow and not deny


def intent_accepts(spec: Mapping[str, Any], token: Mapping[str, str]) -> bool:
    literals = list(spec.get("allowed_subjects", [])) + list(spec.get("allowed_subject_literals", []))
    globs = list(spec.get("allowed_subject_globs", []))
    audiences = list(spec.get("allowed_audiences", [])) + list(spec.get("allowed_audience_literals", []))
    audience_globs = list(spec.get("allowed_audience_globs", []))
    subject_ok = token["sub"] in literals or any(_glob_matches(pattern, token["sub"]) for pattern in globs)
    audience_ok = token["aud"] in audiences or any(_glob_matches(pattern, token["aud"]) for pattern in audience_globs)
    return bool(subject_ok and audience_ok)


def issuer_accepts(spec: Mapping[str, Any], token: Mapping[str, str]) -> bool:
    """Check the explicit issuer sample domain when present.

    Public-change packets may freeze exact mintable subjects in
    ``issuer_subjects``.  Gate packets use the default GitHub constructor profile;
    for them, the required token is valid when it has a typed branch, tag, PR, or
    environment suffix for the contract repository.
    """
    explicit = spec.get("issuer_subjects")
    if explicit is not None:
        if not isinstance(explicit, list) or any(not isinstance(item, str) for item in explicit):
            raise ConformanceError("issuer_subjects must be a string list")
        return any(_glob_matches(pattern, token["sub"]) for pattern in explicit)
    sub = token["sub"]
    return (
        sub.startswith("repo:")
        and any(marker in sub for marker in (":ref:refs/heads/", ":ref:refs/tags/", ":pull_request", ":environment:"))
        and bool(token["aud"])
    )


def check_required_tokens(
    policy: Mapping[str, Any],
    spec: Mapping[str, Any],
    required_tokens: Sequence[Mapping[str, str]],
) -> dict[str, Any]:
    """Evaluate finite positive regression obligations.

    ``missing`` is a confirmed configuration regression only when the token is
    both issuer-mintable and allowed by the reviewed intent.  A token outside the
    issuer model or intent indicates an inconsistent review packet and therefore
    produces ``invalid`` rather than a false security finding.
    """
    checks: list[dict[str, Any]] = []
    missing: list[dict[str, Any]] = []
    invalid: list[dict[str, Any]] = []
    for index, item in enumerate(required_tokens):
        token = {"sub": item["sub"], "aud": item["aud"]}
        mintable = issuer_accepts(spec, token)
        intended = intent_accepts(spec, token)
        admitted = effective_policy_accepts(policy, token)
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
    return {
        "checks": checks,
        "required": len(checks),
        "satisfied": sum(int(item["satisfied"]) for item in checks),
        "missing": missing,
        "invalid": invalid,
        "all_satisfied": not missing and not invalid,
    }
