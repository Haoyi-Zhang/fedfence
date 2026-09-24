"""Strict two-claim preflight. No unknown statement is silently dropped.

This iteration deliberately limits the production-style gate to scalar sub/aud,
StringEquals/StringLike, one exact provider ARN and the web-identity action.
The legacy finite selected-claim backend remains separate, not silently invoked.
"""
from __future__ import annotations
import re
from typing import Any

PREFIX = "token.actions.githubusercontent.com:"
ACTION = "sts:AssumeRoleWithWebIdentity"
ARN = re.compile(r"arn:(aws|aws-us-gov|aws-cn):iam::[0-9]{12}:oidc-provider/token\.actions\.githubusercontent\.com\Z")
FIELDS = {"Sid", "Effect", "Principal", "Action", "Condition"}


def inspect_policy(policy: Any) -> dict:
    issues = []
    def issue(code, location, detail):
        issues.append({"code": code, "location": location, "detail": detail})
    if not isinstance(policy, dict):
        return {"supported": False, "statements": 0, "issues": [{"code": "invalid-policy", "location": "$", "detail": "expected object"}]}
    for key in sorted(set(policy) - {"Version", "Id", "Statement"}):
        issue("unsupported-policy-field", key, str(key))
    if policy.get("Version", "2012-10-17") != "2012-10-17":
        issue("unsupported-policy-version", "Version", str(policy.get("Version")))
    statements = policy.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list) or not statements:
        issue("invalid-statements", "Statement", "a nonempty statement list is required")
        statements = []
    allows = 0
    for i, st in enumerate(statements):
        loc = f"Statement[{i}]"
        if not isinstance(st, dict):
            issue("invalid-statement", loc, "expected object")
            continue
        for field in sorted(set(st) - FIELDS):
            issue("unsupported-statement-field", f"{loc}.{field}", field)
        effect = st.get("Effect")
        if not isinstance(effect, str) or effect not in {"Allow", "Deny"}:
            issue("invalid-effect", f"{loc}.Effect", "explicit Allow/Deny required")
        allows += effect == "Allow"
        principal = st.get("Principal")
        if not isinstance(principal, dict) or set(principal) != {"Federated"}:
            issue("unsupported-principal", f"{loc}.Principal", "single Federated principal required")
        else:
            fed = principal["Federated"]
            fed = fed[0] if isinstance(fed, list) and len(fed) == 1 else fed
            if not isinstance(fed, str) or ARN.fullmatch(fed) is None:
                issue("unsupported-principal", f"{loc}.Principal", "exact GitHub OIDC provider ARN required")
        actions = st.get("Action")
        actions = [actions] if isinstance(actions, str) else actions
        if not isinstance(actions, list) or len(actions) != 1 or not isinstance(actions[0], str) or actions[0].lower() != ACTION.lower():
            issue("unsupported-action", f"{loc}.Action", "singleton AssumeRoleWithWebIdentity required")
        condition = st.get("Condition", {})
        if not isinstance(condition, dict):
            issue("invalid-condition", f"{loc}.Condition", "expected object")
            continue
        for op, predicates in condition.items():
            ploc = f"{loc}.Condition.{op}"
            if op not in {"StringEquals", "StringLike"}:
                issue("unsupported-operator", ploc, op)
            if not isinstance(predicates, dict) or not predicates:
                issue("invalid-condition-group", ploc, "nonempty object required")
                continue
            for key, values in predicates.items():
                if key not in {PREFIX + "sub", PREFIX + "aud"}:
                    issue("unsupported-claim", f"{ploc}.{key}", "coordinate not consumed by the two-claim backend")
                values = [values] if isinstance(values, str) else values
                if not isinstance(values, list) or not values or any(not isinstance(v, str) for v in values):
                    issue("invalid-condition-value", f"{ploc}.{key}", "nonempty scalar-string list required")
                    continue
                if any("${" in v or "%{" in v for v in values):
                    issue("unresolved-interpolation", f"{ploc}.{key}", "provider/IaC variables require resolution")
    if not allows:
        issue("no-supported-allow", "Statement", "gate requires an explicit role-admission Allow")
    return {"supported": not issues, "statements": len(statements), "issues": issues,
            "profile": "aws-github-scalar-sub-aud-v1"}
