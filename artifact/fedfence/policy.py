"""Parsers for the FedFence policy fragment.

The parser is intentionally conservative: a statement enters the positive
GitHub proof core only when its federated principal and claim keys have the
provider namespace that AWS applies to GitHub Actions OIDC.  Unsupported syntax
is retained as evidence but never silently used to prove safety.
"""
from __future__ import annotations

import re
from fnmatch import fnmatchcase
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Tuple

GITHUB_PREFIX = "token.actions.githubusercontent.com:"
GITHUB_ISSUER_HOST = "token.actions.githubusercontent.com"
SUPPORTED_CLAIMS = {
    "sub", "aud",
    "ref", "environment", "repository", "repository_id", "repository_visibility",
    "job_workflow_ref", "workflow_ref", "workflow", "actor", "actor_id",
    "repository_owner", "repository_owner_id", "run_id", "run_number", "run_attempt",
    "repository_custom_properties.tier", "repository_custom_properties.release",
    "repository_custom_properties.environment", "repository_custom_properties.trust",
}
WEB_IDENTITY_ACTION = "sts:assumerolewithwebidentity"
SUPPORTED_LIKE = {"stringlike", "arnlike"}
SUPPORTED_EQUALS = {"stringequals", "arnequals"}
AWS_GITHUB_PRINCIPAL_RE = re.compile(
    r"^arn:(aws|aws-us-gov|aws-cn):iam::[0-9]{12}:oidc-provider/token\.actions\.githubusercontent\.com$"
)

@dataclass
class StatementConstraints:
    effect: str
    action: List[str]
    equals: Dict[str, List[str]] = field(default_factory=dict)
    likes: Dict[str, List[str]] = field(default_factory=dict)
    principal_federated: List[str] = field(default_factory=list)
    principal_wildcard: bool = False
    unsupported_principal: bool = False
    mixed_principal: bool = False
    malformed_principal: bool = False
    unsupported_statement_fields: List[str] = field(default_factory=list)
    unsupported_conditions: List[str] = field(default_factory=list)
    unsupported_claim_keys: List[str] = field(default_factory=list)
    raw_condition_keys: List[str] = field(default_factory=list)

    def patterns_for(self, claim: str) -> List[str]:
        pats: List[str] = []
        if claim in self.equals:
            pats.extend(self.equals[claim])
        if claim in self.likes:
            pats.extend(self.likes[claim])
        return pats

    def groups_for(self, claim: str) -> List[List[str]]:
        groups: List[List[str]] = []
        if claim in self.equals:
            groups.append(list(self.equals[claim]))
        if claim in self.likes:
            groups.append(list(self.likes[claim]))
        return groups

    def typed_groups_for(self, claim: str) -> List[Tuple[str, List[str]]]:
        """Return conjunctive claim groups with operator semantics preserved.

        AWS StringEquals values are literals, whereas StringLike values are glob
        patterns.  Keeping this tag is necessary for soundness: treating an
        equality value containing '*' as a wildcard would prove a different
        policy from the one written by the cloud provider.
        """
        groups: List[Tuple[str, List[str]]] = []
        if claim in self.equals:
            groups.append(("equals", list(self.equals[claim])))
        if claim in self.likes:
            groups.append(("like", list(self.likes[claim])))
        return groups

    @property
    def exact_github_oidc_principal(self) -> bool:
        if self.principal_wildcard or self.unsupported_principal or self.mixed_principal:
            return False
        if len(self.principal_federated) != 1:
            return False
        return _is_exact_github_principal(self.principal_federated[0])

    @property
    def github_oidc_principal(self) -> bool:
        # Backward-compatible name used by older scripts.  The semantics is now
        # exact rather than substring-based.
        return self.exact_github_oidc_principal

    @property
    def has_certified_principal_and_action_core(self) -> bool:
        """The statement can be interpreted over the GitHub OIDC string claims.

        Unsupported Allow conditions are monotone restrictions: ignoring them
        over-approximates the admitted language.  They therefore do not by
        themselves prevent a positive safety proof.  Unsupported principal,
        non-exact action, or structural IAM fields do prevent a proof, because
        they change which issuer/action family the statement denotes.
        """
        return (self.exact_github_oidc_principal
                and _has_exact_web_identity_action(self.action)
                and not self.unsupported_statement_fields)

    @property
    def allow_overapprox_core(self) -> bool:
        return self.has_certified_principal_and_action_core

    @property
    def deny_exact_core(self) -> bool:
        return (self.has_certified_principal_and_action_core
                and not self.unsupported_conditions
                and not self.unsupported_claim_keys)

    @property
    def in_string_core(self) -> bool:
        # Backward-compatible name.  It is exact for Deny and conservative for
        # legacy callers; analyzer uses allow_overapprox_core for Allow.
        return self.deny_exact_core


def _as_list(x: Any) -> List[str]:
    if x is None:
        return []
    if isinstance(x, list):
        return [str(v) for v in x]
    return [str(x)]


def _condition_values(x: Any, sc: "StatementConstraints", op: str) -> List[str] | None:
    """Return scalar IAM string condition values or mark malformed syntax.

    The proof core intentionally accepts only nonempty scalar string values or
    nonempty lists of scalar values.  Empty lists and structured condition
    values are not IAM string-claim languages in this fragment; accepting them
    as empty or stringified values would produce a different policy semantics.
    """
    if isinstance(x, str):
        return [x]
    if isinstance(x, list):
        if not x:
            sc.unsupported_conditions.append(f"{op}:empty-value-list")
            return None
        if all(isinstance(v, str) for v in x):
            return list(x)
        sc.unsupported_conditions.append(f"{op}:non-string-list-value")
        return None
    sc.unsupported_conditions.append(f"{op}:non-string-value")
    return None


def _is_exact_github_principal(p: str) -> bool:
    p = str(p)
    # Raw AWS trust policies identify the provider by ARN.  Accepting host-name
    # substrings would be unsound: a malicious or foreign provider can include
    # the GitHub host text in its own identifier.  Normalizers that target this
    # parser must therefore materialize the exact provider ARN.
    return AWS_GITHUB_PRINCIPAL_RE.match(p) is not None


def _norm_claim(raw: str, sc: StatementConstraints) -> str | None:
    raw = str(raw)
    sc.raw_condition_keys.append(raw)
    if raw.startswith(GITHUB_PREFIX):
        claim = raw[len(GITHUB_PREFIX):]
        if claim in SUPPORTED_CLAIMS or claim.startswith("repository_custom_properties."):
            return claim
        sc.unsupported_claim_keys.append(raw)
        return None
    # Bare sub/aud or other provider keys are not GitHub OIDC constraints in raw
    # AWS mode.  Ignoring them is critical: otherwise an ineffective or foreign
    # condition could be mistaken for a proof-carrying GitHub restriction.
    sc.unsupported_claim_keys.append(raw)
    return None


def _op_name(op: str, sc: StatementConstraints) -> str | None:
    op_s = str(op)
    parts = op_s.split(":")
    # Set-operator prefixes have IAM-specific semantics over multi-valued
    # context keys.  GitHub OIDC claims in this artifact are modeled as scalar
    # values, but accepting the prefix as if it were absent would prove a
    # different policy than the one written.  Treat them as unsupported
    # monotone Allow restrictions and do not use them to discharge Deny.
    if len(parts) > 1 and parts[0].lower() in {"forallvalues", "foranyvalue"}:
        sc.unsupported_conditions.append(op_s)
        return None
    suffix = parts[-1]
    if suffix.lower().endswith("ifexists"):
        sc.unsupported_conditions.append(op_s)
        return None
    return suffix.lower()


def _federated_principals(principal: Any) -> Tuple[List[str], bool, bool, bool, bool]:
    """Return federated principals and flags: wildcard, unsupported, mixed, malformed."""
    if principal is None:
        return [], False, True, False, False
    if principal == "*":
        return [], True, False, False, False
    if not isinstance(principal, Mapping):
        return [], False, True, False, True
    unsupported = False
    fed = principal.get("Federated")
    if fed is None:
        return [], False, True, False, False
    if fed == "*":
        vals: List[str] = []
        wild = True
    else:
        vals = _as_list(fed)
        wild = False
    mixed = False
    for key in principal.keys():
        if str(key).lower() != "federated":
            mixed = True
    # A list with several federated providers is a mixed principal.  The proof
    # core models one issuer at a time; a statement that trusts two issuers needs
    # two separately certified statements.
    if len(vals) != 1:
        mixed = True
    malformed = bool(vals) and not all(_is_exact_github_principal(v) for v in vals)
    return vals, wild, unsupported, mixed, malformed


def parse_aws_trust(policy: Mapping[str, Any]) -> List[StatementConstraints]:
    stmts = policy.get("Statement", [])
    if isinstance(stmts, Mapping):
        stmts = [stmts]
    out: List[StatementConstraints] = []
    for st_obj in stmts:
        if not isinstance(st_obj, Mapping):
            continue
        action = _as_list(st_obj.get("Action"))
        fed, wild, bad_principal, mixed_principal, malformed_principal = _federated_principals(st_obj.get("Principal"))
        sc = StatementConstraints(effect=str(st_obj.get("Effect", "Allow")),
                                  action=action,
                                  principal_federated=fed,
                                  principal_wildcard=wild,
                                  unsupported_principal=bad_principal,
                                  mixed_principal=mixed_principal,
                                  malformed_principal=malformed_principal)
        for field_name in ("NotAction", "NotPrincipal", "Resource", "NotResource"):
            if st_obj.get(field_name) is not None:
                sc.unsupported_statement_fields.append(field_name)
        if _is_web_identity_action(sc.action) and not _has_exact_web_identity_action(sc.action):
            sc.unsupported_statement_fields.append("Action")
        cond = st_obj.get("Condition", {}) or {}
        if isinstance(cond, Mapping):
            for op, kv in cond.items():
                op_l = _op_name(str(op), sc)
                if op_l is None:
                    continue
                if not isinstance(kv, Mapping):
                    sc.unsupported_conditions.append(str(op))
                    continue
                for raw_key, raw_vals in kv.items():
                    claim = _norm_claim(str(raw_key), sc)
                    if claim is None:
                        continue
                    vals = _condition_values(raw_vals, sc, str(op))
                    if vals is None:
                        continue
                    if op_l in SUPPORTED_EQUALS:
                        sc.equals.setdefault(claim, []).extend(vals)
                    elif op_l in SUPPORTED_LIKE:
                        sc.likes.setdefault(claim, []).extend(vals)
                    else:
                        sc.unsupported_conditions.append(str(op))
        else:
            sc.unsupported_conditions.append("Condition")
        out.append(sc)
    return out


def _has_exact_web_identity_action(action: List[str]) -> bool:
    acts = [a.lower() for a in action]
    return acts == [WEB_IDENTITY_ACTION]


def _is_web_identity_action(action: List[str]) -> bool:
    acts = [a.lower() for a in action]
    # Wildcard or pattern statements are included so the analyzer can report an
    # outside-core boundary, but only a singleton exact web-identity action is
    # eligible for a positive proof.  In particular, sts:* denotes the target
    # action and must not disappear as a misleading no-web-identity finding.
    return any(a == WEB_IDENTITY_ACTION or fnmatchcase(WEB_IDENTITY_ACTION, a) for a in acts)


def allow_statements_for_web_identity(policy: Mapping[str, Any]) -> List[StatementConstraints]:
    return [st for st in parse_aws_trust(policy)
            if st.effect.lower() == "allow" and _is_web_identity_action(st.action)]


def deny_statements_for_web_identity(policy: Mapping[str, Any]) -> List[StatementConstraints]:
    return [st for st in parse_aws_trust(policy)
            if st.effect.lower() == "deny" and _is_web_identity_action(st.action)]
