"""A separate owner-reviewed specification, not an intent inferred from IAM.

Reviewer identities and source references are asserted metadata, NOT signatures.
Enforcement of reviewer identity belongs in a separately trusted review process.
"""
from __future__ import annotations
from datetime import datetime, timezone
import re
from .io import digest

class InvalidPacket(ValueError):
    def __init__(self, code, detail):
        self.code = code
        super().__init__(detail)


def timestamp(value):
    if not isinstance(value, str):
        raise InvalidPacket("invalid-timestamp", "timezone-aware ISO timestamp required")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InvalidPacket("invalid-timestamp", str(exc)) from exc
    if parsed.tzinfo is None:
        raise InvalidPacket("invalid-timestamp", "timezone is required")
    return parsed.astimezone(timezone.utc)


def contract_digest(contract):
    return digest({k: v for k, v in contract.items() if k != "review"})


def exact_names(values, field, slash=True):
    if not isinstance(values, list) or any(not isinstance(x, str) or not x for x in values):
        raise InvalidPacket("invalid-intent", f"{field} must be a list of nonempty strings")
    pattern = r"[A-Za-z0-9_.\-/]+" if slash else r"[A-Za-z0-9_.\-]+"
    if any(re.fullmatch(pattern, v) is None for v in values) or len(values) != len(set(values)):
        raise InvalidPacket("invalid-intent", f"{field}: only distinct literal names in this profile")
    return values


def compile_contract(contract):
    if not isinstance(contract, dict) or contract.get("schema") != "fedfence-intent-v1":
        raise InvalidPacket("invalid-contract", "expected fedfence-intent-v1")
    required = {"schema", "repository", "target_role", "intent", "author", "max_snapshot_age_seconds", "review"}
    allowed = required | {"required_tokens"}
    if not required.issubset(contract) or set(contract) - allowed:
        raise InvalidPacket("invalid-contract", "missing or unknown contract fields")
    repo = contract["repository"]
    if not isinstance(repo, str) or re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo) is None:
        raise InvalidPacket("invalid-repository", "exact owner/repository required")
    if not isinstance(contract["target_role"], str) or not contract["target_role"]:
        raise InvalidPacket("invalid-target", "nonempty role target required")
    age = contract["max_snapshot_age_seconds"]
    if type(age) is not int or not 0 < age <= 31*86400:
        raise InvalidPacket("invalid-freshness-policy", "age must be an integer from 1 second to 31 days")
    review = contract["review"]
    if not isinstance(review, dict) or review.get("basis") != "owner-supplied-specification":
        raise InvalidPacket("unreviewed-intent", "owner-supplied specification review required")
    if not isinstance(contract["author"], str) or not contract["author"] or not isinstance(review.get("reviewer"), str) or not review["reviewer"] or review["reviewer"] == contract["author"]:
        raise InvalidPacket("unreviewed-intent", "distinct declared author/reviewer required")
    if not isinstance(review.get("reference"), str) or not review["reference"]:
        raise InvalidPacket("unreviewed-intent", "review record reference required")
    if review.get("approved_digest") != contract_digest(contract):
        raise InvalidPacket("unapproved-contract-change", "review digest does not match current specification")
    intent = contract["intent"]
    if not isinstance(intent, dict) or set(intent) != {"branches", "tags", "pull_request", "environments", "audiences"}:
        raise InvalidPacket("invalid-intent", "expected branches, tags, pull_request, environments, audiences")
    if type(intent["pull_request"]) is not bool:
        raise InvalidPacket("invalid-intent", "pull_request must be Boolean")
    branches = exact_names(intent["branches"], "branches")
    tags = exact_names(intent["tags"], "tags")
    audiences = exact_names(intent["audiences"], "audiences")
    if not audiences:
        raise InvalidPacket("invalid-intent", "at least one audience is required")
    subs = [f"repo:{repo}:ref:refs/heads/{b}" for b in branches]
    subs += [f"repo:{repo}:ref:refs/tags/{t}" for t in tags]
    if intent["pull_request"]:
        subs.append(f"repo:{repo}:pull_request")
    envs = intent["environments"]
    if not isinstance(envs, list):
        raise InvalidPacket("invalid-intent", "environments must be an array")
    names = set()
    for env in envs:
        if not isinstance(env, dict) or set(env) != {"name", "allowed_refs"}:
            raise InvalidPacket("invalid-intent", "environment needs name and allowed_refs")
        exact_names([env["name"]], "environment name", slash=False)
        if env["name"] in names:
            raise InvalidPacket("invalid-intent", "duplicate environment")
        names.add(env["name"])
        refs = exact_names(env["allowed_refs"], "environment allowed_refs")
        if not refs or any(not x.startswith(("refs/heads/", "refs/tags/")) for x in refs):
            raise InvalidPacket("invalid-intent", "environment must name exact allowed refs")
        subs.append(f"repo:{repo}:environment:{env['name']}")
    if not subs:
        raise InvalidPacket("invalid-intent", "at least one intended release identity is required")
    return {"allowed_subjects": subs, "allowed_audiences": audiences}


def compile_required_tokens(contract, spec):
    """Validate finite positive regression examples from the reviewed contract.

    These examples are not inferred from the policy and are not a complete intent
    language.  They state concrete deployment identities that must remain usable
    across a configuration change.
    """
    raw = contract.get("required_tokens", [])
    if not isinstance(raw, list):
        raise InvalidPacket("invalid-required-token", "required_tokens must be an array")
    out = []
    seen = set()
    for index, item in enumerate(raw):
        if not isinstance(item, dict) or set(item) != {"sub", "aud", "reason"}:
            raise InvalidPacket("invalid-required-token", f"required_tokens[{index}] needs sub, aud, and reason")
        if any(not isinstance(item[key], str) or not item[key] for key in ("sub", "aud", "reason")):
            raise InvalidPacket("invalid-required-token", f"required_tokens[{index}] fields must be nonempty strings")
        key = (item["sub"], item["aud"])
        if key in seen:
            raise InvalidPacket("invalid-required-token", "duplicate required token")
        seen.add(key)
        out.append(dict(item))
    return out


def check_snapshots(packet, contract, now):
    snaps = packet.get("snapshots")
    if not isinstance(snaps, dict) or set(snaps) != {"policy", "issuer", "workflow", "governance"}:
        raise InvalidPacket("missing-snapshot", "policy, issuer, workflow, and governance snapshots required")
    now = timestamp(now) if isinstance(now, str) else now
    if not isinstance(now, datetime) or now.tzinfo is None:
        raise InvalidPacket("invalid-check-time", "timezone-aware check time required")
    for name, snap in snaps.items():
        if not isinstance(snap, dict) or not isinstance(snap.get("body"), dict):
            raise InvalidPacket("invalid-snapshot", f"{name}: object body required")
        if snap.get("sha256") != digest(snap["body"]):
            raise InvalidPacket("snapshot-digest-mismatch", f"{name}: content and digest disagree")
        if not isinstance(snap.get("source"), str) or not snap["source"]:
            raise InvalidPacket("missing-provenance", f"{name}: source reference required")
        age = (now - timestamp(snap.get("observed_at"))).total_seconds()
        if age < 0 or age > contract["max_snapshot_age_seconds"]:
            raise InvalidPacket("stale-snapshot", f"{name}: snapshot age outside reviewed bound")
    repo = contract["repository"]
    for name in ("issuer", "workflow", "governance"):
        if snaps[name]["body"].get("repository") != repo:
            raise InvalidPacket("scope-mismatch", f"{name}: repository does not match the contract")
    if snaps["policy"].get("target_role") != contract["target_role"]:
        raise InvalidPacket("scope-mismatch", "policy snapshot targets a different role")
    issuer = snaps["issuer"]["body"]
    if issuer.get("provider") != "github-actions" or issuer.get("subject_mode") != "legacy-default" or issuer.get("version") != "github-legacy-sub-aud-v1":
        raise InvalidPacket("unsupported-issuer-profile", "this gate iteration only supports the explicit legacy-default profile")
    protected = []
    governance = snaps["governance"]["body"]
    env_rules = governance.get("environments")
    if not isinstance(env_rules, dict):
        raise InvalidPacket("invalid-governance", "normalized environments mapping required")
    for env in contract["intent"]["environments"]:
        rule = env_rules.get(env["name"])
        if not isinstance(rule, dict) or rule.get("bypass_disabled") is not True or rule.get("reviewed") is not True:
            raise InvalidPacket("missing-governance-premise", f"{env['name']}: reviewed no-bypass rule required")
        refs = exact_names(rule.get("allowed_refs"), "governance allowed_refs")
        if not refs or not set(refs).issubset(env["allowed_refs"]) or not rule.get("source_ref"):
            raise InvalidPacket("unjustified-governance-premise", f"{env['name']}: exported refs not contained in intent")
        protected.append(f"{repo}:{env['name']}")
    return snaps, {"protected_environments": protected}
