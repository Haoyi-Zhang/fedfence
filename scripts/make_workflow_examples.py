from pathlib import Path
import copy
import sys
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))
from fse_workflow.contract import contract_digest
from fse_workflow.fragment import PREFIX, ACTION
from fse_workflow.io import digest, save_json

OBS = "2026-09-23T00:00:00Z"

def snapshot(body, **kwargs):
    return {"body": body, "sha256": digest(body), "observed_at": OBS,
            "source": "synthetic-regression-fixture", **kwargs}


def packet():
    policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ACTION,
               "Principal": {"Federated": "arn:aws:iam::000000000000:oidc-provider/token.actions.githubusercontent.com"},
               "Condition": {"StringEquals": {PREFIX+"sub": "repo:acme/api:ref:refs/heads/main", PREFIX+"aud": "sts.amazonaws.com"}}}]}
    contract = {"schema": "fedfence-intent-v1", "repository": "acme/api", "target_role": "deploy-production",
                "intent": {"branches": ["main"], "tags": [], "pull_request": False, "environments": [], "audiences": ["sts.amazonaws.com"]},
                "author": "fixture-role-owner", "max_snapshot_age_seconds": 86400,
                "review": {"basis": "owner-supplied-specification", "reviewer": "fixture-security-reviewer", "reference": "fixture-review-1"}}
    contract["review"]["approved_digest"] = contract_digest(contract)
    return {"schema": "fedfence-review-packet-v1", "contract": contract,
            "snapshots": {"policy": snapshot(policy, target_role="deploy-production"),
                          "issuer": snapshot({"provider": "github-actions", "repository": "acme/api", "subject_mode": "legacy-default", "version": "github-legacy-sub-aud-v1"}),
                          "workflow": snapshot({"repository": "acme/api", "revision": "synthetic-revision-A", "description": "fixture, not executed workflow"}),
                          "governance": snapshot({"repository": "acme/api", "environments": {}})}}

def rehash(p, field):
    p["snapshots"][field]["sha256"] = digest(p["snapshots"][field]["body"])

def main():
    base = packet()
    wildcard = copy.deepcopy(base)
    st = wildcard["snapshots"]["policy"]["body"]["Statement"][0]
    st["Condition"]["StringEquals"].pop(PREFIX+"sub")
    st["Condition"]["StringLike"] = {PREFIX+"sub": "repo:acme/api:*"}
    rehash(wildcard, "policy")
    stale = copy.deepcopy(base); stale["snapshots"]["governance"]["observed_at"] = "2026-09-20T00:00:00Z"
    unsupported = copy.deepcopy(base)
    unsupported["snapshots"]["policy"]["body"]["Statement"][0]["Condition"]["StringEqualsIfExists"] = {PREFIX+"aud": "sts.amazonaws.com"}
    rehash(unsupported, "policy")
    env = copy.deepcopy(base)
    env["contract"]["intent"]["branches"] = []
    env["contract"]["intent"]["environments"] = [{"name": "prod", "allowed_refs": ["refs/heads/main"]}]
    env["contract"]["review"]["approved_digest"] = contract_digest(env["contract"])
    env["snapshots"]["policy"]["body"]["Statement"][0]["Condition"]["StringEquals"][PREFIX+"sub"] = "repo:acme/api:environment:prod"
    rehash(env, "policy")
    env_ok = copy.deepcopy(env)
    env_ok["snapshots"]["governance"]["body"]["environments"] = {"prod": {"allowed_refs": ["refs/heads/main"], "reviewed": True, "bypass_disabled": True, "source_ref": "fixture-environment-review"}}
    rehash(env_ok, "governance")

    # Two-sided conformance example. Both policies remain inside the reviewed
    # intent {main, release}, but the after policy drops the concrete main token
    # that the owner marked as required for deployment continuity.
    availability_before = copy.deepcopy(base)
    main_sub = availability_before["snapshots"]["policy"]["body"]["Statement"][0]["Condition"]["StringEquals"][PREFIX+"sub"]
    release_sub = main_sub.replace("/main", "/release")
    availability_before["contract"]["intent"]["branches"] = ["main", "release"]
    availability_before["contract"]["required_tokens"] = [{
        "sub": main_sub,
        "aud": "sts.amazonaws.com",
        "reason": "the production main-branch deployment must remain usable",
    }]
    availability_before["contract"]["review"]["approved_digest"] = contract_digest(availability_before["contract"])
    availability_before["snapshots"]["policy"]["body"]["Statement"][0]["Condition"]["StringEquals"][PREFIX+"sub"] = [main_sub, release_sub]
    rehash(availability_before, "policy")
    availability_after = copy.deepcopy(availability_before)
    availability_after["snapshots"]["policy"]["body"]["Statement"][0]["Condition"]["StringEquals"][PREFIX+"sub"] = release_sub
    rehash(availability_after, "policy")

    for name, obj in {"before": base, "after_wildcard": wildcard, "after_stale": stale, "after_unsupported": unsupported,
                      "environment_missing": env, "environment_reviewed": env_ok,
                      "availability_before": availability_before, "availability_after": availability_after}.items():
        save_json(ROOT/"examples/release_gate"/(name+".json"), obj)

if __name__ == "__main__": main()
