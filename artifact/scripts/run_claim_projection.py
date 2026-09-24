#!/usr/bin/env python3
from __future__ import annotations
import csv, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from fedfence.event import analyze_event_case, result_dict  # noqa: E402

PREFIX = "token.actions.githubusercontent.com:"
PRINCIPAL = "arn:aws:iam::000000000000:oidc-provider/token.actions.githubusercontent.com"
AUD = "sts.amazonaws.com"

def stmt(cond, effect="Allow"):
    return {"Effect": effect, "Principal": {"Federated": PRINCIPAL}, "Action": "sts:AssumeRoleWithWebIdentity", "Condition": cond}

def policy(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}

def ckey(k): return PREFIX + k

def base_states():
    return [
        {"id":"main-prod", "intended": True, "mintable": True, "claims": {"aud":AUD, "sub":"repo:acme/api:environment:prod", "repository":"acme/api", "repository_id":"R_100", "ref":"refs/heads/main", "environment":"prod", "job_workflow_ref":"acme/api/.github/workflows/deploy.yml@refs/heads/main", "repository_visibility":"private", "repository_custom_properties.tier":"prod"}},
        {"id":"dev-prod", "intended": False, "mintable": True, "claims": {"aud":AUD, "sub":"repo:acme/api:environment:prod", "repository":"acme/api", "repository_id":"R_100", "ref":"refs/heads/dev", "environment":"prod", "job_workflow_ref":"acme/api/.github/workflows/deploy.yml@refs/heads/dev", "repository_visibility":"private", "repository_custom_properties.tier":"prod"}},
        {"id":"main-staging", "intended": False, "mintable": True, "claims": {"aud":AUD, "sub":"repo:acme/api:environment:staging", "repository":"acme/api", "repository_id":"R_100", "ref":"refs/heads/main", "environment":"staging", "job_workflow_ref":"acme/api/.github/workflows/deploy.yml@refs/heads/main", "repository_visibility":"private", "repository_custom_properties.tier":"dev"}},
        {"id":"fork-main-prod", "intended": False, "mintable": True, "claims": {"aud":AUD, "sub":"repo:evil/api:environment:prod", "repository":"evil/api", "repository_id":"R_999", "ref":"refs/heads/main", "environment":"prod", "job_workflow_ref":"evil/api/.github/workflows/deploy.yml@refs/heads/main", "repository_visibility":"public", "repository_custom_properties.tier":"prod"}},
    ]

def cases():
    states=base_states()
    # Default subject exact environment cannot express branch-sensitive intent.
    yield {
        "name":"default_environment_subject_is_not_branch_definable",
        "expected_safe": False,
        "policy": policy(stmt({"StringEquals": {ckey("aud"): AUD, ckey("sub"): "repo:acme/api:environment:prod"}})),
        "states": states,
    }
    # A selected provider-specific ref claim refines the projection and proves the same intent.
    yield {
        "name":"refined_ref_environment_repository_safe",
        "expected_safe": True,
        "policy": policy(stmt({"StringEquals": {ckey("aud"): AUD, ckey("repository_id"): "R_100", ckey("ref"): "refs/heads/main", ckey("environment"): "prod"}})),
        "states": states,
    }
    # Repository names alone are not enough when a role owner declares immutable repository identity.
    yield {
        "name":"repository_name_without_id_overgrant",
        "expected_safe": False,
        "policy": policy(stmt({"StringEquals": {ckey("aud"): AUD, ckey("repository"): "acme/api", ckey("environment"): "prod"}})),
        "states": states,
    }
    yield {
        "name":"repository_id_ref_environment_safe",
        "expected_safe": True,
        "policy": policy(stmt({"StringEquals": {ckey("aud"): AUD, ckey("repository_id"): "R_100", ckey("ref"): "refs/heads/main", ckey("environment"): "prod"}})),
        "states": states,
    }
    yield {
        "name":"workflow_ref_cuts_unapproved_branch_workflow",
        "expected_safe": True,
        "policy": policy(stmt({"StringEquals": {ckey("aud"): AUD, ckey("job_workflow_ref"): "acme/api/.github/workflows/deploy.yml@refs/heads/main", ckey("repository_id"): "R_100", ckey("environment"): "prod"}})),
        "states": states,
    }
    yield {
        "name":"custom_property_without_ref_not_branch_safe",
        "expected_safe": False,
        "policy": policy(stmt({"StringEquals": {ckey("aud"): AUD, ckey("repository_custom_properties.tier"): "prod", ckey("environment"): "prod"}})),
        "states": states,
    }
    yield {
        "name":"custom_property_plus_ref_safe",
        "expected_safe": True,
        "policy": policy(stmt({"StringEquals": {ckey("aud"): AUD, ckey("repository_custom_properties.tier"): "prod", ckey("ref"): "refs/heads/main", ckey("environment"): "prod", ckey("repository_id"): "R_100"}})),
        "states": states,
    }

def main() -> int:
    out = ROOT / "results"; out.mkdir(exist_ok=True)
    rows=[]; ok=True
    for case in cases():
        res=analyze_event_case(case)
        correct = (res.safe == bool(case["expected_safe"]))
        ok = ok and correct
        data=result_dict(res)
        (out / f"{case['name']}.projection_result.json").write_text(json.dumps(data, indent=2, sort_keys=True)+"\n")
        rows.append({"case": case["name"], "expected_safe": case["expected_safe"], "fedfence_safe": res.safe, "correct": correct, "states": res.states, "admitted": res.admitted, "intended_admitted": res.intended_admitted, "findings":";".join(data["finding_kinds"])})
    with (out/"claim_projection.csv").open("w", newline="") as f:
        w=csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
    overall={"cases":len(rows), "correct":sum(1 for r in rows if r["correct"]), "unsafe":sum(1 for r in rows if not r["expected_safe"]), "states_per_case":4}
    (out/"claim_projection_overall.json").write_text(json.dumps(overall, indent=2, sort_keys=True)+"\n")
    print(json.dumps(overall, indent=2, sort_keys=True), flush=True)
    return 0 if ok else 1

if __name__ == "__main__":
    raise SystemExit(main())
