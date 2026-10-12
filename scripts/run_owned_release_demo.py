"""Run one owned source-to-generator-to-program experiment, without networking.

This is a separate local application experiment, not another native science
stage, a public deployment, an IAM permission interpreter, or a CI run.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from itertools import product
import json
from pathlib import Path
import platform
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "artifact"))
from fedfence.iac import extract_file
from fedfence.repair import synthesize_repair
from fse_workflow.conformance import effective_policy_accepts
from fse_workflow.contract import contract_digest
from fse_workflow.fragment import PREFIX, inspect_policy
from fse_workflow.gate import review
from fse_workflow.io import digest, load_json, save_json
from fse_workflow.receipt import make_receipt, replay_receipt
from owned_demo.release_bundle import OPERATIONS

FIXTURES = ROOT / "owned_demo"
NOW = "2026-10-11T01:00:00Z"
OBSERVED = "2026-10-11T00:00:00Z"


def require(condition, detail):
    if not condition:
        raise ValueError(detail)


def workflow_contract(workflow):
    require(workflow["schema"] == "fedfence-owned-release-workflow-v1", "workflow schema")
    require(workflow["repository"] == "owned/catalog", "owned repository scope")
    require(workflow["target_role"] == "catalog-publisher", "owned role scope")
    require(workflow["audience"] == "sts.amazonaws.com", "owned audience")
    require(workflow["jobs"] == [{"id": "primary-release", "branch": "main"},
                                  {"id": "maintenance-release", "branch": "release"}], "fixed owned jobs")
    required = workflow["required_permissions"]
    require([(r["action"], r["resource"]) for r in required] == list(OPERATIONS),
            "required permissions must correspond to the executable operations")
    require(all(isinstance(r["reason"], str) and r["reason"] for r in required), "operation rationale")
    permitted = {(r["action"], r["resource"]) for r in workflow["permitted_permissions"]}
    require(set(OPERATIONS) <= permitted, "inconsistent permission bounds")
    identities = [{"sub": f"repo:owned/catalog:ref:refs/heads/{j['branch']}",
                   "aud": workflow["audience"]} for j in workflow["jobs"]]
    contract = {"schema": "fedfence-intent-v1", "repository": workflow["repository"],
                "target_role": workflow["target_role"], "author": "owned-fixture-author",
                "max_snapshot_age_seconds": 86400,
                "intent": {"branches": ["main", "release"], "tags": [],
                           "pull_request": False, "environments": [], "audiences": [workflow["audience"]]},
                "required_tokens": [{**t, "reason": "Execute catalog read and both publication writes"} for t in identities],
                "review": {"basis": "owner-supplied-specification", "reviewer": "owned-fixture-reviewer",
                           "reference": "self-constructed local contract; metadata is not authenticated"}}
    contract["review"]["approved_digest"] = contract_digest(contract)
    required_permissions = [{**t, "action": a, "resource": r} for t in identities for a, r in OPERATIONS]
    allowed_permissions = [{**t, "action": a, "resource": r} for t in identities for a, r in sorted(permitted)]
    return contract, required_permissions, allowed_permissions


def packet_for(contract, workflow, trust):
    bodies = {"policy": trust, "workflow": workflow,
              "issuer": {"repository": workflow["repository"], "provider": "github-actions",
                         "subject_mode": "legacy-default", "version": "github-legacy-sub-aud-v1"},
              "governance": {"repository": workflow["repository"], "environments": {}}}
    snaps = {k: {"body": v, "sha256": digest(v), "observed_at": OBSERVED,
                 "source": "owned local fixture, not authenticated provider capture"} for k, v in bodies.items()}
    snaps["policy"]["target_role"] = contract["target_role"]
    return {"schema": "fedfence-review-packet-v1", "contract": contract, "snapshots": snaps}


def atom(record):
    return tuple(record[k] for k in ("sub", "aud", "action", "resource"))


def direct_trust_relation(trust):
    """Independent exact-literal tuple expansion; no scalar matcher or analyzer.

    Equality bounds exhaust the trust language, so these comparisons have a
    complete finite policy domain, not a sample inferred from successful runs.
    """
    require(inspect_policy(trust)["supported"], "unsupported direct-baseline input")
    allow, deny = set(), set()
    for statement in trust["Statement"]:
        conditions = statement["Condition"]
        require(set(conditions) == {"StringEquals"}, "baseline requires finite literal bounds")
        eq = conditions["StringEquals"]
        require(set(eq) == {PREFIX + "sub", PREFIX + "aud"}, "baseline requires both coordinates")
        subjects, audiences = eq[PREFIX + "sub"], eq[PREFIX + "aud"]
        subjects = [subjects] if isinstance(subjects, str) else subjects
        audiences = [audiences] if isinstance(audiences, str) else audiences
        (allow if statement["Effect"] == "Allow" else deny).update(product(subjects, audiences))
    return allow - deny


def compare_bounds(policy, required, allowed, gate_result):
    """Same-information baselines; the upper-only variant ignores the lower bound."""
    packet = gate_result["packet"]
    contract = packet["contract"]
    intended = {(f"repo:owned/catalog:ref:refs/heads/{b}", "sts.amazonaws.com") for b in contract["intent"]["branches"]}
    positives = {(t["sub"], t["aud"]) for t in contract["required_tokens"]}
    effective = direct_trust_relation(policy["trust"])
    upper_trust = effective <= intended
    lower_trust = positives <= effective
    direct_permissions = {atom(r) for r in policy["permissions"] if (r["sub"], r["aud"]) in effective}
    lower_permissions = {atom(r) for r in required} <= direct_permissions
    upper_permissions = direct_permissions <= {atom(r) for r in allowed}
    # Separately evaluate every concrete grant/obligation with the executable
    # scalar recognizer, then compare with the direct set calculation.
    scalar_permissions = [r for r in policy["permissions"] if effective_policy_accepts(policy["trust"], r)]
    local_upper = all(r in allowed for r in scalar_permissions)
    local_lower = all(r in scalar_permissions for r in required)
    require((local_upper, local_lower) == (upper_permissions, lower_permissions), "permission oracle disagreement")
    expected_trust = "pass" if upper_trust and lower_trust else "fail"
    require(gate_result["result"]["verdict"] == expected_trust, "strict/direct trust disagreement")
    combined = "pass" if expected_trust == "pass" and local_upper and local_lower else "fail"
    direct = "pass" if upper_trust and lower_trust and upper_permissions and lower_permissions else "fail"
    require(combined == direct, "combined/direct lattice disagreement")
    return {"upper_only": "pass" if upper_trust and upper_permissions else "fail",
            "direct_two_sided_lattice": direct, "trust_gate": expected_trust, "combined_local": combined,
            "upper_trust": upper_trust, "lower_trust": lower_trust,
            "upper_permissions": upper_permissions, "lower_permissions": lower_permissions}


def verify_bundle(root):
    """Check expected output content without reusing the publisher's computation."""
    got = load_json(root / "dist/catalog.json")
    require(got == {"count": 2, "products": [
        {"id": "mug", "name": "Blue mug", "price_cents": 1999},
        {"id": "notebook", "name": "Notebook <A>", "price_cents": 2500}]}, "catalog content")
    page = (root / "dist/index.html").read_text(encoding="utf-8")
    require(page == "<!doctype html><title>Catalog</title><ul><li>Blue mug: 1999 cents</li>"
                    "<li>Notebook &lt;A&gt;: 2500 cents</li></ul>\n", "rendered content/escaping")


def run(out: Path):
    out = out.resolve()
    require(out.is_relative_to(ROOT.resolve()), "output must remain inside this candidate artifact")
    require(not out.exists(), "output directory must be new; prior runs are preserved")
    out.mkdir(parents=True)
    workflow = load_json(FIXTURES / "workflow.json")
    contract, required, allowed = workflow_contract(workflow)
    extracted = extract_file(FIXTURES / "source.tf.json")
    require(len(extracted) == 1 and extracted[0].role_name == contract["target_role"], "owned frontend role")
    case = extracted[0].case
    require(inspect_policy(case["policy"])["supported"], "source fragment")
    require(set(case["spec"]["allowed_subjects"]) == {t["sub"] for t in contract["required_tokens"]}, "source/contract subjects")
    require(case["spec"]["allowed_audiences"] == [workflow["audience"]], "source/contract audience")
    repaired, meta = synthesize_repair(case, add_governance=False)
    require(not meta["environment_governance_added"], "do not invent governance")
    save_json(out / "extracted_case.json", case)
    save_json(out / "generator_metadata.json", meta)
    save_json(out / "generated_case.json", repaired)
    # Re-enter the existing frontend with actual serialized generated output.
    require(extract_file(out / "generated_case.json")[0].case == repaired, "generated frontend roundtrip")
    base = {"trust": repaired["policy"], "permissions": allowed}
    save_json(out / "generated_policy.json", base)
    variants = {"source_before": {"trust": case["policy"], "permissions": allowed}, "generated": base}
    loss = deepcopy(base)
    loss["trust"]["Statement"][0]["Condition"]["StringEquals"][PREFIX + "sub"] = contract["required_tokens"][0]["sub"]
    variants["required_release_removed"] = loss
    empty = deepcopy(base)
    denial = deepcopy(empty["trust"]["Statement"][0]); denial["Effect"] = "Deny"
    empty["trust"]["Statement"].append(denial)
    variants["empty_effective_trust"] = empty
    missing = deepcopy(base)
    missing["permissions"] = [r for r in missing["permissions"] if not (r["sub"].endswith("/main") and r["resource"] == "dist/index.html")]
    variants["required_page_write_removed"] = missing
    optional = deepcopy(base)
    optional["permissions"] = [r for r in optional["permissions"] if not (r["action"] == "read" and r["resource"] == "dist/catalog.json")]
    variants["optional_read_removed"] = optional
    excess = deepcopy(base)
    excess["permissions"].append({**contract["required_tokens"][0], "action": "read", "resource": "private/notes.txt"})
    excess["permissions"][-1].pop("reason")
    variants["unrelated_permission_added"] = excess
    rows = []
    for name, policy in variants.items():
        directory = out / name; directory.mkdir()
        save_json(directory / "policy.json", policy)
        packet = packet_for(contract, workflow, policy["trust"])
        result = review(packet, now=NOW)
        require(result["replay_ok"], f"{name}: backend replay")
        receipt = make_receipt(packet, result)
        replayed = replay_receipt(receipt, now=NOW)
        require(replayed.get("receipt_replay_ok"), f"{name}: full receipt replay")
        save_json(directory / "packet.json", packet)
        save_json(directory / "review.json", result)
        save_json(directory / "receipt.json", receipt)
        bounds = compare_bounds(policy, required, allowed, {"packet": packet, "result": result})
        executions = []
        for job in workflow["jobs"]:
            work = directory / job["id"]; (work / "input").mkdir(parents=True)
            (work / "input/catalog.json").write_bytes((FIXTURES / "input/catalog.json").read_bytes())
            command = [sys.executable, "-B", str(FIXTURES / "release_bundle.py"), "--root", str(work),
                       "--policy", str(directory / "policy.json"), "--branch", job["branch"],
                       "--result", str(work / "execution.json")]
            proc = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
            execution = load_json(work / "execution.json")
            token = {"sub": f"repo:owned/catalog:ref:refs/heads/{job['branch']}", "aud": workflow["audience"]}
            expected = effective_policy_accepts(policy["trust"], token) and all({**token, "action": a, "resource": r} in policy["permissions"] for a, r in OPERATIONS)
            require(proc.returncode == (0 if expected else 1), f"{name}/{job['id']}: execution exit")
            require(execution["status"] == ("completed" if expected else "blocked"), "execution status")
            if expected:
                verify_bundle(work)
                require(execution["trace"] == [{"action": a, "resource": r} for a, r in OPERATIONS], "actual operation trace")
            else:
                require(not (work / "dist/index.html").exists(), "blocked job must not complete page publication")
            executions.append({"job": job["id"], "exit_code": proc.returncode, **execution,
                               "functional_content_verified": expected})
        rows.append({"variant": name, **bounds, "required_tokens": len(contract["required_tokens"]),
                     "required_permissions": len(required), "executions": executions})
    # A syntactically extracted but unresolved input must never enter synthesis.
    dynamic = deepcopy(load_json(FIXTURES / "source.tf.json"))
    dynamic["resource"]["aws_iam_role"]["catalog-publisher"]["assume_role_policy"]["Statement"][0]["Condition"]["StringEquals"][PREFIX + "sub"] = "${var.release_subject}"
    save_json(out / "unresolved.tf.json", dynamic)
    unsupported = extract_file(out / "unresolved.tf.json")
    support = inspect_policy(unsupported[0].case["policy"])
    require(not support["supported"], "unresolved source refused before generation")
    save_json(out / "frontier.json", {"owned_source_files": 2, "executed_extractions": 2,
              "literal_supported": 1, "unresolved_refused_before_generator": 1,
              "public_source_records_changed": 0, "unresolved_support": support})
    result = {"schema": "fedfence-owned-release-demo-v1", "status": "pass",
              "python": sys.version, "platform": platform.platform(),
              "source_chain": "extract_file -> synthesize_repair -> strict gate and receipt -> executable local publisher",
              "scope": "Owned exact local application permissions; not AWS permission enforcement or CI deployment",
              "execution_kind": "manual local Python subprocesses, not native CI",
              "required_identity_count": 2, "required_permission_count": len(required),
              "variants": rows, "public_counts_unchanged": True, "remote_writes": False,
              "operational_tokens_used": False, "external_deployments": 0}
    save_json(out / "summary.json", result)
    print(json.dumps({"status": "pass", "variants": len(rows), "executions": sum(len(r["executions"]) for r in rows),
                      "completed": sum(e["status"] == "completed" for r in rows for e in r["executions"]),
                      "required_permissions": len(required), "summary": str(out / "summary.json")}, sort_keys=True))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    run(args.out)


if __name__ == "__main__":
    main()
