#!/usr/bin/env python3
from __future__ import annotations
import csv, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from fedfence.projection import (  # noqa: E402
    CLAIM_PROJECTIONS,
    BASIS_PREDICATES,
    github_default_subject,
    github_refined_environment_subject,
    projection_from_fields,
    sample_space,
    claim_definability_counterexample,
    minimal_claim_bases,
)

PROJECTIONS = [
    ("default-subject", github_default_subject),
    ("refined-environment-subject", github_refined_environment_subject),
    ("subject-plus-ref", projection_from_fields(["default_sub", "ref"])),
    ("subject-plus-repo-class", projection_from_fields(["default_sub", "repo_class"])),
    ("subject-plus-ref-plus-repo-class", projection_from_fields(["default_sub", "ref", "repo_class"])),
]
CLAIM_BASIS_UNIVERSE = ["default_sub", "ref", "event", "environment", "repo", "repository_id", "repo_class"]

def describe_state(s):
    return {"org": s.org, "repo": s.repo, "event": s.event, "ref": s.ref, "environment": s.environment, "repo_class": s.repo_class}

def main() -> int:
    states = sample_space()
    rows = []
    witnesses = {}
    for pname, pred in BASIS_PREDICATES.items():
        for qname, proj in PROJECTIONS:
            ce = claim_definability_counterexample(states, proj, pred)
            definable = ce is None
            rows.append({"predicate": pname, "projection": qname, "definable": definable})
            if ce is not None:
                a, b, claim = ce
                witnesses[f"{pname}/{qname}"] = {
                    "claim": str(claim),
                    "positive_state": describe_state(a),
                    "negative_state": describe_state(b),
                }
    basis_rows = []
    for pname, pred in BASIS_PREDICATES.items():
        bases = minimal_claim_bases(states, pred, CLAIM_BASIS_UNIVERSE)
        if not bases:
            basis_rows.append({"predicate": pname, "basis": "<none>", "size": 0})
        for b in bases:
            basis_rows.append({"predicate": pname, "basis": "+".join(b), "size": len(b)})
    out = ROOT / "results"
    out.mkdir(exist_ok=True)
    with (out / "definability.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["predicate", "projection", "definable"])
        w.writeheader(); w.writerows(rows)
    with (out / "claim_basis.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["predicate", "basis", "size"])
        w.writeheader(); w.writerows(basis_rows)
    (out / "definability_witnesses.json").write_text(json.dumps(witnesses, indent=2, sort_keys=True))
    print(json.dumps({
        "states": len(states),
        "definability_rows": len(rows),
        "nondefinable": len(witnesses),
        "claim_basis_rows": len(basis_rows),
        "claim_universe": len(CLAIM_BASIS_UNIVERSE),
    }, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
