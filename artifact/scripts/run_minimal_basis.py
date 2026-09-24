#!/usr/bin/env python3
from __future__ import annotations
import csv, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from fedfence.projection import (  # noqa: E402
    BASIS_PREDICATES,
    CLAIM_PROJECTIONS,
    claim_definability_counterexample,
    minimal_claim_bases,
    projection_from_fields,
    sample_space,
)

REGIMES = {
    "default-subject-only": ["default_sub"],
    "documented-subject-template": ["repo", "context"],
    "refined-subject-template": ["refined_sub"],
    "structured-claims": ["repository_id", "event", "ref", "environment", "repo_class"],
    "all-claims": list(CLAIM_PROJECTIONS.keys()),
}
BASIS_UNIVERSE = ["repo", "repository_id", "event", "ref", "environment", "context", "repo_class"]

def describe_state(s):
    return {"org": s.org, "repo": s.repo, "event": s.event, "ref": s.ref, "environment": s.environment, "repo_class": s.repo_class}

def main() -> int:
    states = sample_space()
    out = ROOT / "results"; out.mkdir(exist_ok=True)
    rows = []
    witnesses = {}
    basis_rows = []
    for pred_name, pred in BASIS_PREDICATES.items():
        for regime, claims in REGIMES.items():
            proj = projection_from_fields(claims)
            ce = claim_definability_counterexample(states, proj, pred)
            rows.append({"predicate": pred_name, "regime": regime, "claims": "+".join(claims), "definable": ce is None})
            if ce is not None:
                pos, neg, claim = ce
                witnesses[f"{pred_name}/{regime}"] = {"claim": list(claim) if isinstance(claim, tuple) else claim, "positive_state": describe_state(pos), "negative_state": describe_state(neg)}
        bases = minimal_claim_bases(states, pred, BASIS_UNIVERSE)
        basis_rows.append({"predicate": pred_name, "min_cardinality": len(bases[0]) if bases else -1, "bases": ";".join("+".join(b) for b in bases)})
    with (out / "minimal_basis.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["predicate", "min_cardinality", "bases"]); w.writeheader(); w.writerows(basis_rows)
    with (out / "projection_regimes.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["predicate", "regime", "claims", "definable"]); w.writeheader(); w.writerows(rows)
    (out / "projection_witnesses.json").write_text(json.dumps(witnesses, indent=2, sort_keys=True) + "\n")
    overall = {"states": len(states), "predicates": len(BASIS_PREDICATES), "regimes": len(REGIMES), "rows": len(rows), "nondefinable": len(witnesses), "basis_rows": len(basis_rows)}
    (out / "minimal_basis_overall.json").write_text(json.dumps(overall, indent=2, sort_keys=True) + "\n")
    print(json.dumps(overall, indent=2, sort_keys=True))
    return 0
if __name__ == "__main__":
    raise SystemExit(main())
