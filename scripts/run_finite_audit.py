"""Exhaustive finite sanity check, not a mechanized theorem or provider oracle."""
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT))
from fse_workflow.io import save_json
from itertools import product


def subsets(xs):
    xs=list(xs)
    return [frozenset(x for i,x in enumerate(xs) if mask>>i&1) for mask in range(1<<len(xs))]

U=range(4); domain_sets=subsets(U); obs_sets=subsets([0,1]); count=0; loose_counterexample=None
for projection in product([0,1],repeat=4):
    for M in domain_sets:
        for Phi in domain_sets:
            intended=M & Phi
            may_intent={projection[x] for x in intended}
            mintable_image={projection[x] for x in M}
            bad_image={projection[x] for x in M-intended}
            must_safe=mintable_image-bad_image
            saturated=not (may_intent & bad_image)
            for allow in obs_sets:
                for deny in obs_sets:
                    effective=allow-deny
                    actual={x for x in M if projection[x] in effective}
                    ground=actual.issubset(intended)
                    universal=(mintable_image & effective).issubset(must_safe)
                    assert universal == ground
                    if saturated:
                        assert ground == (mintable_image & effective).issubset(may_intent)
                    if not ground and (mintable_image & effective).issubset(may_intent) and loose_counterexample is None:
                        loose_counterexample={"projection":list(projection),"mintable":sorted(M),"intended":sorted(intended),
                                              "allow":sorted(allow),"deny":sorted(deny),"admitted":sorted(actual)}
                    count+=1
summary={"universe_states":4,"observation_values":2,"checked_models":count,"passed":True,
         "incorrect_existential_lifting_counterexample":loose_counterexample,
         "claim":"must-safe observation containment iff supplied-state safety; saturated case recovers existential image",
         "evidence_type":"bounded exhaustive consistency audit; not mechanization or provider equivalence"}
save_json(ROOT/'fse/results/finite_semantics_audit.json',summary)
print(summary)
