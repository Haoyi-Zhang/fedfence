"""Bounded checks of the manuscript's set-theoretic propositions."""
from itertools import product
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from fse_workflow.io import save_json

def powerset(xs):
 xs=list(xs);return [set(x for i,x in enumerate(xs) if m>>i&1) for m in range(1<<len(xs))]
def image(M,p):return {p[w] for w in M}
def safe(M,I,p):return image(M,p)-image(M-I,p)
def admitted(M,E,p):return {w for w in M if p[w] in E}
S=powerset(range(4));Y=powerset(range(2));realizability=0;restriction=0;refinement=0;monotonicity=0
for p in product(range(2),repeat=4):
 for M in S:
  for I in S:
   H=safe(M,I,p)
   for Q in Y:
    witnesses=[E for E in Y if admitted(M,E,p)<=I and Q<=image(M,p)&E]
    assert bool(witnesses)==(Q<=H)
    if witnesses:assert admitted(M,Q,p)<=I
    realizability+=1
   for M2 in S:
    if M2<=M:
     assert H&image(M2,p)<=safe(M2,I,p);restriction+=1
   for I2 in S:
    if I<=I2:
     assert H<=safe(M,I2,p);monotonicity+=1
for fine in product(range(2),repeat=4):
 for f in product(range(2),repeat=2):
  coarse=tuple(f[y] for y in fine)
  for M in S:
   for I in S:
    fine_safe=admitted(M,safe(M,I,fine),fine);coarse_safe=admitted(M,safe(M,I,coarse),coarse)
    assert coarse_safe<=fine_safe;refinement+=1
obj=dict(schema='fedfence-relational-audit-v1',passed=True,states=4,observations=2,checks=dict(two_sided_realizability=realizability,governance_restriction=restriction,intent_monotonicity=monotonicity,observation_refinement=refinement),claim_boundary='finite counterexample search for elementary set-theoretic propositions, not a proof assistant or provider equivalence')
save_json(ROOT/'tosem/results/relational_audit.json',obj);print(obj)
