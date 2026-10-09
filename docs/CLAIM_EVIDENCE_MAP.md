# Claim-to-evidence map

All paths below are relative to the artifact root. A recorded local digest binds bytes to a supplied record; it does not prove the record's remote authenticity.

| Manuscript claim | Executable or source evidence | Scope and non-claim |
|---|---|---|
| Three-valued precedence and valid positive regression checks | `fse_workflow/decision.py`, `gate.py`, `conformance.py`; `tests/test_tosem_consistency.py` | Invalid premises yield unknown even with latent counterexamples. No deployment-failure oracle. |
| Must-safe observation characterization | Mathematical propositions in paper §4; `scripts/run_finite_audit.py`, `tosem/results/finite_semantics_audit.json` | Written set-theoretic proof plus bounded counterexample search. Not a proof-assistant mechanization or a provider implementation proof. |
| Two-sided realizability, intent/governance/observation relations | Paper section on relational changes; `scripts/run_relational_audit.py`, `tosem/results/relational_audit.json` | Abstract predicates can exist without being expressible in the supported AWS fragment. Required mintability must be rechecked after governance restriction. |
| Allow-minus-Deny is a tuple relation | `fse_workflow/conformance.py`, `fragment.py`; `scripts/run_tosem_validation.py` | Positive scalar checks and 56 literal strict-gate cases are not universal semantic equivalence to cloud IAM. |
| 204 regression tests | `scripts/run_fse_tests.py`; `tosem/results/unit_tests.json`; `logs/unit-tests.log` | Local synthetic assertions over the declared finite model. |
| 3,945 core checks | `artifact/scripts/self_check.py`; `logs/core-self-check.log` | Bounded word enumeration over a small alphabet plus symbolic named examples. |
| 65,536 finite decisions; 256 finite full replays | `tosem/results/two_sided_exhaustive.json`, `two_sided_samples.json` | Three atoms, five relation subsets, two invalidity settings. Distribution is generated design, not real-world prevalence. |
| 56 strict differential cases | `tosem/results/strict_literal_differential.csv` | Seven nonempty literal Allow subsets × eight Deny subsets; separately written finite expected result. Shared Python runtime, no cloud reference implementation. |
| Exact scalar matcher | Written DP recurrence and proof; `tosem/results/matcher_differential.json` | 242,580 bounded pairs agree with recursive enumeration and the inherited NFA; not full provider Unicode semantics. |
| Typed issuer refinements | `issuer_membership_differential.json`; `tests/test_final_boundaries.py` | 2,304 checks against the inherited grammar, including empty/default and audience refinements. |
| Complete bounded-glob oracle | Written finite-bound proof; `strict_glob_differential.json/.csv`; `bounded_glob_packets/` | Every Allow has finite equality bounds; all 192 generated packets agree, not arbitrary-policy completeness. |
| Joint freshness interval | Paper subsection on the joint freshness interval; staggered-time regression tests | Intersection of declared timestamp intervals, not authenticated remote capture. |
| Local recomputation measurements | `local_scaling.csv/.json`; generated plot data and plot-provenance audit | 54 recorded local runs plus 18 warm-ups; no benchmark competitor, confidence interval or deployment SLA. |
| Six dependency transformations | `tosem/results/dependency_metamorphic.json` | Workflow digest change invalidates a dependency, not a proof that workflow semantics are analyzed. |
| Eight seeded fault challenges | `scripts/run_seeded_faults.py`; `tosem/results/seeded_faults.json`; `logs/seeded_faults/` | Hand-selected single fault/test pairs with passing controls and assertion failures, not a representative mutation adequacy score. |
| Full-review replay checks required identities and dependencies | `fse_workflow/receipt.py`, `cli.py`; receipt regression tests | Reruns current gate; not a cache, independent checker, signature or provenance authentication. Successful replay retains fail/unknown verdicts. |
| 9 commits, 10 role contracts, 21 configurations | `scripts/run_tosem_studies.py`; `tosem/results/public_study.json/.csv` | Case reconstruction; seven finite-adapter cases and fourteen regular-language-adapter cases, not all strict packets. No denominator for a population rate. |
| Sports-store ECR and frontend role distinctions | `study/corrections.json`, corrected public rows, `tosem/results/repair_audit.json` | ECR fail→pass, frontend pass→pass in a seven-identity domain. Do not combine into one before/after role result. |
| Microticket default-empty and observed-binding distinction | Same repaired case records; three configuration rows | Empty branch remains fail. Observed-binding pass is conditional; actual variable assignment and deployment success not established. |
| 24 source excerpts | `tosem/results/source_frontier.json` | All excerpt hashes checked; zero complete source files available, zero full-source extractions executed. Inherited annotations are not extractor accuracy. |
| 12 maintenance metadata records | `tosem/results/maintenance_metadata.json` | Eleven annotated breakage reports, two recorded run IDs, zero live reproductions or independent root-cause adjudications. |
| Reproducible current entry point | `Makefile`, `scripts/reproduce_tosem.py`, `tosem/results/reproduction.json` | Ten actual local evidence steps followed by generated tables, paper build and consistency audit. |
| Complete character support | Manuscript Proposition `prop:character-support`; `artifact/fedfence/regular.py`; `docs/CHARACTER_DOMAIN_FIX.md` | Conditional on all primitive predicates being represented; not a proof of all implementation code or provider semantics. |
| 3,342,336 primitive comparisons | `scripts/run_character_domain_audit.py`; `tosem/results/character_domain_audit.json` | Three full-code-point predicate sweeps, not whole-string or policy enumeration. |
| 57,498 concrete/quotient comparisons; 60 constructor insertions | Same audit result | Explicit bounded pattern/word alphabets and five constructor positions; concrete words are not added to support. |
| Coverage failures cannot certify a result | 48 added unit tests; atomic versions 3/effective version 6; two rejection challenges | Shared parser/NFA assumptions remain; independent residual check does not create an independent whole-system checker. |

## Explicitly unsupported claims

No representative incidence or prevalence; no cloud deployment verification; no signature or reviewer identity verification; no live token issuance; no user-time or productivity effect; no measured superiority over Zelkova, Cedar, OPA, Checkov, ARGUS, or other tools; no full Terraform/Pulumi/host-language normalization; no workflow reachability or end-to-end release guarantee; no independently adjudicated accuracy; no theorem that the Python implementation refines the whole mathematical model.
