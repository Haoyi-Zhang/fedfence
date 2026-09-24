# Evidence Summary

This file maps the paper claims to artifact outputs.

| Claim family | Evidence file |
| --- | --- |
| Curated semantic cases | `results/case_summary.csv` |
| Witness and governance replay | `results/witness_replay.csv` |
| Documentation-derived examples | `results/public_examples.csv`, `results/public_examples_overall.json` |
| Standalone label audit | `results/label_audit.csv`, `results/label_audit_overall.json` |
| Independent baseline suite | `results/baseline_suite.csv`, `results/baseline_suite_summary.csv`, `results/baseline_suite_overall.json` |
| Governance export audit | `results/governance_export_rows.csv`, `results/governance_export_audit.json` |
| Deployment manifest interface | `results/deployment_manifest.csv`, `results/deployment_manifest_overall.json` |
| Definability model | `results/definability.csv`, `results/definability_witnesses.json` |
| Selected-claim projection | `results/claim_projection.csv`, `results/claim_projection_overall.json` |
| Proof certificates | `results/certificate_summary.csv`, `results/certificates/` |
| Certificate tamper rejection | `results/certificate_tamper.csv`, `results/certificate_tamper_overall.json` |
| Monotone repairs | `results/repair_summary.csv`, `results/repairs/` |
| Differential fuzzing | `results/differential_fuzz_overall.json`, `results/differential_fuzz.csv` |
| Metamorphic laws | `results/metamorphic_overall.json`, `results/metamorphic.csv` |
| Semantic-grid transport | `results/semantic_grid_overall.json`, `results/semantic_grid.csv` |
| IaC extractor invariance | `results/iac_overall.json`, `results/iac_rows.csv`, `results/iac_template_summary.csv` |
| Baseline comparison | `results/iac_baselines.csv`, `results/public_baselines.csv` |
| Synthetic scaling | `results/benchmark.csv` |
| Figure regeneration | `paper/figures/benchmark.pdf`, `paper/figures/iac_cdf.pdf` |
| Submission audit | `results/submission_audit.json` |
| Trusted-base map | `results/tcb_report.json`, `results/tcb_report.csv` |
| Implementation footprint | `results/code_metrics.json`, `results/code_metrics.csv` |
| Evidence ledger | `results/evidence_ledger.json` |

Submitted high-level results:

- 37 registered-profile curated and hardening cases: 13 safe and 24 unsafe or outside-core, including literal-star/literal-question equality regressions, glob-question versus literal-intent regression, unsupported set-operator boundary, action-wildcard boundary, unsupported-Allow erasure, supported-Deny narrowing, unsupported-Deny non-discharge, branch-slash subjects, and percent-encoded environment names.
- 20 public and documentation-derived examples: 6 safe and 14 unsafe or outside-core, drawn from official provider documentation and public troubleshooting/reference material, all classified according to the submitted labels.
- Standalone finite-domain label audit: recomputes all 37 registered, 20 public, and 8 optional public-issue challenge labels without importing the analyzer or certificate verifier; 65/65 agree with the submitted labels.
- Independent baseline suite: seven rule families over the same 65 rows; the strongest non-proof linter gets 61/65 correct, while FedFence gets 65/65.
- Governance export audit: six exported-settings fixtures with ten branch, tag, environment, and reusable-workflow premises; 10/10 match the expected fail-closed labels.
- Deployment-manifest interface: eight example role-review manifest rows run through the same proof path as registered cases; 8/8 agree with expected labels.
- 3,945 bounded and symbolic self-check comparisons, including operator-aware finite-support and unsupported-Allow erasure regressions.
- 37 effective case-level certificates emitted and 37 replayed successfully; 234 certificate-tamper trials are rejected.
- 2,000 randomized differential-fuzz obligations, all matching bounded enumeration.
- 768 metamorphic-law checks.
- Selected-claim projection: 7 finite event-space refinements, all classified as expected.
- 4,480 semantic-grid obligations: 35 representatives transported across delimiter-preserving service atoms, all classified according to generated labels.
- 3,360 IaC roles across direct trust JSON, Terraform JSON, and CloudFormation JSON: 1,248 safe and 2,112 unsafe or outside-core, all classified according to generated labels.
- Synthetic scaling through 64 intended subject patterns and one 65-pattern unsafe row.

The code-metrics report records the implementation and harness footprint and checks that registered cases, hardening cases, public examples, governance-export fixtures, and deployment-manifest inputs remain separated. The evidence ledger is a final claim-integrity check: it re-computes the title and abstract hashes, checks the compiled PDF page/font invariants, label-audit pass status, baseline-suite separation, and verifies that the registered-profile counts used in the paper are observable from regenerated `results/`. The `reference_results/` directory contains the paper-profile snapshot. Reruns write to `results/`; reviewers should expect identical labels and certificate checks but CPU-dependent timing.

Public evidence metadata includes a SHA-256 hash of each normalized JSON example, so reviewers can distinguish the submitted offline evidence from later edits to public pages.

## Additional acceptance-profile evidence

The paper-profile run also includes two independent stress checks that are not used to label the curated cases. `projection_laws.csv` exhaustively checks the finite-event Galois connection and kernel-saturation characterization over six observation regimes, producing 202,752 Galois checks and 1,536 saturation checks in the reference run. `adversarial_matrix.csv` instantiates 35 independently labeled policy families over 64 service atoms each, covering principal exactness, action exactness, claim-key namespace, literal-versus-glob operator semantics, supported and unsupported Deny, repository-scoped governance, and set-operator boundaries. The reference run classifies all 2,240 adversarial cases as expected.
