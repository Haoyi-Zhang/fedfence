# Artifact Evaluation Notes

## Claimed support

This artifact supports functional and reproduced-results evaluation. It includes source code, curated inputs, documentation-derived examples, generated outputs, IaC extraction logic, proof-certificate replay, witness replay, repair checks, differential fuzzing, metamorphic checks, semantic-grid transport, and scripts to regenerate the paper's tables and vector figures without network access.

## Hardware and runtime

The artifact is CPU-only. It does not require a GPU, cluster, cloud account, container registry, cloud credentials, or a live GitHub repository. Timing values are machine-dependent; verdicts, witnesses, certificate replay, corpus cardinalities, and generated labels are deterministic.

## Reproduction steps

```bash
cd artifact
./scripts/reproduce_all.sh
```

The script runs these stages: code audit, trusted-base report, self-check, curated cases, witness replay, definability, selected-claim projection, public examples, effective case-level certificates, repairs, differential fuzzing, metamorphic laws, synthetic scaling, IaC mutation corpus, semantic-grid transport, figure generation, submission audit, and evidence ledger.

## Expected high-level results

- 37 registered-profile curated cases: 13 safe and 24 unsafe or outside-core. Three optional boundary-hardening cases live in `hardening_cases/` and are reported separately.
- 20 public and documentation-derived examples: 6 safe and 14 unsafe or outside-core.
- Self-check: 3,945 bounded and symbolic comparisons.
- Certificates: 37 emitted and 37 independently verified; 234 certificate-tamper trials rejected.
- Differential fuzzing: 2,000 randomized obligations, all matching bounded enumeration.
- Metamorphic laws: 768 checks.
- Selected-claim projection: 7 finite event-space refinements, all classified as expected.
- Semantic grid: 4,480 generated obligations; 2,816 unsafe; 35 direct representatives and 4,445 transported obligations.
- IaC mutation corpus: 3,360 roles; 1,248 safe and 2,112 unsafe or outside-core; direct trust JSON, Terraform JSON, and CloudFormation JSON encodings.
- Synthetic scaling: largest safe submitted row has 64 intended subject patterns; largest unsafe row has 65 policy patterns.
- Evidence ledger: title/abstract hashes, 18-page US-letter PDF/font invariants, and registered-profile counts all pass.
- Trusted-base report: certificate replay is checked not to import the high-level analyzer, and module SLOC/function counts are emitted for reviewer inspection.

Exact millisecond values may differ across machines. Reproductions should match verdicts, witness validity, certificate validity, schemas, corpus cardinalities, and qualitative scaling trends.

## What is not evaluated

This artifact is an offline verifier for the trust-admission boundary studied in the paper. It consumes local policy inputs, selected-claim event cases, and IaC encodings; it does not require live cloud accounts, GitHub API access, private repository data, or downstream IAM-permission execution.

## Anonymity

The artifact is anonymized. Do not add repository remotes, account-specific paths, organization names, personal names, API tokens, cloud account IDs, or author metadata before uploading it to an anonymous artifact-hosting service.

The artifact includes three extra review-hardening checks: an exhaustive finite-model verification of the projection-calculus laws, an independently labeled adversarial matrix that stresses the policy front end, and a separated optional boundary-case/template profile that is never folded into the registered abstract counts. These checks are intended to catch proof-to-code drift in areas that are easy to get subtly wrong: literal wildcard characters, IAM action exactness, principal scope, claim namespaces, Deny erasure, and governance transport.
