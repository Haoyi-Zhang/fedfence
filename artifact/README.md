# FedFence Artifact

FedFence checks whether a federated CI/CD trust policy admits GitHub OIDC subjects or audiences outside an explicit deployment intent. The core safety check is the issuer-aware language inclusion over the effective policy language.

```text
issuer claims ∩ effective policy claims ⊆ declared intent claims
```

Unsafe results include concrete claim witnesses, missing governance premises, or outside-core diagnostics. Governance premises can be checked from exported repository-settings snapshots, and reviewer-supplied role packets can be processed through a deployment manifest. The artifact also extracts the supported trust fragment from direct JSON, Terraform JSON role fragments, and CloudFormation JSON role resources.

## Requirements

- Python 3.10 or newer.
- No required Python packages for JSON checking, curated cases, IaC extraction, certificates, repair checks, or automata self-checks.
- Core checker, JSON cases, IaC extraction, certificates, repair checks, and automata self-checks use only the Python standard library.
- Figure regeneration uses checked-in CSVs and a local LaTeX/TikZ toolchain; PyYAML is required for CloudFormation YAML/frontier cases and is listed in requirements.txt.

## Main commands

Full paper-profile run:

```bash
./scripts/reproduce_all.sh
```

Quick smoke run:

```bash
./scripts/reproduce_quick.sh
```

One curated case:

```bash
python3 -m fedfence.cli cases/02_repo_wildcard_all_events.json
python3 -m fedfence.cli cases/02_repo_wildcard_all_events.json --json
```

## Expected high-level results

- `scripts/self_check.py` passes 3,945 bounded and symbolic comparisons.
- 37 registered-profile curated cases: 13 safe and 24 unsafe or outside-core. Three optional boundary-hardening cases live in `hardening_cases/` and are reported separately.
- 20 public and documentation-derived examples: 6 safe and 14 unsafe or outside-core.
- `scripts/run_label_audit.py` recomputes the 37 registered, 20 public, and 8 optional public-issue challenge labels with a standalone finite-domain IAM/OIDC witness search that does not import the analyzer or certificate verifier.
- `scripts/run_baseline_suite.py` evaluates seven independent rule families over the registered/public rows; the strongest baseline remains below FedFence.
- `scripts/run_governance_exports.py` verifies six exported settings fixtures and ten branch/tag/environment/reusable-workflow premises.
- `scripts/run_deployment_manifest.py` processes eight example role-review manifest rows through the same proof path as registered cases.
- `scripts/verify_witnesses.py` replays every curated witness/governance result.
- `scripts/run_definability.py` checks 24 workflow states and emits non-definability witnesses; `scripts/run_claim_projection.py` evaluates seven selected-claim projection refinements.
- `scripts/run_certificates.py` emits and verifies 37 effective case-level certificates in the registered profile.
- `scripts/run_repair.py` checks monotone witness-cut repairs and governance repairs.
- `scripts/run_differential_fuzz.py` checks 2,000 randomized pair/triple containment obligations against bounded enumeration.
- `scripts/run_metamorphic.py` checks 768 generated metamorphic-law instances.
- `scripts/run_semantic_grid.py` checks 35 representatives and transports certificates over 4,480 generated semantic-grid obligations.
- `scripts/run_iac_scale.py` analyzes a 3,360-role IaC mutation corpus across 35 semantic templates and 3 encodings.
- `scripts/run_benchmark.py` measures synthetic scaling from 1 to 65 subject patterns.
- `scripts/run_tcb_report.py` emits a reviewer-facing trusted-base map and checks that certificate replay does not import the high-level analyzer.
- `scripts/run_code_metrics.py` records Python footprint, registered-case separation, public-example counts, governance-export fixture count, deployment-manifest presence, and replay/analyzer separation.
- `scripts/run_evidence_ledger.py` checks the locked title/abstract hashes, page/font invariants, and all registered-profile evidence counts against regenerated outputs.
- `scripts/make_figures.py` regenerates the vector PDF/SVG figures.
- Optional boundary-hardening rows are separated from the registered profile: run `python3 scripts/run_hardening_cases.py` for the three extra case-level schema checks, or set `FEDFENCE_TEMPLATE_PROFILE=extended` for the 40-template IaC/semantic-grid stress profile. These extra checks are not counted in the registered abstract profile.

## Outputs

- `results/case_summary.csv`: curated-case table used in the paper.
- `results/public_examples.csv`: documentation-derived example table.
- `results/label_audit*.csv/json`: standalone finite-domain label audit.
- `results/baseline_suite*.csv/json`: independent baseline-suite audit.
- `results/governance_export*.csv/json`: exported-settings premise audit.
- `results/deployment_manifest*.csv/json`: reviewer-supplied role-packet manifest audit.
- `results/witness_replay.csv`: witness/governance replay results.
- `results/definability.csv` and `results/definability_witnesses.json`: projection-definability outputs.
- `results/certificate_summary.csv` and `results/certificates/`: replayable proof-certificate outputs.
- `results/repair_summary.csv` and `results/repairs/`: witness-cut and governance repair outputs.
- `results/differential_fuzz*.csv/json`: randomized differential checks.
- `results/metamorphic*.csv/json`: metamorphic-law checks.
- `results/semantic_grid*.csv/json`: semantic-grid transport results.
- `results/benchmark.csv`: timing data for the synthetic scaling figure.
- `results/iac_rows.csv`, `results/iac_template_summary.csv`, and `results/iac_overall.json`: IaC mutation-corpus outputs.
- `results/iac_baselines.csv`: comparison against checklist-style baseline rules.
- `results/submission_audit.json`: final anonymous-submission audit.
- `results/tcb_report.json` and `results/tcb_report.csv`: replay trusted-base map.
- `results/code_metrics.json` and `results/code_metrics.csv`: implementation footprint and manifest checks.
- `results/evidence_ledger.json`: title/abstract lock, PDF preflight, and paper-profile count ledger.

See `EVIDENCE.md`, `STATUS.md`, `REPRODUCE.md`, `SECURITY_SCOPE.md`, and `DISCLOSURE.md` for additional artifact-evaluation notes.

- `results/public_source_metadata.csv`: source-host and SHA-256 provenance records for the normalized public examples.
