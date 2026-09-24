# FedFence - FSE 2027 submission candidate

**Package status:** the manuscript, artifact, studies, tests, reproducibility
manifest, and PDF preflight are complete for author review. The package is
internally reproducible; it does **not** claim representative field accuracy,
owner-confirmed findings, a live organizational deployment, product superiority,
or measured human usability.

FedFence reviews changes to CI/CD workload-identity trust. A separately reviewed
release contract supplies the intended upper bound and optional concrete identities
that must remain usable. Versioned policy, issuer, workflow, and governance
snapshots form the change unit. The gate returns:

- `pass` (process exit `0`) only when containment, required identities, and replay agree;
- `fail` (exit `1`) with an unintended-admission or missing-required-identity witness; or
- `unknown` (exit `2`) for unsupported semantics, stale/missing evidence, inconsistent
  specifications, timeout, or replay disagreement.

## Final additions

- JSON, human text, SARIF 2.1.0, and GitHub annotation renderers.
- A root `action.yml` composite action and a review-packet JSON Schema.
- Stable, documented exit behavior and machine-readable receipts.
- 79 local tests; 65,536 finite state/policy models; 37 historical cases; 3,945
  inherited self checks; eight executable walkthroughs.
- A frozen nine-commit before/after study (eight `fail -> pass`, one
  `fail -> unknown`).
- A 12-repository immutable-subject maintenance corpus: 11 commits report denied
  or broken exchanges, and two have archived public post-fix Actions-success run
  IDs.
- A query-defined 24-repository source-normalization frontier: seven files are
  literal or constant-foldable from pinned source; 17 require caller, module,
  dynamic-HCL, or host-language evaluation.

The public studies are purposive or query-defined. They establish recurring
maintenance shapes and extraction boundaries, not prevalence or independent
ground truth.

## Package map

- `paper/`: anonymous ACM `acmsmall,screen,review,anonymous` manuscript.
- `action.yml`: composite GitHub Action.
- `schemas/`: review-packet schema.
- `fse_workflow/`: pass/fail/unknown change-review implementation.
- `examples/`: complete packets and a reference GitHub workflow.
- `study/`: frozen public-change, runtime-compatibility, and source-frontier manifests.
- `evidence/public_changes/`: locally captured relevant public diff hunks.
- `tests/`: unit and integration tests.
- `scripts/`: reproduction, study, benchmark, and audit drivers.
- `fse/results/`: machine-readable outputs.
- `docs/`: study protocols, evidence boundaries, and completion report.
- `baseline/` and `artifact/`: byte-preserved predecessor submission/material.

## Quick use

```bash
python3 -m fse_workflow.cli review examples/release_gate/before.json \
  --now 2026-09-23T01:00:00Z

python3 -m fse_workflow.cli compare \
  examples/release_gate/before.json \
  examples/release_gate/after_wildcard.json \
  --now 2026-09-23T01:00:00Z --format github

python3 -m fse_workflow.cli review \
  examples/release_gate/after_wildcard.json \
  --now 2026-09-23T01:00:00Z \
  --format sarif --output result.sarif --result-json result.json
```

A GitHub workflow can invoke the packaged composite action:

```yaml
- uses: ./trusted
  id: fedfence
  with:
    packet: candidate/.fedfence/production.json
- uses: actions/upload-artifact@v4
  if: always()
  with:
    name: fedfence-result
    path: ${{ steps.fedfence.outputs.result-json }}
```

The full reference workflow is `examples/github-actions-fedfence.yml`.

## Reproduce and audit

Requirements: Python 3.11+ standard library; TeX with `acmart`, BibTeX, TikZ;
`pdfinfo`, `pdftotext`, and `pdffonts` for preflight.

```bash
make reproduce
make paper
make audit
```

For a split execution whose result files have already been produced:

```bash
python3 scripts/reproduce_final.py --manifest-only
```

Important outputs:

- `fse/results/final_reproduction_manifest.json`
- `fse/results/final_audit.json`
- `paper/FedFence_FSE_final_submission_candidate.pdf`
- `FINAL_AUDIT_REPORT.md`
- `SHA256SUMS` (generated for the final packaged tree)

## Supported and unsupported claims

Supported by this package:

- three-valued change review for the stated GitHub/AWS trust fragment;
- two-sided conformance: exclusion of unintended identities plus finite positive
  regression examples;
- internally replayable results and explicit evidence dependencies;
- source-traceable explanation of the frozen public changes and maintenance cases;
- a measured source-normalization frontier for the frozen 24-file convenience sample.

Not supported:

- prevalence or representative supported-fragment coverage;
- independent precision/recall or owner-confirmed findings;
- proof that a successful public workflow was caused by the cited trust edit;
- live cloud/provider conformance by FedFence;
- superiority to Access Analyzer, Checkov, Trivy/tfsec, OPA, ARGUS, or Cosseter;
- measured developer productivity/usability; or
- a machine-checked refinement from the calculus to Python.

See `docs/FSE_SUBMISSION_GATES.md` and `FINAL_AUDIT_REPORT.md` for the exact
boundary.
