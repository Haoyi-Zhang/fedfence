# Public OIDC trust-change pilot

## Research question and boundary

The pilot asks whether FedFence's review packet can explain the before/after
behavior stated by developers in public GitHub/AWS OIDC trust changes.

It is **not** a randomized corpus, a prevalence estimate, an independently
adjudicated accuracy benchmark, or an owner-confirmed vulnerability study. The
commit message, relevant diff, and any accompanying test or documentation supply
source-stated intent. FedFence is run after the source is frozen; those records
are not promoted to external ground truth.

## Frozen screening denominator

The screening manifest records three commit-search queries, 17 candidate
changes, nine inclusions, and eight exclusions. A candidate is included only
when:

1. the public commit is pinned by full SHA;
2. the commit message states a GitHub/AWS OIDC review goal;
3. the relevant trust-policy delta is visible in the diff; and
4. the before/after unit can be normalized without executing repository code.

Duplicate forks, non-AWS trusted-publishing changes, multi-topic commits without
an isolated review unit, new policies without a comparable before state, and
cases requiring unavailable evidence for a positive result are retained in the
screening manifest with explicit exclusion reasons.

## Included changes

| ID | Kind | Source-stated change | FedFence |
|---|---|---|---|
| `artur-main-branch` | security hardening | repository wildcard to exact `main` | fail -> pass |
| `pmcg-master-branch` | security hardening | branch wildcard to exact `master` | fail -> pass |
| `arriagada-main-branch` | security hardening | wrong exact feature ref to exact `main` | fail -> pass |
| `shadow-release-branches` | security hardening | repository wildcard to named release refs | fail -> pass |
| `amr-org-scope` | security hardening | global repository wildcard to one organization | fail -> pass |
| `manyiu-repository-scope` | security hardening | owner-wide trust to one repository and immutable ID | fail -> pass |
| `michele-environment-cut` | cross-plane hardening | repository wildcard to environment plus audience | fail -> unknown |
| `sports-store-immutable-main` | security hardening | broad immutable wildcard to exact immutable main subjects | fail -> pass |
| `microticket-immutable-compatibility` | compatibility repair | legacy-only prod subject to legacy plus observed immutable subject | fail -> pass |

The environment row remains `unknown` because exact environment admission does
not prove the branch-sensitive requirement without a reviewed governance export.
The compatibility row is different: its old policy is within the upper-bound
intent but does not admit the immutable subject that the public commit says was
observed at runtime. A finite required-token regression obligation catches this
loss; one-sided overgrant checking does not.

## Source traceability

For each row the package records and verifies:

- repository and full commit SHA;
- canonical public URL and affected file;
- local relevant-hunk snapshot;
- SHA-256 of that snapshot;
- removed and added source literals; and
- normalized before/after policy, intent, and expected transition.

The snapshots are relevant hunks, not complete repositories. Manual
normalization is auditable but is not a general verified Terraform,
CloudFormation, or CDK extractor.

## Results and interpretation

- repositories / commits: 9 / 9;
- source snapshots verified: 9/9;
- source-aligned transitions: 9/9;
- before/after phases aligned with source-stated direction: 18/18;
- transition counts: 8 fail-to-pass, 1 fail-to-unknown;
- required tokens declared/satisfied after repair: 1/1;
- owner-confirmed findings: 0;
- independently adjudicated labels: 0;
- prevalence and accuracy claims: false.

Three explanatory rules are evaluated only on the 17 phases with source-stated
pass/fail outcomes:

- claim-presence agrees on 9/17;
- wildcard-ban agrees on 12/17; and
- exact-ref-only agrees on 12/17.

These are ablations, not vendor-tool runs. They show that the target property is
not equivalent to claim presence, wildcard absence, or exact-ref syntax. In
particular, an exact but wrong branch violates intent; some reviewed release or
repository pattern families intentionally retain wildcards; and a compatibility
repair can require preserving an identity rather than excluding one.

## Local execution-cost check

The frozen benchmark runs analyzer, required-token checks, and certificate replay
over all nine normalized changes for seven repetitions. On the recorded local
platform the full batch has a median of 946.08 ms and p95 of 986.22 ms. This
excludes source collection, IaC evaluation, network access, provider behavior,
and human review. It is a local feasibility check, not production tail latency.

The ordinary final reproduction validates the frozen benchmark file rather than
repeating this comparatively expensive timing run. A fresh timing run remains
available explicitly.

## Reproduction

```bash
python scripts/run_public_change_study.py
python scripts/validate_public_change_latency.py
# Optional fresh timing run:
python scripts/benchmark_public_changes.py
```

Outputs:

- `fse/results/public_change_study.json`
- `fse/results/public_change_study.csv`
- `fse/results/public_change_latency.json`
