# Public source-normalization frontier

## Question

When a public IaC file contains a GitHub OIDC `sub` condition, how much of the
trust language is visible in that pinned file, and what additional evaluation is
needed before a sound review packet can be built?

## Frozen sample

`study/source_frontier_sample.json` contains 24 unique repositories selected from
a GitHub code-search convenience sample for the provider-qualified subject key.
Every record pins repository, path, full commit SHA, blob SHA when available,
source URL, an excerpt digest, a primary frontier class, audience visibility, and
features that drove classification.

This is not a random sample and does not measure prevalence, security quality, or
extractor accuracy.

## Result

| Primary class | Files |
|---|---:|
| Literal policy in pinned source | 5 |
| Constant-foldable HCL | 2 |
| Caller/module instantiation | 15 |
| Host-language generation | 1 |
| Unsupported operator plus instantiation | 1 |

Thus seven files expose a literal or source-constant policy, whereas 17 require
caller values, module expansion, dynamic HCL evaluation, or host-language
synthesis. Six files have no explicit `aud` condition in the pinned trust document;
two delegate audience handling to a referenced module.

These counts are a normalization frontier, not a FedFence coverage rate. A sound
organization study should first resolve modules/plans/synthesis, then report:
extracted roles, supported packets, withheld packets, positive certificates, and
owner-reviewed witnesses separately.

## Reproduce

```bash
python3 scripts/run_source_frontier_study.py
```

Outputs:

- `fse/results/source_frontier_summary.json`
- `fse/results/source_frontier_rows.csv`
