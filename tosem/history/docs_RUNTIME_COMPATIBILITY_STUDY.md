# Immutable-subject maintenance corpus

## Question

Do public development histories contain concrete maintenance failures caused by a
mismatch between the OIDC subject a repository actually emits and the subject its
AWS trust policy accepts?

## Frozen corpus

`study/runtime_compatibility_corpus.json` contains 12 public repositories/commits.
Inclusion required a pinned commit whose message or diff explicitly describes
immutable owner/repository-ID subjects in a GitHub/AWS trust-policy maintenance
change. Eleven report denied or broken exchanges; one is proactive hardening.

Evidence remains source-stated. The study did not access private logs or accounts
and did not independently reproduce the root causes.

## Result

- 12 repositories / 12 commits;
- 11 denied or broken exchange reports;
- six commits name CloudTrail as the source of the observed subject;
- four describe decoding a real workflow token;
- nine syntactically distinct repair categories;
- two pinned public GitHub Actions run IDs conclude successfully after the fix;
- two additional commits state that a deploy completed or turned green.

Repairs include exact immutable values, dual exact legacy/immutable values,
wildcarding only numeric-ID segments, and combining the wildcarded `sub` with
exact selected claims. The diversity motivates versioned issuer profiles and
positive required-identity regression examples; it does not show which repair is
universally preferable.

## Reproduce

```bash
python3 scripts/run_runtime_compatibility_study.py
```

Outputs:

- `fse/results/runtime_compatibility_summary.json`
- `fse/results/runtime_compatibility_rows.csv`
