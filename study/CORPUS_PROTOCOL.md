# FSE empirical protocol v1 — freeze before collection

This is a proposed study protocol, not completed research. The current package contains no population-level deployment result and no owner-confirmed defect.

## Units and sampling
A sampling unit is a public repository at a full commit SHA plus a role definition location. A policy instance produced from a module additionally needs the caller inputs and Terraform/provider versions. Repeated role clones are retained in a duplicate ledger but cannot inflate independent sample size. Documentation examples, reusable modules, instantiated repository policies, and real organization exports are separate strata. Do not treat a template as an operational AWS role.

Record exact queries, query date, API result cap, retrieved repository IDs, default-branch commit, exclusions, forks, archived status and license. Freeze the candidate list before seeing FedFence findings. Do not select only files the parser can read. Recommended engineering target: 100+ independently located candidate role definitions across at least 30 repositories; these are planning goals, not power guarantees or achieved counts. Prefer complete, auditable denominators to a large but unrecoverable number.

## Extraction accounting
For every candidate record one of: extracted concrete trust policy; unresolved module/expression; parse error; not an OIDC role; permission/access failure; duplicate. Preserve unsupported candidates. Report (i) extracted/candidate and (ii) supported/extracted and (iii) supported/candidate, with unit type, repository clustering and exclusion reasons. A coverage number from a purposive sample is not a population prevalence estimate.

## Intent and governance annotation
Do not infer intent by copying `sub` from the policy under test. Store source evidence for intended repository, ref/event/environment, audience and allowed release job. Separate (a) owner-confirmed intent, (b) independently double-reviewed public evidence, (c) author-designed hypothetical contract, and (d) unknown. An ambiguous contract remains unknown. Two annotators work without seeing tool verdicts; reconcile only after initial judgments and report disagreement. No independent humans or owner confirmations have been recruited or completed in this iteration.

For governance, keep exporter identity, API endpoint or file, timestamp, repository/role scope, complete field set, permissions/omissions, and source hash. Missing branch/environment protection data is unknown, not evidence of protection. Read-only public metadata cannot establish private organization settings. Source hashes do not authenticate a service or reviewer, and cannot reveal a cloud change that was never exported.

## Endpoints
RQ1 — extraction and fragment coverage with unknown rate.
RQ2 — correctness on independently adjudicated policies; precision/recall only when labels and task are comparable.
RQ3 — change review: genuine before/after commits and synthetic edits in separate strata, preserved intended behavior and valid witness rate.
RQ4 — external tools: pinned Checkov and Trivy/tfsec, a documented custom OPA/Rego rule, authorized AWS Access Analyzer validation/custom checks. Report versions, policies/rules, timeouts, stderr and raw output. Different semantics must be analyzed as complementary tasks, not coerced into a single misleading F1 score.
RQ5 — authoring/review effort: wall-clock task time, errors, clarification requests, review agreement and correction time. Only a consented study under applicable ethics requirements can support usability claims.

## Performance
Use a fixed seed only for synthetic tasks, record machine/software versions, distinguish parsing/analysis/replay, warm-up and repeat counts, median/p95/dispersion and timeouts. Do not report only completed cases. For a clustered corpus, bootstrap at repository level, not template-derived row level. No new production performance claim is supported by the present results.

## Disclosure and privacy
No active exploitation, no secret collection, no third-party mutations. Source evidence is not a vulnerability confirmation. Before reporting a potentially actionable defect publicly, obtain owner confirmation where feasible and follow a documented coordinated-disclosure process. Contacting maintainers and sending cloud requests are not performed by any default reproduction command in this package.
