# FedFence — TOSEM research artifact

This is the existing FedFence implementation, revised in place for **“FedFence: Specification-Guided Review of CI/CD Trust Changes: Two-Sided Conformance, Observation Boundaries, and Snapshot-Relative Replay.”** It is a local, specification-driven reviewer of supplied CI/CD trust snapshots, not a cloud deployment controller. `fse_workflow` remains the original package name to avoid a second implementation or a breaking namespace migration.

The current entry points are this README and this directory's Makefile. The paper lives in the **sibling `../paper/` directory**. Older FSE documentation and output directories are not the authority for the present manuscript's counts or claims.

The delivered ten-stage evidence is in `tosem/results/`, with raw logs in
`logs/`; it supplies the paper's current tables and plot. The separate
225-file nine-stage campaign remains in `tosem/results/native-science`.
`make native-audit` passively checks that retained campaign against this
artifact's actual scientific sources. The unchanged `make tables` target
also selects its receipt explicitly; the default generator instead selects
the ten-stage root outputs, as described below. `make coherence-tests` runs
twelve separate portable passive-consumer regressions, also a required
scientific-CI step; they are not part of the 204 ordinary tests or evidence stages.
See [retained nine-stage consumer instructions](docs/CURRENT_EVIDENCE_CONSUMERS.md).

## Reproduce from the delivered layout

```sh
cd artifact
make evidence       # all ten offline evidence steps; regenerate paper tables
make -C ../paper    # compile those tables into ../paper/FedFence_TOSEM.pdf
make audit          # verify evidence/manuscript consistency
# Or execute all three stages:
make reproduce
```

For just the ordinary regression suite, run `make tests`. For the corrected source-backed, source-frontier and maintenance studies, run `make studies`. Outputs are written to `tosem/results/`, with logs in `logs/`; quantitative LaTeX macros and tables are regenerated in `../paper/generated/`. Re-running overwrites generated results and timings. It does not change the supplied public-source fixtures.

**Requirements:** the demonstrated JSON path and all ten evidence steps use Python 3.10+ and its standard library. The delivered ten-stage measurements and the separate retained nine-stage campaign used CPython 3.12.14 on Linux. The supplied paper was built on Windows with pdfTeX from TeX Live 2024 and installed `acmart` v2.12. `make` is required for the Makefile commands. Paper compilation additionally needs a working TeX installation with `acmart`, `ACM-Reference-Format`, TikZ, PGFPlots, algorithm/algpseudocode and the packages listed in `../paper/main.tex`, plus `latexmk` and BibTeX. The final PDF audit uses Poppler's `pdfinfo`, `pdftotext` and `pdffonts`. The supplied PDF does not require a TeX installation to read. No font files are distributed.

The preserved legacy YAML extractor has separate optional dependencies in `artifact/requirements.txt`; it is **not** exercised by the current JSON reproduction path. No cloud credentials, cloud account, paid API, external analyzer, repository checkout, network fetch or source program execution is required by the current reproduction command. Historical fetch scripts are not called by it.

### Optional portable scalar matcher tests

From this artifact directory, with Python 3.10+ and no extra dependencies:

```sh
python -B scalar_tests/test_glob_matches.py -v
```

This self-contained seven-method suite loads only `fse_workflow/conformance.py`
and standard-library modules. It compares 10,571 bounded pattern/string pairs
with an independent recursive definition, adds 15 literal/code-point controls,
and checks the cell cap, literal fast path, invalid types and injected deadlines.
It does not import or execute gates, policies, providers, symbolic analysis,
receipts or cloud/workflow commands, and needs no before copy or private paths.

The scalar DP now reuses its two row buffers; recurrence, character domain,
cell cap and deadline checks are unchanged. These tests live outside `tests/`
and are **not** included in the retained 204-test discovery count or the
existing nine-/ten-stage drivers. Scientific CI runs the seven methods as a
separate required step and retains their raw log; the original scientific
command and all 204-test/source-bound gates remain unchanged. This configuration
is not a hosted CI success claim.

Earlier campaigns remain bound to their original sources. Both delivered
campaigns identified below ran the changed matcher; neither is a reseal of
earlier records. The scalar suite alone does not refresh receipts or establish
full-gate conformance or a measured speedup. The native receipt requires Linux
CPython 3.12.14; the nine- and ten-stage routes remain distinct, and old evidence
must not be rehashed.

On pushes to `main`, `scientific-checks.yml` automatically runs the owned fresh
route, pinned to Linux CPython 3.12.14. After the separate eight assembler guards,
it prepares a new execution copy without deleting checkout outputs, runs the
unchanged nine stages and the separate seven scalar methods, then assembles
exactly 225 fresh native evidence files. The unchanged passive audit must accept
before a new receipt is issued. Pull-request and manual runs of that scientific
workflow retain scalar-plus-nine-stage checkout checks, without fresh collection.
The separate `fresh-native-evidence.yml` remains manual-only for an explicitly
reviewed ref; it is not another automatic push job. Both workflows share a
non-cancelling concurrency group. Review the source/ref and schedule one owned
campaign without other concurrent measurement jobs. Old receipts, historical
Linux timings and negative controls are not rewritten, and the new route is
not a ten-stage or current-PDF success claim. The retained successful current
nine-stage run is identified below; configuring a workflow alone is not evidence
that another run succeeded.
See [fresh native instructions](docs/FRESH_NATIVE_EVIDENCE.md), including the
separate eight-method portable assembler guards (not part of 204 or seven).

## Strict gate and full-review replay

All paths below are relative to this artifact directory. The explicit historical clock is for deterministic fixtures, not a way to approve stale operational evidence.

```sh
python3 -m fse_workflow review \
  examples/release_gate/availability_before.json \
  --now 2026-09-23T01:00:00Z \
  --receipt-json tosem/results/example_receipt.json \
  --result-json tosem/results/example_review.json

python3 -m fse_workflow replay \
  tosem/results/example_receipt.json \
  --now 2026-09-23T01:00:00Z

python3 -m fse_workflow compare \
  examples/release_gate/availability_before.json \
  examples/release_gate/availability_after.json \
  --now 2026-09-23T01:00:00Z
```

The first two commands return `pass` (exit 0) for the fresh supplied fixture. The comparison deliberately returns `fail` (exit 1) because the second policy excludes a required identity. This is the expected result, not a failed reproduction. Other presentation choices are `--format json`, `--format sarif` and `--format github`; `--result-json` always preserves the machine-readable result. Omit `--now` when evaluating actual supplied snapshots against the current clock. No demonstration here establishes that a real deployment succeeds or fails.

| Verdict | Exit | Meaning within the supported supplied model |
|---|---:|---|
| `pass` | 0 | Supported, fresh, consistent premises; upper-bound safety and every declared positive obligation established. |
| `fail` | 1 | A supported conformance violation, such as an overgrant or a valid required identity excluded by the policy. |
| `unknown` | 2 | Invalid/inconsistent/stale premises, unsupported syntax or profile, or insufficient analysis/replay evidence. |

An invalid premise takes precedence over a simultaneously observed failure candidate. An invalid required identity is not labeled as a demonstrated deployment regression. `--previous` is used only to report changed dependencies; it is not a verdict cache. A full receipt binds the complete two-sided semantic result and is re-evaluated using the current implementation and caller clock. Receipt integrity and successful replay are not source authentication, approval authentication, or an independent checker. A successfully replayed failing receipt remains a failure.

## Supported analysis boundary

The strict path accepts the documented GitHub-style legacy issuer profile and a narrow trust-policy fragment: supported `2012-10-17` statements, one exact GitHub OIDC provider ARN, `sts:AssumeRoleWithWebIdentity`, `Allow`/`Deny`, and positive `StringEquals`/`StringLike` conditions on `sub` and `aud`. Effective acceptance is a **tuple relation**, not independent subject and audience marginals. Unsupported context keys, mixed provider principals, operators and profiles are refused conservatively. See the manuscript and `fse_workflow/fragment.py` for the executable boundary.

The packet's separate release contract includes admissible identities, declared reviewer metadata, positive regression identities, and a maximum snapshot age. Snapshot digests, source metadata, scope and freshness are checked. Workflow bytes are bound as a dependency but not converted into a reachability proof. JSON Schema describes structure; the Python validator also checks cross-field semantics, reviewed digests and freshness. Neither performs cryptographic authentication of a reviewer or source.

Public cases use explicitly identified **study adapters**. Fourteen configurations use the inherited regular-language study adapter and seven use a finite explicit-issuer relation. These are not all strict-CLI cases, and the finite domain is not asserted to exhaust GitHub's live issuer behavior.

## Delivered evidence

The root `tosem/results/reproduction.json` records ten successful offline
science stages on Linux CPython 3.12.14. Their outputs include 204 ordinary
tests with no failures/errors/skips, eight seeded semantic fault controls,
54 local timing samples, 18 warm-ups, and 18 summary cells. The table below
describes those delivered root outputs. The supplied 41-page Windows-built
paper and the same science outputs subsequently passed the original 53-check
Linux package audit, recorded in `tosem/results/final_audit.json` and
`docs/AUDIT_REPORT.md`. Seven scalar methods, eight assembler guards, and
twelve passive-consumer tests were executed separately; they are not added
to the 204 ordinary tests or the ten stages. These are finite model and
package-consistency checks, not universal proof or a speed-gain comparison.

The separately retained nine-stage campaign is run **37670050420**, attempt 1, source commit
`07258c854b9136504952d2b842866074500847bf`: nine successful stages, 204 ordinary
tests with no failures/errors/skips, and 225 bound evidence files, on Linux
CPython 3.12.14. The original receipt and eight sidecars are retained under
`tosem/results/native-science`, byte-unchanged. Its seven scalar methods and
eight assembler guards are separate from 204. The preparation manifest's full
support-source inventory describes that published snapshot, not newly edited
consumer wrappers. The passive audit binds the unchanged 56 scientific files
and 12 study inputs to the actual installed artifact root. It does not establish
a new run, source authentication, proof correctness or a ten-stage/PDF pass.

Retained pre-buffer-change native evidence remains in `tosem/current-native-37484284472/`,
with its original `tosem/results/current_science_receipt.json`; that receipt must
still reject the changed matcher. Earlier raw records and negative controls
remain retained with their original source bindings, separately from the
delivered root outputs. No live cloud or public-source program was executed.

To validate or regenerate the paper's delivered ten-stage root selection,
without executing scientific drivers:

```sh
python -B scripts/generate_tosem_tables.py --check  # validate/render; write nothing
python -B scripts/generate_tosem_tables.py          # write ../paper/generated/
make -C ../paper                                  # build from that selection
```

To passively verify the separate nine-stage records or select their semantic counts:

```sh
make native-audit
make tables
# Without make, with Python on the command path:
python -B scripts/generate_tosem_tables.py --current-receipt tosem/results/native-science/_fresh-science/current-science-receipt.json --evidence-root tosem/results/native-science
```

These commands do not execute the scientific drivers. The explicit
current-receipt mode fails if bound sources/data change or counts disagree.
`make tables`, `make current-tables`, and the table prerequisite of `make paper`
select the nine-stage receipt, while scaling still comes from the root
`tosem/results/local_scaling.csv`. They record that different selection in
`generation.json`; they do not reproduce the ten-stage generation provenance.
The default generator selects the root outputs and checks the current test
count and all scaling rows and summaries before any writes. The full
ten-stage/PDF audit remains a separate gate, not a property of the nine-stage
receipt. `make reproduce` executes the complete ten-stage/build/audit route
and replaces generated results and timing samples.

| Layer | Actual unit and result | Authoritative output |
|---|---|---|
| Ordinary regression suite | 204 tests, 0 failures, 0 errors, 0 skips | `tosem/results/unit_tests.json` |
| Core self-check | 3,945 bounded/symbolic comparisons | `tosem/results/core_self_check.json` |
| Observation projection | 65,536 four-state/two-observation models | `tosem/results/finite_semantics_audit.json` |
| Two-sided finite decision | 65,536 decisions over three atoms; 256 full certificate replay samples | `tosem/results/two_sided_exhaustive.json` |
| Strict literal differential | 56 actual gate configurations; all agree with the direct tuple-set oracle | `tosem/results/strict_literal_differential.csv` |
| Character support | 3,342,336 code-point predicate comparisons across three saturated supports; 57,498 concrete/quotient matcher pairs; 60 constructor checks | `tosem/results/character_domain_audit.json` |
| Domain integration and rejection | Four regular cases, three strict packets covering pass/fail/unknown, and two local rejection challenges | `tosem/results/character_domain_audit.json` |
| Prefix matcher differential | 242,580 exhaustive bounded pairs; recursive oracle, DP matcher and preserved NFA agree | `tosem/results/matcher_differential.json` |
| Issuer refinement bridge | 2,304 scalar/NFA membership checks, including audience refinements | `tosem/results/issuer_membership_differential.json` |
| Strict bounded-glob differential | 192 complete packets: 64 pass / 128 fail, all expected | `tosem/results/strict_glob_differential.csv` |
| Local recomputation costs | 54 timed runs and 18 warm-ups; 6 sizes × 3 tasks × 3 repetitions | `tosem/results/local_scaling.csv` |
| Relational propositions | Four bounded counterexample searches, reported separately | `tosem/results/relational_audit.json` |
| Dependency transformations | Six explicit metamorphic relations | `tosem/results/dependency_metamorphic.json` |
| Seeded semantic faults | Eight hand-selected changes; each has a passing control and an assertion detecting the isolated fault | `tosem/results/seeded_faults.json` |
| Public change study | 9 commits, 10 role contracts, 21 configurations: 10 pass / 10 fail / 1 unknown | `tosem/results/public_study.json` |
| Source frontier | 24 verified frozen excerpts, 0 complete source files, 0 executed full-source extractions | `tosem/results/source_frontier.json` |
| Maintenance records | 12 supplied metadata records; 11 annotated breakage reports, 2 recorded public success-run IDs; 0 live replays | `tosem/results/maintenance_metadata.json` |

These units are not interchangeable and must not be summed into a sample size, success rate, accuracy, or population estimate. Timings are local descriptive measurements, not a competitive or representative performance benchmark. Seeded fault/test pairs were selected together and do not form a population mutation score.

## Layout and provenance

- `fse_workflow/`: existing review wrapper, shared three-valued rule, study adapters and the new full-review receipt support.
- `artifact/fedfence/`: retained regular-language analysis core, with the character-domain correction applied; this inner `artifact` name is a historical path, not another FedFence system.
- `tests/`, `scripts/`, `examples/`, `schemas/`: current regression tests, evidence drivers and benign fixtures.
- `study/`: supplied source manifests, frozen patch/excerpt records and recorded corrections.
- `tosem/results/`: delivered ten-stage root outputs and package audit; `native-science/` holds the separate retained nine-stage receipt and its original sidecars. `docs/CLAIM_EVIDENCE_MAP.md` describes the earlier claim mapping.
- `tosem/history/`, `fse/results/`, `results/`: retained historical documentation and/or compatibility outputs. Do not use them to overwrite the current study's role and branch distinctions.

The original core's own `artifact/README.md` and Makefile describe an older, narrower component-level workflow. The current whole-project entry point is the Makefile next to **this** README. The compatibility aliases `scripts/reproduce_final.py` and `scripts/audit_final.py` now dispatch to the TOSEM drivers.

See `docs/CHANGELOG_TOSEM.md`, `docs/AUDIT_REPORT.md`, and `docs/FINAL_REPORT_ZH.md`. The final archive hash manifest detects accidental file changes; like review digests, it is not an authenticated signature. No submission to a journal, source publication, cloud action, maintainer contact, or author approval was performed by these scripts.

## Current finite-helper repairs and earlier character-domain correction

The current suite has 204 tests: the retained 194-test checkpoint plus ten methods covering finite-event matching, absent versus empty claims, certificate replay, and the empty observation basis. The finite-event path now implements only star and question-mark operators, with literal brackets, and requires presence for its four supported positive condition operators. A constant predicate can have the empty cardinality-minimum observation basis. These are retained library-helper repairs, not changes to the strict CLI's accepted fragment or claims about a live provider.

The earlier character-domain correction remains in place. Scalar empty strings and their single-element-list forms agree; explicit malformed clocks no longer become the current clock. The regular-language positive path intersects issuer subject refinements with the original typed grammar and also honors audience refinements. No replacement system or namespace migration is introduced.

Positive wildcard checks use an exact two-row dynamic program with a 2,000,000-cell per-match cap and a shared monotonic review deadline. Exhaustion is `unknown`, not negative membership. Literal equality is a separate fast path. The checks do not promise hard preemption of JSON parsing, allocation, or arbitrary host execution.

To independently regenerate this package in a **new, absent directory** on the same machine:

```sh
python3 scripts/check_clean_rebuild.py --destination /tmp/fedfence-clean-check
```

The script deletes generated results, logs, paper tables/plot data, the PDF and TeX intermediates in the copy, then calls its current `make reproduce`. Selected deterministic semantic outputs must agree; new timing samples and PDF byte hashes need not. See `docs/CLEAN_REBUILD.md` for the actual recorded execution.

`make template-current` is a separate opt-in networked bootstrap for the pinned official acmart v2.20 files. It is not part of offline reproduction. The supplied earlier attempt was blocked by external access and is not represented as a completed latest-template build; it was not rerun in this repair.

## Character-domain contract and legacy evidence

The regular and scalar string model is `python-str-codepoints-v1`: all Python string code points U+0000 through U+10FFFF, without normalization. This is not a live-provider validity claim. The strict UTF-8 packet transport can reject values (e.g. unpaired surrogates) that direct library tests exercise. `DEFAULT_ALPHABET` is only a preference pool for selecting an OTHER representative. All literal singletons and constructor exclusions must be represented; exhausting preferences never exhausts the semantic domain. Raw NFA constructors still have an explicit finite alphabet, so concrete out-of-support words require projection or a support built with their literal characters.

Atomic certificates are version 3; effective-case certificates are version 6. Both bind the character-domain identifier. Legacy certificates must be regenerated; do not relabel or reuse their invariants. Full receipts also change because the implementation digest changes. Read `docs/CHARACTER_DOMAIN_FIX.md` for the exact coverage obligation and evidence limits.

Run only the new audit using `make character-domain`. The full `make reproduce` now has ten evidence steps and includes it automatically. The verification checks are local; no cloud account, credentials, public workflow execution, or external security scanner is used.

## Bounded flat-repository scientific checks

From this directory, or a repository whose root is this artifact directory, run:

```sh
python -B scripts/run_scientific_checks.py --out scientific-check-output
```

The output directory must be new. The driver retains raw logs, fails on any nonzero stage, and enforces a shared 1,200-second budget as well as per-stage limits. Its nine stages exercise the current unit suite, core, projection, relational, two-sided, character, matcher/issuer/bounded-glob/scaling, repair, and supplied-source checks. `--no-paper-table` keeps the character audit's checks identical while omitting its sibling-paper write. The current unit output is `fse/results/unit_tests.json`; this flat driver does not relabel the supplied `tosem/results/unit_tests.json` or earlier seeded-fault records as current. No paper build or eight-fault mutation-copy campaign is included.

`.github/workflows/scientific-checks.yml` runs that command on Ubuntu 24.04 with CPython 3.12.14 for pushes to `main`, pull requests, or manual dispatch. A main push uses the fresh copy and mandatory collection described above; the other triggers retain checkout checks. It bounds wall time and process CPU/address space, uses one allowed CPU for the scientific driver, retains failure gates, and uploads raw logs and result files even after a failure. The action revisions are pinned. The separate fresh-native workflow is manual-only and shares the concurrency group, which does not serialize other projects. The retained pre-buffer-change Linux evidence identifies run 37484284472, artifact 11422128499, and source commit `e2535e4bdf8b04d098fe132ee008a018a8402ac8`. The Windows recheck is a separate local execution. The existing material-integrity workflow is retained separately.
