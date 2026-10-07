# Fresh owned native evidence

This is a source-bound route, not a completed campaign or a new timing claim.
`.github/workflows/scientific-checks.yml` runs fresh preparation and mandatory
collection automatically only on a push to `main`, using Linux CPython 3.12.14.
Its pull-request/manual triggers run scalar-plus-nine-stage checkout checks,
without fresh collection. The separate
`.github/workflows/fresh-native-evidence.yml` remains manual-only for an
explicitly reviewed ref; it is not another automatic push job. Review the
source/ref before publishing or dispatching, and schedule one owned campaign
without concurrent measurement jobs. The shared non-cancelling concurrency
group serializes these two workflows, not other projects. No provider API,
supplied public program/workflow, cloud credentials or external security tool
is executed by the scientific children.

The ordinary **204 methods**, original nine-stage driver, passive native audit
and retained receipts remain unchanged. The required scientific workflow now
adds the guarded main-push fresh route; it does not weaken their contracts.
The scalar **seven methods** and assembler **eight guard methods** are separate
required steps in a fresh job. New helpers live outside ordinary `tests/`.

## Portable guards only

Python 3.10+ standard library; choose an absolute absent path outside the artifact:
On Windows, choose a short workspace output path so retained filenames fit the
host's path-length limit; this helper does not change global Windows settings.

```sh
python -B fresh_science_tests/test_assembler.py --out /ABSENT/PRIVATE/p113-assembler-guards -v
```

This copies reviewed artifact bytes, tests output exclusions/path refusals and
immutable-input drift, and rejects collection from an unrun copy. It imports
only the assembler and passive standard-library auditor, not gates or core
implementations. All own fixture/copy outputs remain in that private path. It
does not synthesize successful scientific records, run the 204 tests, or time a
benchmark. A successful guard suite is not native campaign success.

## Reviewed native commands (Linux CPython 3.12.14 only)

Run from the flat artifact checkout. `/ABSENT/PRIVATE/p113-fresh-native` must
be an absolute new directory with an existing parent, disjoint from the source:

```sh
python -B scripts/assemble_fresh_science.py prepare --source . --workdir /ABSENT/PRIVATE/p113-fresh-native
cd /ABSENT/PRIVATE/p113-fresh-native
export PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONOPTIMIZE=0
export TMPDIR="$PWD/_fresh-science/tmp"
set -euo pipefail
timeout --signal=TERM --kill-after=5s 30s python -B scalar_tests/test_glob_matches.py -v 2>&1 | tee _fresh-science/scalar-tests.log
CPU=$(python -c 'import os; print(min(os.sched_getaffinity(0)))')
printf 'Single allowed CPU: %s\n' "$CPU" | tee _fresh-science/affinity.log
(ulimit -t 900; ulimit -v 2097152; timeout --signal=TERM --kill-after=15s 1200s taskset -c "$CPU" python -B scripts/run_scientific_checks.py) 2>&1 | tee _fresh-science/driver.log
timeout --signal=TERM --kill-after=5s 60s python -B scripts/assemble_fresh_science.py collect --workdir "$PWD" 2>&1 | tee _fresh-science/assembler.log
```

The helper never launches that campaign itself. The automatic main-push fresh
job and the separate manual fresh workflow use these caps, read-only repository
permissions, pinned actions, disabled checkout credentials, and always upload
raw output, including failed attempts. The automatic job additionally records
its commit/run identity. The manual commands above remain the same underlying
prepare/scalar/driver/collect sequence; they do not enable a second automatic job.
Assertions must remain enabled. Ordinary tests retain their original three
`TemporaryDirectory` lifecycles; `TMPDIR` contains only newly owned test fixtures
in the execution copy, and those tests perform their original fixture cleanup.
The helper has no deletion path and never modifies original result directories.

## Freshness and limits

Preparation refuses existing/nested destinations, links/reparse points/special
files, and an already prepared source. It omits only outer generated roots
`tosem/results`, `fse/results`, `results`, `scientific-check-output` and
`scalar-regression-output`, plus Git/Python caches. Immutable inner
`artifact/results`, `artifact/reference_results`, study, patch/example inputs,
licenses and other copied files are retained byte-for-byte. The pre-execution
manifest binds every copied immutable file, including new helper/auditor/test/
workflow bytes not selected by the existing scientific-source manifest.

Collection requires that unchanged input inventory, exact generated origins,
the separate seven-method log, and actual native collection environment. It
copies the audit's 16 JSON records, four CSVs, nine stage logs, four execution/
unit/projection/repair records and 192 packets to `fresh-native-evidence/`.
Missing outputs have no historical fallback. Only after the unchanged native
audit accepts all 204 methods/nine stages/counts/negative controls/source and
output bindings does it write `_fresh-science/current-science-receipt.json`
and `native-audit.json`. No old receipt is rehashed. Preserve failed/partial
copies; a retry needs a new directory.

Keep all generated raw files, not just those 225 audit inputs. The unchanged
scaling stage generates 54 individual timing rows and an 18-warm-up count;
it does not separately record the warm-up durations/outcomes. This route keeps
exactly what the driver produces and does not invent missing warm-up records.
These new descriptive measurements are separate from historical paper
measurements and are not a before/current speedup experiment. Successful native
collection still is not the ten-stage TOSEM/paper audit, provider equivalence,
proof validation, source authentication or a verified deployment result.
