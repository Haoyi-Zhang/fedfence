#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PYTHONDONTWRITEBYTECODE=1
cleanup_temp() {
  rm -rf "$ROOT/fedfence/__pycache__" "$ROOT/scripts/__pycache__" "$ROOT/results/.mplconfig"
  rm -f "$ROOT/../paper/main.aux" "$ROOT/../paper/main.log" "$ROOT/../paper/main.out" "$ROOT/../paper/main.toc" "$ROOT/../paper/main.fls" "$ROOT/../paper/main.fdb_latexmk" "$ROOT/../paper/main.synctex.gz"
  rm -f "$ROOT/../main.aux" "$ROOT/../main.log" "$ROOT/../main.out" "$ROOT/../main.toc" "$ROOT/../main.fls" "$ROOT/../main.fdb_latexmk" "$ROOT/../main.synctex.gz"
}
trap cleanup_temp EXIT
run_step() {
  local name="$1"; shift
  echo "[FedFence] begin ${name}"
  ( cd "$ROOT" && "$@" )
  echo "[FedFence] end ${name}"
}
PY="${PYTHON:-python3}"
PYFLAGS_DEFAULT="${PYFLAGS:-}"
PYFLAGS_ARR=()
if [ -n "$PYFLAGS_DEFAULT" ]; then read -r -a PYFLAGS_ARR <<< "$PYFLAGS_DEFAULT"; fi
rm -rf "$ROOT/results"
mkdir -p "$ROOT/results"

# Default paper-profile run. It exercises every checker component and regenerates
# the paper tables. Use scripts/reproduce_quick.sh for a shorter smoke test.
export FEDFENCE_CASE_LIMIT="${FEDFENCE_CASE_LIMIT:-0}"
export FEDFENCE_CERT_LIMIT="${FEDFENCE_CERT_LIMIT:-0}"
export FEDFENCE_REPAIR_LIMIT="${FEDFENCE_REPAIR_LIMIT:-0}"
export FEDFENCE_TEMPLATE_PROFILE="${FEDFENCE_TEMPLATE_PROFILE:-registered}"
export FEDFENCE_GRID_PER="${FEDFENCE_GRID_PER:-128}"
export FEDFENCE_GRID_WORKERS="${FEDFENCE_GRID_WORKERS:-1}"
export FEDFENCE_GRID_TRANSPORT="${FEDFENCE_GRID_TRANSPORT:-1}"
export FEDFENCE_IAC_PER="${FEDFENCE_IAC_PER:-32}"
export FEDFENCE_IAC_WORKERS="${FEDFENCE_IAC_WORKERS:-1}"
export FEDFENCE_IAC_TRANSPORT="${FEDFENCE_IAC_TRANSPORT:-1}"
export FEDFENCE_BENCH_MAX="${FEDFENCE_BENCH_MAX:-64}"
export FEDFENCE_BENCH_REPS="${FEDFENCE_BENCH_REPS:-3}"
export FEDFENCE_META_PER="${FEDFENCE_META_PER:-128}"
export FEDFENCE_META_TRANSPORT="${FEDFENCE_META_TRANSPORT:-1}"
export FEDFENCE_FUZZ_PAIRS="${FEDFENCE_FUZZ_PAIRS:-1200}"
export FEDFENCE_FUZZ_TRIPLES="${FEDFENCE_FUZZ_TRIPLES:-800}"
run_step code-audit "$PY" "${PYFLAGS_ARR[@]}" -u scripts/run_code_audit.py
run_step code-metrics "$PY" "${PYFLAGS_ARR[@]}" -u scripts/run_code_metrics.py
run_step tcb-report "$PY" "${PYFLAGS_ARR[@]}" -u scripts/run_tcb_report.py
run_step max-narrowing "$PY" "${PYFLAGS_ARR[@]}" -u scripts/run_max_narrowing_sanity.py
run_step self-check "$PY" "${PYFLAGS_ARR[@]}" -u scripts/self_check.py
run_step curated-cases "$PY" "${PYFLAGS_ARR[@]}" -u scripts/run_cases.py
run_step optional-boundary-cases "$PY" "${PYFLAGS_ARR[@]}" -u scripts/run_hardening_cases.py
run_step witness-replay "$PY" "${PYFLAGS_ARR[@]}" -u scripts/verify_witnesses.py
run_step definability "$PY" "${PYFLAGS_ARR[@]}" -u scripts/run_definability.py
run_step minimal-basis "$PY" "${PYFLAGS_ARR[@]}" -u scripts/run_minimal_basis.py
run_step projection-laws "$PY" "${PYFLAGS_ARR[@]}" -u scripts/run_projection_laws.py
run_step claim-projection "$PY" "${PYFLAGS_ARR[@]}" -u scripts/run_claim_projection.py
run_step public-examples "$PY" "${PYFLAGS_ARR[@]}" -u scripts/run_public_examples.py
run_step provider-drift "$PY" "${PYFLAGS_ARR[@]}" -u scripts/run_provider_drift.py
run_step label-audit "$PY" "${PYFLAGS_ARR[@]}" -u scripts/run_label_audit.py
run_step baseline-suite "$PY" "${PYFLAGS_ARR[@]}" -u scripts/run_baseline_suite.py
run_step governance-exports "$PY" "${PYFLAGS_ARR[@]}" -u scripts/run_governance_exports.py
run_step adversarial-matrix "$PY" "${PYFLAGS_ARR[@]}" -u scripts/run_adversarial_matrix.py
run_step external-evidence "$PY" "${PYFLAGS_ARR[@]}" -u scripts/run_external_evidence.py
run_step deployment-manifest "$PY" "${PYFLAGS_ARR[@]}" -u scripts/run_deployment_manifest.py
run_step replay-oracle "$PY" "${PYFLAGS_ARR[@]}" -u scripts/run_replay_oracle.py
run_step source-metadata "$PY" "${PYFLAGS_ARR[@]}" -u scripts/run_source_metadata.py
run_step certificates "$PY" "${PYFLAGS_ARR[@]}" -u scripts/run_certificates.py
run_step certificate-tamper "$PY" "${PYFLAGS_ARR[@]}" -u scripts/run_certificate_tamper.py
run_step repair "$PY" "${PYFLAGS_ARR[@]}" -u scripts/run_repair.py
run_step differential-fuzz "$PY" "${PYFLAGS_ARR[@]}" -u scripts/run_differential_fuzz.py
run_step metamorphic-laws "$PY" "${PYFLAGS_ARR[@]}" -u scripts/run_metamorphic.py
run_step synthetic-scaling "$PY" "${PYFLAGS_ARR[@]}" -u scripts/run_benchmark.py
run_step iac-corpus "$PY" "${PYFLAGS_ARR[@]}" -u scripts/run_iac_scale.py
run_step iac-frontier "$PY" "${PYFLAGS_ARR[@]}" -u scripts/run_iac_frontier.py
run_step semantic-grid "$PY" "${PYFLAGS_ARR[@]}" -u scripts/run_semantic_grid.py
if [ "${FEDFENCE_SKIP_FIGURES:-0}" = "1" ]; then
  echo "[FedFence] skip figures (FEDFENCE_SKIP_FIGURES=1)"
else
  run_step figures "$PY" -u scripts/make_figures.py
fi
cleanup_temp
run_step submission-audit "$PY" "${PYFLAGS_ARR[@]}" -u scripts/audit_submission.py
run_step evidence-ledger "$PY" "${PYFLAGS_ARR[@]}" -u scripts/run_evidence_ledger.py --profile paper
