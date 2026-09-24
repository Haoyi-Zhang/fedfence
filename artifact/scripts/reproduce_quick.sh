#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PYTHONDONTWRITEBYTECODE=1
PY="${PYTHON:-python3}"
PYFLAGS_DEFAULT="${PYFLAGS:-}"
PYFLAGS_ARR=()
if [ -n "$PYFLAGS_DEFAULT" ]; then read -r -a PYFLAGS_ARR <<< "$PYFLAGS_DEFAULT"; fi
rm -rf "$ROOT/results"
mkdir -p "$ROOT/results"
cleanup_temp() {
  rm -rf "$ROOT/fedfence/__pycache__" "$ROOT/scripts/__pycache__" "$ROOT/results/.mplconfig"
  rm -f "$ROOT/../paper/main.aux" "$ROOT/../paper/main.log" "$ROOT/../paper/main.out" "$ROOT/../paper/main.toc" "$ROOT/../paper/main.fls" "$ROOT/../paper/main.fdb_latexmk" "$ROOT/../paper/main.synctex.gz"
  rm -f "$ROOT/../main.aux" "$ROOT/../main.log" "$ROOT/../main.out" "$ROOT/../main.toc" "$ROOT/../main.fls" "$ROOT/../main.fdb_latexmk" "$ROOT/../main.synctex.gz"
}
trap cleanup_temp EXIT
export FEDFENCE_CASE_LIMIT="${FEDFENCE_CASE_LIMIT:-0}"
export FEDFENCE_CERT_LIMIT="${FEDFENCE_CERT_LIMIT:-0}"
export FEDFENCE_REPAIR_LIMIT="${FEDFENCE_REPAIR_LIMIT:-0}"
export FEDFENCE_TEMPLATE_PROFILE="${FEDFENCE_TEMPLATE_PROFILE:-registered}"
run_step() {
  local name="$1"; shift
  echo "[FedFence quick] begin ${name}"
  ( cd "$ROOT" && "$@" )
  echo "[FedFence quick] end ${name}"
}
# Smoke profile: all representative parsers and replay paths, but no exhaustive
# self-check, fuzzing, large grids.  Use
# reproduce_all.sh for the paper-profile run.
run_step code-metrics "$PY" "${PYFLAGS_ARR[@]}" -u scripts/run_code_metrics.py
run_step tcb-report "$PY" "${PYFLAGS_ARR[@]}" -u scripts/run_tcb_report.py
run_step max-narrowing "$PY" "${PYFLAGS_ARR[@]}" -u scripts/run_max_narrowing_sanity.py
run_step curated-cases "$PY" "${PYFLAGS_ARR[@]}" -u scripts/run_cases.py
run_step optional-boundary-cases "$PY" "${PYFLAGS_ARR[@]}" -u scripts/run_hardening_cases.py
run_step witness-replay "$PY" "${PYFLAGS_ARR[@]}" -u scripts/verify_witnesses.py
run_step claim-projection "$PY" "${PYFLAGS_ARR[@]}" -u scripts/run_claim_projection.py
run_step certificates "$PY" "${PYFLAGS_ARR[@]}" -u scripts/run_certificates.py
run_step certificate-tamper "$PY" "${PYFLAGS_ARR[@]}" -u scripts/run_certificate_tamper.py
run_step public-examples "$PY" "${PYFLAGS_ARR[@]}" -u scripts/run_public_examples.py
run_step provider-drift "$PY" "${PYFLAGS_ARR[@]}" -u scripts/run_provider_drift.py
run_step label-audit "$PY" "${PYFLAGS_ARR[@]}" -u scripts/run_label_audit.py
run_step baseline-suite "$PY" "${PYFLAGS_ARR[@]}" -u scripts/run_baseline_suite.py
run_step governance-exports "$PY" "${PYFLAGS_ARR[@]}" -u scripts/run_governance_exports.py
run_step external-evidence "$PY" "${PYFLAGS_ARR[@]}" -u scripts/run_external_evidence.py
run_step deployment-manifest "$PY" "${PYFLAGS_ARR[@]}" -u scripts/run_deployment_manifest.py
run_step replay-oracle "$PY" "${PYFLAGS_ARR[@]}" -u scripts/run_replay_oracle.py
run_step source-metadata "$PY" "${PYFLAGS_ARR[@]}" -u scripts/run_source_metadata.py
run_step iac-frontier "$PY" "${PYFLAGS_ARR[@]}" -u scripts/run_iac_frontier.py
cleanup_temp
if command -v timeout >/dev/null 2>&1; then
  run_step submission-audit timeout 120 "$PY" "${PYFLAGS_ARR[@]}" -u scripts/audit_submission.py
else
  run_step submission-audit "$PY" "${PYFLAGS_ARR[@]}" -u scripts/audit_submission.py
fi
run_step evidence-ledger "$PY" "${PYFLAGS_ARR[@]}" -u scripts/run_evidence_ledger.py --profile quick
cleanup_temp
