.PHONY: all quick code-audit code-metrics tcb-report max-narrowing evidence-ledger cases hardening-cases witnesses certificates public-examples label-audit baseline-suite external-evidence replay-oracle minimal-basis repair fuzz metamorphic benchmark semantic-grid iac figures clean

all:
	./scripts/reproduce_all.sh

quick: code-audit tcb-report cases witnesses certificates public-examples label-audit baseline-suite external-evidence replay-oracle

code-audit:
	python3 scripts/run_code_audit.py

code-metrics:
	python3 scripts/run_code_metrics.py

tcb-report:
	python3 scripts/run_tcb_report.py

max-narrowing:
	python3 scripts/run_max_narrowing_sanity.py

evidence-ledger:
	python3 scripts/run_evidence_ledger.py --profile paper

cases:
	python3 scripts/run_cases.py

hardening-cases:
	python3 scripts/run_hardening_cases.py

witnesses:
	python3 scripts/verify_witnesses.py

certificates:
	python3 scripts/run_certificates.py

repair:
	python3 scripts/run_repair.py

fuzz:
	python3 scripts/run_differential_fuzz.py

metamorphic:
	python3 scripts/run_metamorphic.py

public-examples:
	python3 scripts/run_public_examples.py

label-audit:
	python3 scripts/run_label_audit.py

baseline-suite:
	python3 scripts/run_baseline_suite.py

external-evidence:
	python3 scripts/run_external_evidence.py

replay-oracle:
	python3 scripts/run_replay_oracle.py

minimal-basis:
	python3 scripts/run_minimal_basis.py

benchmark:
	python3 scripts/run_benchmark.py

semantic-grid:
	python3 scripts/run_semantic_grid.py

iac:
	python3 scripts/run_iac_scale.py

figures:
	python3 scripts/make_figures.py

clean:
	rm -rf results __pycache__ fedfence/__pycache__ scripts/__pycache__
	mkdir -p results
