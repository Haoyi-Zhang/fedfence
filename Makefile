PYTHON ?= python3
export PYTHONDONTWRITEBYTECODE=1
.PHONY: tests demo public-changes benchmark source-frontier runtime-corpus reproduce paper audit clean

tests:
	$(PYTHON) scripts/run_fse_tests.py

demo:
	$(PYTHON) scripts/run_demo_suite.py

public-changes:
	$(PYTHON) scripts/run_public_change_study.py

benchmark:
	$(PYTHON) scripts/benchmark_public_changes.py

source-frontier:
	$(PYTHON) scripts/run_source_frontier_study.py

runtime-corpus:
	$(PYTHON) scripts/run_runtime_compatibility_study.py

reproduce:
	$(PYTHON) scripts/reproduce_final.py

paper:
	$(MAKE) -C paper

audit:
	$(PYTHON) scripts/audit_final.py

clean:
	$(MAKE) -C paper clean
	find fse_workflow tests scripts -type d -name __pycache__ -prune -exec rm -rf {} +
