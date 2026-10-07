PYTHON ?= python3
export PYTHONDONTWRITEBYTECODE=1
.PHONY: character-domain tests evidence reproduce paper audit tables studies public-changes source-frontier runtime-corpus clean
.PHONY: native-audit current-tables coherence-tests
CURRENT_RECEIPT ?= tosem/results/native-science/_fresh-science/current-science-receipt.json
CURRENT_EVIDENCE_ROOT ?= tosem/results/native-science

# Explicit current consumer; old default receipt and ten-stage audit remain distinct.
native-audit:
	$(PYTHON) -B scripts/audit_current_science.py --receipt "$(CURRENT_RECEIPT)" --evidence-root "$(CURRENT_EVIDENCE_ROOT)"

current-tables:
	$(PYTHON) -B scripts/generate_tosem_tables.py --current-receipt "$(CURRENT_RECEIPT)" --evidence-root "$(CURRENT_EVIDENCE_ROOT)"

coherence-tests:
	$(PYTHON) -B coherence_tests/test_evidence_consumers.py -v

tests:
	$(PYTHON) scripts/run_fse_tests.py

character-domain:
	$(PYTHON) scripts/run_character_domain_audit.py

evidence:
	$(PYTHON) scripts/reproduce_tosem.py

reproduce:
	$(PYTHON) scripts/reproduce_tosem.py --paper

studies public-changes source-frontier runtime-corpus:
	$(PYTHON) scripts/run_tosem_studies.py

tables: current-tables

paper: tables
	$(MAKE) -C ../paper

audit:
	$(PYTHON) scripts/audit_tosem.py

clean:
	$(MAKE) -C ../paper clean
	find . -type d -name __pycache__ -prune -exec rm -rf {} +

# Explicit networked template bootstrap only; never part of offline reproduction.
.PHONY: template-current
template-current:
	$(MAKE) -C ../paper template-current
