PYTHON ?= python3
export PYTHONDONTWRITEBYTECODE=1
.PHONY: character-domain tests evidence reproduce paper audit tables studies public-changes source-frontier runtime-corpus clean

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

tables:
	$(PYTHON) scripts/generate_tosem_tables.py

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
