from __future__ import annotations
from pathlib import Path
import json
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT))
from fse_workflow.io import save_json
suite=unittest.defaultTestLoader.discover(str(ROOT/"tests"))
runner=unittest.TextTestRunner(verbosity=2)
r=runner.run(suite)
summary={"tests_run":r.testsRun,"failures":len(r.failures),"errors":len(r.errors),"skipped":len(r.skipped),
         "passed":r.wasSuccessful(), "evidence_type":"local synthetic regression tests, not deployment evidence"}
save_json(ROOT/"fse/results/unit_tests.json",summary)
raise SystemExit(0 if r.wasSuccessful() else 1)
