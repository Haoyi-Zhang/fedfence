import pathlib,sys,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT))
from fse_workflow.gate_decision import resolve
class GateDecisionPrecedenceTests(unittest.TestCase):
 def test_invalid_and_overgrant(self): self.assertEqual(('unknown',2),(lambda d:(d.status,d.exit_code))(resolve(invalid=True,overgrant=True,missing_required=False)))
 def test_invalid_and_missing(self): self.assertEqual(('unknown',2),(lambda d:(d.status,d.exit_code))(resolve(invalid=True,overgrant=False,missing_required=True)))
 def test_only_invalid(self): self.assertEqual(('unknown',2),(lambda d:(d.status,d.exit_code))(resolve(invalid=True,overgrant=False,missing_required=False)))
 def test_only_missing(self): self.assertEqual(('fail',1),(lambda d:(d.status,d.exit_code))(resolve(invalid=False,overgrant=False,missing_required=True)))
