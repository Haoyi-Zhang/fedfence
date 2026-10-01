import json,pathlib,sys,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT))
from fse_workflow.normalized_study import decide
class PublicCorrectionTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls): cls.c=json.loads((ROOT/'study/corrections.json').read_text())
 def test_sports_store_roles_are_separate(self):
  roles={r['role']:r for r in self.c['sports_store']['roles']}; self.assertEqual({'github_actions_ecr','github_actions_frontend'},set(roles)); self.assertEqual(6,len(roles['github_actions_ecr']['after_allow'])); self.assertEqual(1,len(roles['github_actions_frontend']['after_allow']))
 def test_cross_role_subject_swaps_are_rejected(self):
  roles={r['role']:r for r in self.c['sports_store']['roles']}
  for ce in self.c['sports_store']['cross_role_counterexamples']:
   role=roles[ce['role']]; r=decide(explicit_issuer=[ce['must_reject']],allow=role['after_allow'],intent=[ce['must_reject']]); self.assertEqual([],r.admitted)
 def test_microticket_empty_and_bound_branches(self):
  m=self.c['microticket']; common={'explicit_issuer':m['explicit_issuer'],'intent':m['intent'],'required':m['required']}
  got={x['name']:decide(allow=x['allow'],**common).status for x in m['configurations']}; self.assertEqual('fail',got['after-default-empty']); self.assertEqual('pass',got['after-observed-binding'])
 def test_success_metadata_is_not_assignment_proof(self): self.assertFalse(self.c['microticket']['actions_success_metadata_is_assignment_proof'])
