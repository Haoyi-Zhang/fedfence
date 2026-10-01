import json, pathlib, sys, unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT))
from fse_workflow.normalized_study import decide,certificate,replay
AUD='sts.amazonaws.com'; VALID='repo:acme/api:ref:refs/heads/main'; EXTRA=VALID+':extra'
def t(s):return {'sub':s,'aud':AUD}
class IssuerDomainContractTests(unittest.TestCase):
 def test_explicit_nonlegacy_issuer_is_not_vacuous(self):
  p={'explicit_issuer':[t(EXTRA)],'allow':[t(EXTRA)],'intent':[t(EXTRA)],'required':[t(EXTRA)]}
  r=decide(**p); self.assertEqual(('pass',0),(r.status,r.exit_code)); self.assertEqual('pass',replay(certificate(p,r)).status)
 def test_required_identity_outside_explicit_issuer_is_unknown(self):
  r=decide(explicit_issuer=[t(VALID)],allow=[t(EXTRA)],intent=[t(EXTRA)],required=[t(EXTRA)])
  self.assertEqual(('unknown',2),(r.status,r.exit_code)); self.assertIn('required-token-outside-issuer-domain',{f.code for f in r.findings})
 def test_legal_branch_control(self):
  self.assertEqual('pass',decide(explicit_issuer=[t(VALID)],allow=[t(VALID)],intent=[t(VALID)],required=[t(VALID)]).status)
 def test_invalid_overgrant_precedence(self):
  r=decide(explicit_issuer=[t(VALID),t(EXTRA)],allow=[{'sub':'repo:acme/api:*','aud':AUD}],intent=[t(VALID)],invalid=['invalid-contract'])
  self.assertEqual(('unknown',2),(r.status,r.exit_code)); self.assertIn('admission-expansion',{f.code for f in r.latent_findings})
 def test_invalid_missing_precedence(self):
  r=decide(explicit_issuer=[t(VALID)],allow=[],intent=[t(VALID)],required=[t(VALID)],invalid=['invalid-contract'])
  self.assertEqual(('unknown',2),(r.status,r.exit_code)); self.assertIn('required-token-not-admitted',{f.code for f in r.latent_findings})
 def test_only_invalid(self):
  r=decide(explicit_issuer=[t(VALID)],allow=[t(VALID)],intent=[t(VALID)],invalid=['invalid-contract'])
  self.assertEqual(('unknown',2),(r.status,r.exit_code))
 def test_only_missing(self):
  r=decide(explicit_issuer=[t(VALID)],allow=[],intent=[t(VALID)],required=[t(VALID)])
  self.assertEqual(('fail',1),(r.status,r.exit_code))
