from __future__ import annotations
import copy
import unittest
from unittest.mock import patch
from fse_workflow.contract import contract_digest
from fse_workflow.conformance import issuer_accepts
from fse_workflow.fragment import PREFIX
from fse_workflow.gate import review
from fse_workflow.io import digest
from fse_workflow.normalized_study import decide, certificate, replay
from fse_workflow.receipt import make_receipt, replay_receipt
from scripts.make_workflow_examples import packet, rehash

NOW = '2026-09-23T01:00:00Z'
A = ('repo:acme/api:ref:refs/heads/main', 'sts.amazonaws.com')
B = ('repo:acme/api:ref:refs/heads/dev', 'sts.amazonaws.com')
def positive(p, tokens):
    p['contract']['required_tokens'] = [dict(sub=s,aud=a,reason='synthetic positive regression') for s,a in tokens]
    p['contract']['review']['approved_digest'] = contract_digest(p['contract'])
def reseal(c,key):
    c[key]=digest({k:v for k,v in c.items() if k!=key})

class TOSEMConsistencyTests(unittest.TestCase):
    def test_gate_invalid_dominates_overgrant(self):
        p=packet(); positive(p,[B])
        st=p['snapshots']['policy']['body']['Statement'][0]
        st['Condition']['StringEquals'].pop(PREFIX+'sub')
        st['Condition']['StringLike']={PREFIX+'sub':'repo:acme/api:*'}
        rehash(p,'policy'); r=review(p,now=NOW)
        self.assertEqual('unknown',r['verdict']); self.assertTrue(r['required_token_checks']['invalid'])
        self.assertTrue(any(x.get('kind')=='subject-overgrant' for x in r['findings']))
    def test_gate_invalid_dominates_valid_missing(self):
        p=packet(); positive(p,[A,B])
        st=copy.deepcopy(p['snapshots']['policy']['body']['Statement'][0]); st['Effect']='Deny'
        p['snapshots']['policy']['body']['Statement'].append(st); rehash(p,'policy')
        r=review(p,now=NOW); self.assertEqual('unknown',r['verdict'])
        self.assertEqual(1,len(r['required_token_checks']['missing']))
    def test_mixed_provider_principals_refused(self):
        p=packet(); st=copy.deepcopy(p['snapshots']['policy']['body']['Statement'][0])
        st['Principal']['Federated']=st['Principal']['Federated'].replace('000000000000','111111111111')
        p['snapshots']['policy']['body']['Statement'].append(st); rehash(p,'policy')
        r=review(p,now=NOW); self.assertEqual('unknown',r['verdict'])
        self.assertIn('mixed-provider-principals',[x['code'] for x in r['findings']])
    def test_invalid_timeout_inputs(self):
        for value in (0,-1,float('inf'),float('nan'),True,'15'):
            with self.subTest(value=value):
                r=review(packet(),now=NOW,timeout=value)
                self.assertEqual('invalid-timeout',r['findings'][0]['code'])
    def test_receipt_roundtrip_with_positive(self):
        p=packet(); positive(p,[A]); r=review(p,now=NOW)
        got=replay_receipt(make_receipt(p,r),now=NOW)
        self.assertEqual('pass',got['verdict']); self.assertTrue(got['receipt_replay_ok'])
    def test_receipt_forged_decision_rehashed(self):
        p=packet(); c=make_receipt(p,review(p,now=NOW)); c['decision']['verdict']='fail'; reseal(c,'receipt_sha256')
        self.assertEqual('receipt-replay-disagreement',replay_receipt(c,now=NOW)['findings'][0]['code'])
    def test_receipt_required_obligation_tamper_rehashed(self):
        p=packet(); c=make_receipt(p,review(p,now=NOW)); positive(c['packet'],[B]); reseal(c,'receipt_sha256')
        got=replay_receipt(c,now=NOW)
        self.assertEqual('unknown',got['verdict']); self.assertEqual('unknown',got['current_result']['verdict'])
    def test_receipt_expired_at_replay(self):
        p=packet(); c=make_receipt(p,review(p,now=NOW))
        got=replay_receipt(c,now='2026-09-25T00:00:00Z')
        self.assertEqual('unknown',got['verdict']); self.assertFalse(got['receipt_replay_ok'])
    def test_receipt_implementation_change(self):
        p=packet(); c=make_receipt(p,review(p,now=NOW))
        with patch('fse_workflow.gate.implementation_digest',return_value='changed'):
            self.assertEqual('unknown',replay_receipt(c,now=NOW)['verdict'])
    def test_receipt_unsealed_tamper(self):
        p=packet(); c=make_receipt(p,review(p,now=NOW)); c['decision']['exit_code']=2
        self.assertEqual('invalid-receipt',replay_receipt(c,now=NOW)['findings'][0]['code'])
    def test_snapshot_age_exact_boundary(self):
        self.assertEqual('pass',review(packet(),now='2026-09-24T00:00:00Z')['verdict'])
        self.assertEqual('unknown',review(packet(),now='2026-09-24T00:00:01Z')['verdict'])
    def test_normalized_generators_not_consumed(self):
        r=decide(explicit_issuer=(t for t in [A,B]),allow=(t for t in [A,B]),intent=(t for t in [A,B]),required=(t for t in [A,B]))
        self.assertEqual('pass',r.status); self.assertEqual({A,B},set(r.admitted))
    def test_brackets_are_literal_not_character_class(self):
        a=('repo:acme/api:ref:refs/heads/[ab]','x'); b=('repo:acme/api:ref:refs/heads/a','x')
        r=decide(explicit_issuer=[a,b],allow=[a],intent=[a],required=[a])
        self.assertEqual('pass',r.status); self.assertEqual([a],r.admitted)
    def test_normalized_no_coordinate_coercion(self):
        self.assertEqual('unknown',decide(explicit_issuer=[(1,'x')],allow=[],intent=[]).status)
    def test_normalized_required_outside_intent(self):
        r=decide(explicit_issuer=[A,B],allow=[B],intent=[A],required=[B])
        self.assertEqual('unknown',r.status); self.assertTrue(r.latent_findings)
    def test_normalized_entire_result_replayed(self):
        p=dict(explicit_issuer=[A,B],allow=[A],intent=[A],required=[A]); c=certificate(p,decide(**p))
        c['decision']['admitted']=[]; reseal(c,'certificate_digest')
        got = replay(c)
        self.assertEqual('unknown', got.status)
        self.assertTrue(got.findings)
        self.assertEqual('decision-replay-mismatch', got.findings[0].code)
    def test_normalized_certificate_roundtrip(self):
        p=dict(explicit_issuer=[A,B],allow=[A],intent=[A],required=[A])
        self.assertEqual('pass',replay(certificate(p,decide(**p))).status)
    def test_normalized_unknown_operator(self):
        self.assertEqual('unknown',decide(explicit_issuer=[A],allow=[dict(sub=A[0],aud=A[1],operator='StringNotLike')],intent=[A]).status)
