"""Benign literal/wildcard and explicit-input regressions for the final revision."""
from __future__ import annotations
import copy
from datetime import datetime, timezone
import time
import unittest
from unittest.mock import patch

from fse_workflow.conformance import (ConformanceBudgetExceeded, _as_list,
    _glob_matches, effective_policy_accepts)
from fse_workflow.contract import contract_digest
from fse_workflow.fragment import PREFIX, inspect_policy
from fse_workflow.gate import review
from fse_workflow.receipt import make_receipt, replay_receipt
from scripts.make_workflow_examples import packet, rehash

NOW = '2026-09-23T01:00:00Z'
SUB = 'repo:acme/api:ref:refs/heads/main'
AUD = 'sts.amazonaws.com'

def positive_packet():
    p = packet()
    p['contract']['required_tokens'] = [{'sub': SUB, 'aud': AUD, 'reason': 'benign release identity'}]
    p['contract']['review']['approved_digest'] = contract_digest(p['contract'])
    return p

class FinalBoundaryTests(unittest.TestCase):
    def test_empty_scalar_and_list_are_equivalent(self):
        outcomes = []
        for value in ('', ['']):
            p = positive_packet()
            p['snapshots']['policy']['body']['Statement'][0]['Condition']['StringEquals'][PREFIX+'sub'] = value
            rehash(p, 'policy')
            outcomes.append(review(p, now=NOW)['verdict'])
        self.assertEqual(['fail', 'fail'], outcomes)

    def test_empty_literal_does_not_remove_other_alternative(self):
        p = positive_packet()
        p['snapshots']['policy']['body']['Statement'][0]['Condition']['StringEquals'][PREFIX+'sub'] = ['', SUB]
        rehash(p, 'policy')
        self.assertEqual('pass', review(p, now=NOW)['verdict'])

    def test_empty_deny_list_literal_preserves_positive(self):
        p = positive_packet()
        deny = copy.deepcopy(p['snapshots']['policy']['body']['Statement'][0])
        deny['Effect'] = 'Deny'
        deny['Condition']['StringEquals'][PREFIX+'sub'] = ['']
        p['snapshots']['policy']['body']['Statement'].append(deny)
        rehash(p, 'policy')
        self.assertEqual('pass', review(p, now=NOW)['verdict'])

    def test_nonempty_condition_list_not_nonempty_each_string(self):
        self.assertEqual([''], _as_list(''))
        self.assertEqual([''], _as_list(['']))
        for value in ([], [None], 3, False):
            with self.subTest(value=value), self.assertRaises(ValueError):
                _as_list(value)

    def test_explicit_falsey_time_is_not_omission(self):
        with patch('fse_workflow.gate.datetime') as clock:
            clock.now.return_value = datetime(2026,9,23,1,tzinfo=timezone.utc)
            for value in ('', False, 0):
                with self.subTest(value=value):
                    result = review(positive_packet(), now=value)
                    self.assertEqual('unknown', result['verdict'])
                    self.assertIn(result['findings'][0]['code'], {'invalid-check-time','invalid-timestamp'})
            clock.now.assert_not_called()

    def test_omitted_time_uses_current_clock(self):
        with patch('fse_workflow.gate.datetime') as clock:
            clock.now.return_value = datetime(2026,9,23,1,tzinfo=timezone.utc)
            self.assertEqual('pass', review(positive_packet())['verdict'])
            clock.now.assert_called_once_with(timezone.utc)

    def test_equivalent_timezone_offsets(self):
        self.assertEqual('pass', review(positive_packet(), now='2026-09-23T09:00:00+08:00')['verdict'])

    def test_future_snapshot_is_unknown(self):
        self.assertEqual('unknown', review(positive_packet(), now='2026-09-22T23:59:59Z')['verdict'])

    def test_staggered_snapshot_interval_edges(self):
        p=positive_packet()
        p['snapshots']['workflow']['observed_at']='2026-09-23T00:30:00Z'
        for stamp, verdict in [('2026-09-23T00:29:59Z','unknown'),
                               ('2026-09-23T00:30:00Z','pass'),
                               ('2026-09-24T00:00:00Z','pass'),
                               ('2026-09-24T00:00:01Z','unknown')]:
            with self.subTest(time=stamp):
                self.assertEqual(verdict, review(p, now=stamp)['verdict'])

    def test_receipt_within_same_freshness_interval(self):
        p=positive_packet(); receipt=make_receipt(p,review(p,now=NOW))
        result=replay_receipt(receipt,now='2026-09-23T02:00:00Z')
        self.assertTrue(result['receipt_replay_ok']); self.assertEqual('pass',result['verdict'])

    def test_unknown_receipt_can_agree_without_becoming_pass(self):
        p=positive_packet(); stamp='2026-09-25T00:00:00Z'
        result=replay_receipt(make_receipt(p,review(p,now=stamp)),now=stamp)
        self.assertTrue(result['receipt_replay_ok']); self.assertEqual('unknown',result['verdict'])

    def test_fail_receipt_can_agree_without_becoming_pass(self):
        p=positive_packet(); st=p['snapshots']['policy']['body']['Statement'][0]
        deny=copy.deepcopy(st); deny['Effect']='Deny'; p['snapshots']['policy']['body']['Statement'].append(deny)
        rehash(p,'policy'); result=replay_receipt(make_receipt(p,review(p,now=NOW)),now=NOW)
        self.assertTrue(result['receipt_replay_ok']); self.assertEqual('fail',result['verdict'])

    def test_missing_policy_version_not_defaulted(self):
        p=packet();p['snapshots']['policy']['body'].pop('Version');rehash(p,'policy')
        self.assertEqual('unknown',review(p,now=NOW)['verdict'])

    def test_nonstring_optional_ids_refused(self):
        for level, key in [('policy','Id'),('statement','Sid')]:
            p=packet(); policy=p['snapshots']['policy']['body']
            target=policy if level=='policy' else policy['Statement'][0]
            target[key]={'unexpected':'object'};rehash(p,'policy')
            self.assertEqual('unknown',review(p,now=NOW)['verdict'])

    def test_string_optional_ids_do_not_change_verdict(self):
        p=positive_packet();policy=p['snapshots']['policy']['body'];policy['Id']='Example'
        policy['Statement'][0]['Sid']='Release';rehash(p,'policy')
        self.assertEqual('pass',review(p,now=NOW)['verdict'])

    def test_glob_empty_and_adjacent_stars(self):
        for pat, word, expected in [('', '', True),('', 'a', False),('*','',True),
            ('**','',True),('?','',False),('*?','a',True),('a**b','ab',True),
            ('a**b','axxb',True),('a**b','axxc',False)]:
            with self.subTest(pattern=pat, word=word):
                self.assertEqual(expected,_glob_matches(pat,word))

    def test_glob_brackets_backslash_newline_unicode_literal(self):
        for pat, word, expected in [('[ab]','a',False),('[ab]','[ab]',True),
            (r'a\b',r'a\b',True),('a?b','a\nb',True),('caf?','café',True)]:
            self.assertEqual(expected,_glob_matches(pat,word))

    def test_matcher_work_budget_returns_explicit_exhaustion(self):
        with self.assertRaises(ConformanceBudgetExceeded):
            _glob_matches('*?'*800,'a'*2000)

    def test_matcher_expired_deadline(self):
        with self.assertRaises(ConformanceBudgetExceeded):
            _glob_matches('*','a',deadline=time.monotonic()-1)

    def test_tiny_gate_budget_is_unknown(self):
        result=review(positive_packet(),now=NOW,timeout=1e-12)
        self.assertEqual('unknown',result['verdict'])
        self.assertEqual('analysis-timeout',result['findings'][0]['code'])

    def test_positive_budget_exhaustion_is_not_fail_or_pass(self):
        with patch('fse_workflow.gate.check_required_tokens',side_effect=ConformanceBudgetExceeded('synthetic exhausted budget')):
            result=review(positive_packet(),now=NOW)
        self.assertEqual('unknown',result['verdict'])
        self.assertEqual('positive-analysis-budget',result['findings'][-1]['code'])

    def test_condition_group_conjunction(self):
        p=packet()['snapshots']['policy']['body'];st=p['Statement'][0]
        st['Condition']['StringLike']={PREFIX+'sub':'*:refs/heads/dev'}
        self.assertFalse(effective_policy_accepts(p,dict(sub=SUB,aud=AUD)))

    def test_statement_reorder_preserves_complete_tuple_result(self):
        p=packet()['snapshots']['policy']['body'];st=copy.deepcopy(p['Statement'][0]);st['Effect']='Deny'
        st['Condition']['StringEquals'][PREFIX+'aud']='vault';p['Statement'].append(st)
        token=dict(sub=SUB,aud=AUD)
        self.assertTrue(effective_policy_accepts(p,token));p['Statement'].reverse()
        self.assertTrue(effective_policy_accepts(p,token))

    def test_normalized_budget_exhaustion_is_unknown(self):
        from fse_workflow.normalized_study import decide
        with patch('fse_workflow.normalized_study._glob_matches', side_effect=ConformanceBudgetExceeded('benign injected exhaustion')):
            result=decide(explicit_issuer=[(SUB,AUD)],allow=[('*','*')],intent=[(SUB,AUD)])
        self.assertEqual('unknown',result.status)
        self.assertEqual('positive-analysis-budget',result.findings[0].code)

    def test_long_literal_has_linear_fastpath(self):
        value='a'*3000
        self.assertTrue(_glob_matches(value,value))
        self.assertFalse(_glob_matches(value,value+'b'))

    def test_empty_positive_set_still_checks_expired_budget(self):
        from fse_workflow.conformance import check_required_tokens
        with self.assertRaises(ConformanceBudgetExceeded):
            check_required_tokens({}, {}, [], deadline=time.monotonic()-1)

    def test_governance_source_reference_must_be_string(self):
        import json
        from pathlib import Path
        base=json.loads((Path(__file__).resolve().parents[1]/'examples/release_gate/environment_reviewed.json').read_text())
        for source in (True, 1, ['declared-ref'], {'ref':'declared-ref'}):
            p=copy.deepcopy(base)
            p['snapshots']['governance']['body']['environments']['prod']['source_ref']=source
            rehash(p,'governance')
            self.assertEqual('unknown',review(p,now=NOW)['verdict'])

    def test_issuer_refinement_does_not_replace_constructor(self):
        from fse_workflow.conformance import issuer_accepts
        token=dict(sub='custom:subject',aud=AUD)
        self.assertFalse(issuer_accepts({'issuer_subjects':['custom:subject']},token))

    def test_empty_issuer_refinements_keep_inherited_default(self):
        from fse_workflow.conformance import issuer_accepts
        self.assertTrue(issuer_accepts({'issuer_subjects':[], 'issuer_audiences':[]},dict(sub=SUB,aud=AUD)))

    def test_explicit_issuer_audience_is_respected(self):
        from fse_workflow.conformance import issuer_accepts
        self.assertFalse(issuer_accepts({'issuer_audiences':['vault']},dict(sub=SUB,aud=AUD)))
        self.assertTrue(issuer_accepts({'issuer_audiences':['vault']},dict(sub=SUB,aud='vault')))

    def test_issuer_list_types_do_not_coerce(self):
        from fse_workflow.conformance import issuer_accepts
        for key in ('issuer_subjects','issuer_audiences'):
            with self.assertRaises(ValueError):
                issuer_accepts({key:'*'},dict(sub=SUB,aud=AUD))

    def test_unmintable_audience_is_invalid_positive_not_missing(self):
        from fse_workflow.conformance import check_required_tokens
        spec={'allowed_subjects':[SUB],'allowed_audiences':[AUD],'issuer_audiences':['vault']}
        result=check_required_tokens(packet()['snapshots']['policy']['body'],spec,[dict(sub=SUB,aud=AUD)])
        self.assertEqual(1,len(result['invalid']))
        self.assertEqual([],result['missing'])

    def test_huge_timeout_integer_is_unknown(self):
        result=review(positive_packet(),now=NOW,timeout=10**1000)
        self.assertEqual('unknown',result['verdict'])
        self.assertEqual('invalid-timeout',result['findings'][0]['code'])

    def test_deep_unserializable_packet_is_unknown(self):
        p=positive_packet(); value={}; current=value
        for _ in range(1500):
            current['nested']={};current=current['nested']
        p['snapshots']['policy']['body']['unknown']=value
        self.assertEqual('unknown',review(p,now=NOW)['verdict'])
