import unittest
from fse_workflow.study import summarize

class StudyTests(unittest.TestCase):
    def row(self,i,**kwargs):
        return {'unit_id':str(i),'source_kind':'public-repository','oracle':{'label':'unknown'},**kwargs}
    def test_unlabeled_not_correct(self):
        r=summarize([self.row(1,extraction='extracted',support='supported',fedfence='pass')])
        self.assertEqual(0,r['external_labeled']); self.assertEqual(0,r['external_correct'])
        self.assertIsNone(r['external_accuracy_on_classified'])
    def test_parser_failure_stays_in_coverage_denominator(self):
        r=summarize([self.row(1,extraction='extracted',support='supported'),self.row(2,extraction='unresolved')])
        self.assertEqual(.5,r['coverage_over_candidates']); self.assertEqual(1,r['coverage_over_extracted'])
    def test_synthetic_never_external_accuracy(self):
        r=summarize([self.row(1,source_kind='generated',fedfence='pass',oracle={'label':'safe','provenance':'synthetic-specification','evidence_ref':'fixture'})])
        self.assertEqual(0,r['external_classified'])
    def test_unknown_not_false_positive(self):
        r=summarize([self.row(1,fedfence='unknown',oracle={'label':'unsafe','provenance':'owner-confirmed','evidence_ref':'owner-review'})])
        self.assertEqual(1,r['external_unknown']); self.assertEqual(0,r['external_classified'])
    def test_duplicate_denominator_rejected(self):
        with self.assertRaises(ValueError): summarize([self.row(1), self.row(1)])
    def test_missing_oracle_provenance_rejected(self):
        with self.assertRaises(ValueError): summarize([self.row(1,oracle={'label':'safe'})])
    def test_known_correct_and_incorrect(self):
        oracle={'label':'unsafe','provenance':'independent-double-review','evidence_ref':'review'}
        r=summarize([self.row(1,fedfence='fail',oracle=oracle),self.row(2,fedfence='pass',oracle=oracle)])
        self.assertEqual(.5,r['external_accuracy_on_classified'])
