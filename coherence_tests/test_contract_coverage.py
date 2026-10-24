from pathlib import Path
import copy
import json
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parent))
from contract_coverage import ROOT, qualification, literal_subjects


class ContractCoverageTests(unittest.TestCase):
    def test_retained_nonvacuity_and_same_information(self):
        public=json.loads((ROOT/'tosem/results/public_study.json').read_text())
        corrections=json.loads((ROOT/'study/corrections.json').read_text())
        result=qualification(public,corrections)
        self.assertEqual(result['configurations'],21)
        self.assertEqual(result['finite_direct_set_comparisons'],7)
        self.assertEqual(result['finite_direct_set_disagreements'],[])
        self.assertEqual(sum(x['required_occurrences'] for x in result['rows']),17)
        self.assertEqual(sum(x['lower_evidence']=='vacuous' for x in result['rows']),14)

    def test_wrong_finite_admission_is_detected(self):
        public=json.loads((ROOT/'tosem/results/public_study.json').read_text())
        corrections=json.loads((ROOT/'study/corrections.json').read_text())
        row=next(x for x in public['rows'] if x['role']=='github_actions_ecr' and x['configuration']=='after')
        row['result']['admitted']=[]
        self.assertTrue(qualification(public,corrections)['finite_direct_set_disagreements'])

    def test_literal_projection_and_nested_quoted_braces(self):
        text='# resource "aws_iam_role" "test" {}\nresource "aws_iam_role" "test" { name="{quoted}/*"\n assume_role_policy=jsonencode({Statement=[{Effect="Allow" Action="sts:AssumeRoleWithWebIdentity" Condition={StringEquals={"token.actions.githubusercontent.com:sub"=["repo:a/b:ref:refs/heads/main"]}}}]})\n}'
        result=literal_subjects(text,'test')
        self.assertEqual(result['subjects'],['repo:a/b:ref:refs/heads/main'])
        for bad in (text+text,text.replace('repo:a/b','repo:${var.repo}'),text[:-1],text.replace('StringEquals','StringLike')):
            with self.assertRaises(ValueError):literal_subjects(bad,'test')

    def test_subject_in_tags_is_not_a_trust_condition(self):
        text='resource "aws_iam_role" "test" { tags={"token.actions.githubusercontent.com:sub"=["repo:a/b:ref:refs/heads/main"]} assume_role_policy=jsonencode({Statement=[{Effect="Allow" Action="sts:AssumeRoleWithWebIdentity" Condition={StringEquals={"token.actions.githubusercontent.com:aud"="sts.amazonaws.com"}}}]}) }'
        with self.assertRaises(ValueError):literal_subjects(text,'test')

    def test_wrong_nesting_duplicate_or_multiple_statements_rejected(self):
        good='resource "aws_iam_role" "test" { assume_role_policy=jsonencode({Statement=[{Effect="Allow" Action="sts:AssumeRoleWithWebIdentity" Condition={StringEquals={"token.actions.githubusercontent.com:sub"="repo:a/b:ref:refs/heads/main"}}}]}) }'
        self.assertEqual(literal_subjects(good,'test')['subjects'],['repo:a/b:ref:refs/heads/main'])
        for bad in (
                good.replace('Condition={StringEquals=', 'Metadata={StringEquals='),
                good.replace('Effect="Allow"','Effect="Deny"'),
                good.replace('Action="sts:AssumeRoleWithWebIdentity"','Action="other"'),
                good.replace('Condition={StringEquals=', 'Condition={Other={} StringEquals='),
                good.replace('Condition={StringEquals=', 'Condition={} Condition={StringEquals='),
                good.replace('}]})','},{Effect="Allow"}]})'),
                good.replace('assume_role_policy=jsonencode','nested={assume_role_policy=jsonencode').replace('}) }','})} }')):
            with self.subTest(source=bad),self.assertRaises(ValueError):literal_subjects(bad,'test')

    def test_quoted_brackets_and_unrelated_tags_do_not_change_condition(self):
        text='resource "aws_iam_role" "test" { tags={"token.actions.githubusercontent.com:sub"="wrong"} assume_role_policy=jsonencode({Statement=[{Effect="Allow" Action="sts:AssumeRoleWithWebIdentity" Condition={StringEquals={"token.actions.githubusercontent.com:sub"=["repo:a/b]:ref:refs/heads/main"]}}}]}) }'
        self.assertEqual(literal_subjects(text,'test')['subjects'],['repo:a/b]:ref:refs/heads/main'])


if __name__=='__main__':unittest.main()
