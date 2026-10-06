"""Owned finite-event inputs; no live issuer, cloud request, or external target."""
from functools import lru_cache
from itertools import product
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'artifact'))
from fedfence.analyzer import analyze_case
from fedfence.certificate import certificate_for_case, verify_certificate
from fedfence.event import _match_value, _statement_matches, analyze_event_case

PREFIX = 'token.actions.githubusercontent.com:'


def statement(op, value, effect='Allow'):
    return {'Effect': effect, 'Action': 'sts:AssumeRoleWithWebIdentity',
            'Principal': {'Federated': 'arn:aws:iam::000000000000:oidc-provider/token.actions.githubusercontent.com'},
            'Condition': {op: {PREFIX+'sub': value}}}


def recursive_match(pattern, value):
    @lru_cache(None)
    def visit(i, j):
        if i == len(pattern):
            return j == len(value)
        if pattern[i] == '*':
            return any(visit(i+1, k) for k in range(j, len(value)+1))
        return j < len(value) and (pattern[i] == '?' or pattern[i] == value[j]) and visit(i+1, j+1)
    return visit(0, 0)


class EventSemanticsTests(unittest.TestCase):
    def test_brackets_are_literal_not_a_class(self):
        self.assertTrue(_match_value('stringlike', '[ab]', ['[ab]']))
        self.assertFalse(_match_value('stringlike', 'a', ['[ab]']))

    def test_only_star_question_mark_are_operators(self):
        for pattern, value, expected in [
            ('[!a]', 'b', False), ('[!a]', '[!a]', True),
            ('a\\b', 'a\\b', True), ('a?b', 'a\nb', True),
            ('caf?', 'café', True), ('**', '', True), ('?', '', False),
        ]:
            with self.subTest(pattern=pattern, value=value):
                self.assertEqual(expected, _match_value('stringlike', value, [pattern]))

    def test_equals_keeps_metacharacters_literal(self):
        self.assertTrue(_match_value('stringequals', '*?', ['*?']))
        self.assertFalse(_match_value('stringequals', 'ab', ['*?']))

    def test_absent_claim_does_not_match_positive_condition(self):
        for op, value in [('StringEquals', ''), ('ArnEquals', ''),
                          ('StringLike', '*'), ('ArnLike', '*')]:
            with self.subTest(operator=op):
                self.assertEqual((False, None), _statement_matches(statement(op, value), {}))

    def test_present_empty_claim_is_distinct_from_absence(self):
        for op, value in [('StringEquals', ''), ('ArnEquals', ''),
                          ('StringLike', '*'), ('ArnLike', '*')]:
            with self.subTest(operator=op):
                self.assertEqual((True, None), _statement_matches(statement(op, value), {'sub': ''}))

    def test_absent_deny_claim_does_not_remove_an_admission(self):
        allow = statement('StringEquals', 'owned')
        deny = statement('StringEquals', '', 'Deny')
        deny['Condition'] = {'StringEquals': {PREFIX+'ref': ''}}
        case = {'name': 'owned-missing-coordinate',
                'policy': {'Version': '2012-10-17', 'Statement': [allow, deny]},
                'states': [{'id': 'owned', 'mintable': True, 'intended': False,
                            'claims': {'sub': 'owned'}}]}
        result = analyze_event_case(case)
        self.assertEqual(1, result.admitted)
        self.assertFalse(result.safe)
        self.assertEqual('event-overgrant', result.findings[0].kind)

    def test_event_dispatch_and_replay_preserve_literal_brackets(self):
        case = {'name': 'owned-literal-brackets',
                'policy': {'Version': '2012-10-17', 'Statement': [statement('StringLike', '[ab]')]},
                'states': [
                    {'id': 'literal', 'mintable': True, 'intended': True, 'claims': {'sub': '[ab]'}},
                    {'id': 'letter', 'mintable': True, 'intended': False, 'claims': {'sub': 'a'}},
                ]}
        result = analyze_case(case)
        self.assertTrue(result.safe)
        self.assertEqual(1, result.allow_subject_edges)
        self.assertTrue(verify_certificate(certificate_for_case(case))[0])

    def test_bounded_matching_agrees_with_recursive_oracle(self):
        alphabet = ('a', 'b', '*', '?', '[', ']')
        values_alphabet = ('a', 'b', '[', ']', '\n')
        comparisons = 0
        for length in range(4):
            for chars in product(alphabet, repeat=length):
                pattern = ''.join(chars)
                for n in range(3):
                    for letters in product(values_alphabet, repeat=n):
                        value = ''.join(letters)
                        self.assertEqual(recursive_match(pattern, value),
                                         _match_value('stringlike', value, [pattern]), (pattern, value))
                        comparisons += 1
        self.assertEqual(8029, comparisons)


class LegacyBasisTests(unittest.TestCase):
    def test_constant_predicate_has_the_empty_minimum_basis(self):
        from fedfence.projection import minimal_claim_bases, sample_space
        for states, candidates in [(sample_space(), ['default_sub', 'ref']),
                                   (sample_space(), []), ([], [])]:
            with self.subTest(states=len(states), candidates=candidates):
                self.assertEqual([()], minimal_claim_bases(states, lambda s: True, candidates))

    def test_nonconstant_predicate_still_needs_a_coordinate(self):
        from fedfence.projection import minimal_claim_bases, sample_space, release_branch_api
        self.assertEqual([('default_sub',)],
                         minimal_claim_bases(sample_space(), release_branch_api, ['default_sub']))
