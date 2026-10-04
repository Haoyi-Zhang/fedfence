"""Regression obligations for complete character support in the supplied model.

All inputs are synthetic strings. No real issuer, workflow, credential, or cloud
account is involved. Direct predicates/recursion do not call support selection.
"""
from __future__ import annotations
import copy
import itertools
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'artifact'))
from fedfence.regular import (CHARACTER_DOMAIN, CODEPOINT_LIMIT, DEFAULT_ALPHABET,
    alphabet_from_patterns, pattern_literals, fresh_character, validate_support,
    glob, union_literals, contains_witness)
from fedfence.github import (GITHUB_SUPPORT_LITERALS, github_alphabet_from_patterns,
    issuer_subject_nfa, parse_github_subject)
from fedfence.analyzer import analyze_case
from fedfence.certificate import (pair_certificate, pair_group_certificate,
    triple_certificate, triple_group_certificate, certificate_for_case, verify_certificate)
from fse_workflow.conformance import (_glob_matches, issuer_accepts,
    effective_policy_accepts, intent_accepts)
from fse_workflow.gate import review
from fse_workflow.receipt import make_receipt, replay_receipt
from fse_workflow.io import digest
from scripts.character_domain_fixtures import (SUB, AUD, BRANCH, NOW,
    exhausted_case, exhausted_packet)


class SupportDomainTests(unittest.TestCase):
    def test_entire_preference_pool_exhaustion_retains_other(self):
        literals=set(DEFAULT_ALPHABET)|{'*','?'}
        alph=alphabet_from_patterns(('equals',sorted(literals)),['?'])
        self.assertTrue(literals < set(alph))
        self.assertTrue(validate_support(alph,('equals',sorted(literals)))[0])

    def test_empty_preference_pool_does_not_shrink_domain(self):
        alph=alphabet_from_patterns(['?'],base=())
        self.assertTrue(alph)
        self.assertTrue(glob('?',alph).accepts(alph[0]))

    def test_all_ascii_literals_leave_a_non_ascii_representative(self):
        literals=''.join(map(chr,range(128)))
        alph=alphabet_from_patterns(('equals',[literals]))
        self.assertEqual(129,len(alph))
        self.assertTrue(any(ord(ch)>=128 for ch in alph))

    def test_all_bmp_literals_leave_a_supplementary_representative(self):
        literals=''.join(map(chr,range(0x10000)))
        alph=alphabet_from_patterns(('equals',[literals]))
        self.assertEqual(0x10001,len(alph))
        self.assertTrue(any(ord(ch)>=0x10000 for ch in alph))

    def test_no_other_only_when_whole_domain_is_exhausted(self):
        # A membership oracle for the complete finite code-point domain.
        class EntireDomain:
            def __contains__(self,ch): return isinstance(ch,str) and len(ch)==1
        self.assertIsNone(fresh_character(EntireDomain(),base=()))

    def test_a_fixed_extra_sentinel_can_also_become_literal(self):
        literals=set(DEFAULT_ALPHABET)|set('!*?')
        alph=alphabet_from_patterns(('equals',sorted(literals)))
        self.assertTrue(set(alph)-literals)
        self.assertNotIn('!',set(alph)-literals)

    def test_equality_metacharacters_are_literal_singletons(self):
        self.assertEqual({'*','?'},pattern_literals(('equals',['*?'])))
        self.assertEqual(set(),pattern_literals(('like',['*?'])))

    def test_tuples_are_not_converted_to_python_repr(self):
        self.assertEqual({'\n','é','𐀀'},pattern_literals(('\n','é','𐀀')))
        self.assertNotIn('\\',pattern_literals(('\n','é','𐀀')))

    def test_generator_values_preserve_exact_unicode_literals(self):
        values=(v for v in ['é','\ud800','\U0010ffff','*'])
        self.assertEqual(set('é\ud800\U0010ffff*'),pattern_literals(('equals',values)))

    def test_mapping_literal_alias_matches_tuple(self):
        self.assertEqual(pattern_literals(('literal',['*?'])),
                         pattern_literals({'op':'literal','values':['*?']}))

    def test_unknown_support_operator_is_not_silently_glob(self):
        with self.assertRaises(ValueError):
            alphabet_from_patterns({'op':'unknown','values':['?']})

    def test_invalid_base_characters_are_rejected(self):
        for base in (['ab'],[None],[1],['']):
            with self.subTest(base=base),self.assertRaises(ValueError):
                alphabet_from_patterns(['?'],base=base)

    def test_support_validator_does_not_trust_fresh_selector(self):
        literals=set(DEFAULT_ALPHABET)
        with patch('fedfence.regular.fresh_character',return_value=None):
            alph=alphabet_from_patterns(('equals',sorted(literals)))
        ok,note=validate_support(alph,('equals',sorted(literals)))
        self.assertFalse(ok);self.assertIn('OTHER',note)

    def test_missing_singleton_is_rejected_before_remainder(self):
        self.assertFalse(validate_support(('a','z'),('equals',['a?']))[0])

    def test_duplicate_and_noncharacter_support_are_rejected(self):
        for alph in (('a','a'),('ab',),('',),(None,)):
            self.assertFalse(validate_support(alph,['a'])[0])

    def test_finite_nfa_api_requires_representative_words(self):
        alph=alphabet_from_patterns(['?'])
        self.assertFalse(glob('?',alph).accepts('雪'))
        self.assertTrue(glob('?',alph).accepts(alph[0]))
        # The scalar path uses the concrete domain, never the finite support.
        self.assertTrue(_glob_matches('?','雪'))

    def test_containment_retains_a_word_outside_every_listed_character(self):
        pool=list(DEFAULT_ALPHABET)+['*','?']
        alph=alphabet_from_patterns(('equals',pool),['?'])
        word=contains_witness(glob('?',alph),union_literals(pool,alph),alph)
        self.assertIsNotNone(word);self.assertNotIn(word,pool)
        self.assertTrue(_glob_matches('?',word))

    def test_raw_glob_is_codepoint_not_byte_or_grapheme(self):
        self.assertTrue(_glob_matches('?','𐀀'))
        self.assertTrue(_glob_matches('?','\ud800'))
        self.assertFalse(_glob_matches('?','e\u0301'))
        self.assertFalse(_glob_matches('é','e\u0301'))


class ConstructorDomainTests(unittest.TestCase):
    def test_constructor_support_includes_excluded_metacharacters(self):
        alph=github_alphabet_from_patterns(['*'])
        self.assertTrue(set(':/*?').issubset(alph))
        self.assertTrue(validate_support(alph,('equals',GITHUB_SUPPORT_LITERALS),['*'])[0])

    def test_parser_and_scalar_reject_literal_constructor_metacharacters(self):
        for char in '*?:':
            for subject in (BRANCH+char,'repo:'+char+'/api:pull_request',
                            'repo:acme/'+char+':pull_request'):
                self.assertIsNone(parse_github_subject(subject))
                self.assertFalse(issuer_accepts({},dict(sub=subject,aud=AUD)))

    def test_uncommon_components_match_scalar_and_symbolic(self):
        for ch in ['é','雪','𐀀','\n','\x00','\ud800','\U0010ffff','\\','[']:
            for subject in (BRANCH+ch,'repo:'+ch+'/api:pull_request'):
                alph=github_alphabet_from_patterns(('equals',[subject,AUD]))
                self.assertTrue(issuer_subject_nfa([],alph).accepts(subject))
                self.assertTrue(issuer_accepts({},dict(sub=subject,aud=AUD)))
                self.assertIsNotNone(parse_github_subject(subject))

    def test_slash_depends_on_constructor_position(self):
        self.assertIsNotNone(parse_github_subject(BRANCH+'/'))
        self.assertIsNone(parse_github_subject('repo:ac/me/api:pull_request'))

    def test_parser_fullmatch_does_not_accept_valid_prefix_only(self):
        for subject in (BRANCH+'x:\n','repo:acme/api:pull_request\n'):
            self.assertIsNone(parse_github_subject(subject))


class CertificateDomainTests(unittest.TestCase):
    def test_all_four_atomic_builders_bind_domain(self):
        certs=[pair_certificate('p',['a*'],['a*']),
               pair_group_certificate('pg',[('equals',['a'])],['a']),
               triple_certificate('t',['?'],['a'],['a']),
               triple_group_certificate('tg',['?'],[('equals',['a'])],['a'])]
        for cert in certs:
            self.assertEqual(3,cert['version'])
            self.assertEqual(CHARACTER_DOMAIN,cert['character_domain'])
            self.assertTrue(verify_certificate(cert)[0])

    def test_plain_pattern_tuple_is_not_a_typed_group(self):
        for spelling in ('like', 'equals', 'literal', 'glob'):
            cert=pair_certificate('tuple',[spelling,'x'],['x'])
            tuple_cert=pair_certificate('tuple',(spelling,'x'),['x'])
            self.assertEqual('unsafe',tuple_cert['verdict'])
            self.assertEqual(cert,tuple_cert)
            self.assertTrue(verify_certificate(tuple_cert)[0])
            triple=triple_certificate('tuple',(spelling,'x'),('*',),('x',))
            self.assertEqual('unsafe',triple['verdict'])
            self.assertTrue(verify_certificate(triple)[0])

    def test_plain_intent_tuple_and_generation_guards(self):
        certs=[pair_certificate('p',['like'],('like','x')),
               triple_certificate('t',('like','x'),['like'],('like','x')),
               pair_group_certificate('pg',[('equals',['like'])],('like','x')),
               triple_group_certificate('tg',('like','x'),[('equals',['like'])],('like','x'))]
        for cert in certs:
            self.assertEqual('safe',cert['verdict'])
            self.assertTrue(verify_certificate(cert)[0])
        builders=[lambda:pair_certificate('p',['a*'],['a*']),
                  lambda:triple_certificate('t',['a*'],['a*'],['a*']),
                  lambda:pair_group_certificate('pg',[('like',['a*'])],['a*']),
                  lambda:triple_group_certificate('tg',['a*'],[('like',['a*'])],['a*'])]
        with patch('fedfence.regular.fresh_character',return_value=None):
            for build in builders:
                with self.assertRaisesRegex(ValueError,'incomplete certificate character support'):
                    build()

    def test_custom_base_is_preference_not_synthetic_pattern(self):
        cert=pair_certificate('hint',['a'],['a'],alphabet=('\n',))
        self.assertNotIn('\\',cert['alphabet'])
        self.assertTrue(verify_certificate(cert)[0])

    def test_trimmed_other_class_is_refused_even_for_true_judgment(self):
        cert=pair_certificate('same',['a*'],['a*'])
        cert['alphabet']='a'
        ok,note=verify_certificate(cert)
        self.assertFalse(ok);self.assertIn('OTHER',note)

    def test_missing_equality_literal_metacharacter_is_refused(self):
        cert=pair_group_certificate('literal',[('equals',['*'])],['*'])
        cert['alphabet']=cert['alphabet'].replace('*','')
        self.assertFalse(verify_certificate(cert)[0])

    def test_missing_typed_boundary_is_refused(self):
        cert=triple_group_certificate('typed',[],[('equals',[SUB])],[SUB],issuer_kind='github-default')
        self.assertTrue(verify_certificate(cert)[0])
        cert['alphabet']=cert['alphabet'].replace('?','')
        self.assertFalse(verify_certificate(cert)[0])

    def test_alphabet_duplicates_are_refused(self):
        cert=pair_certificate('same',['a'],['a']);cert['alphabet']+=cert['alphabet'][0]
        self.assertFalse(verify_certificate(cert)[0])

    def test_legacy_atomic_certificate_requires_regeneration(self):
        cert=pair_certificate('same',['a'],['a']);cert['version']=2
        cert.pop('character_domain')
        self.assertFalse(verify_certificate(cert)[0])

    def test_wrong_domain_is_refused(self):
        cert=pair_certificate('same',['a'],['a']);cert['character_domain']='ascii'
        self.assertFalse(verify_certificate(cert)[0])

    def test_invalid_verdict_is_not_interpreted_as_safe(self):
        cert=pair_certificate('same',['a'],['a']);cert['verdict']='unknown'
        self.assertFalse(verify_certificate(cert)[0])

    def test_unsupported_issuer_kind_is_refused(self):
        cert=triple_certificate('same',['a'],['a'],['a']);cert['issuer_kind']='arbitrary'
        self.assertFalse(verify_certificate(cert)[0])

    def test_malformed_alphabet_is_a_replay_failure(self):
        cert=pair_certificate('same',['a'],['a']);cert['alphabet']=['a']
        self.assertFalse(verify_certificate(cert)[0])

    def test_typed_group_aliases_preserve_literal_question(self):
        cert=pair_group_certificate('alias',[{'op':'literal','values':['?']}],['?'])
        self.assertTrue(verify_certificate(cert)[0])
        self.assertIn('?',cert['alphabet'])

    def test_unknown_group_operator_is_not_coerced(self):
        with self.assertRaises(ValueError):
            pair_group_certificate('bad',[{'op':'bogus','values':['?']}],['?'])

    def test_effective_certificate_domain_and_legacy_invalidation(self):
        cert=certificate_for_case(exhausted_case(closed=True))
        self.assertEqual(6,cert['version']);self.assertTrue(verify_certificate(cert)[0])
        cert['version']=5;self.assertFalse(verify_certificate(cert)[0])


class EndToEndDomainTests(unittest.TestCase):
    def test_analyzer_refuses_support_without_residual_class(self):
        with patch('fedfence.regular.fresh_character',return_value=None):
            with self.assertRaisesRegex(ValueError,'incomplete analysis character support'):
                analyze_case(exhausted_case())

    def test_effective_replay_generation_refuses_incomplete_support(self):
        with patch('fedfence.regular.fresh_character',return_value=None):
            with self.assertRaisesRegex(ValueError,'incomplete replay character support'):
                certificate_for_case(exhausted_case())

    def test_both_coordinates_detect_unlisted_character_and_have_passing_control(self):
        for coordinate in ('sub','aud'):
            for closed in (False,True):
                with self.subTest(coordinate=coordinate,closed=closed):
                    case=exhausted_case(coordinate,closed=closed)
                    result=analyze_case(case);cert=certificate_for_case(case)
                    self.assertEqual(closed,result.safe)
                    self.assertEqual('safe' if closed else 'unsafe',cert['verdict'])
                    self.assertTrue(verify_certificate(cert)[0])
                    if not closed:
                        field=coordinate+'ject-overgrant' if coordinate=='sub' else 'audience-overgrant'
                        self.assertTrue(any(f.kind==field for f in result.findings))

    def test_expanding_listed_characters_does_not_exhaust_other(self):
        for extras in ('!',''.join(chr(n) for n in range(128))):
            case=exhausted_case('aud',extra_literal=extras)
            self.assertFalse(analyze_case(case).safe)
            self.assertEqual('unsafe',certificate_for_case(case)['verdict'])

    def test_strict_gate_open_domain_is_fail_and_closed_control_passes(self):
        for closed in (False,True):
            result=review(exhausted_packet(closed=closed),now=NOW)
            self.assertEqual('pass' if closed else 'fail',result['verdict'])
            self.assertTrue(result['replay_ok'])
            self.assertTrue(result['required_token_checks']['all_satisfied'])

    def test_full_receipt_reruns_corrected_domain(self):
        p=exhausted_packet();result=review(p,now=NOW)
        replay=replay_receipt(make_receipt(p,result),now=NOW)
        self.assertEqual('fail',replay['verdict']);self.assertTrue(replay['receipt_replay_ok'])

    def test_changed_implementation_cannot_reuse_old_receipt(self):
        p=exhausted_packet(closed=True);receipt=make_receipt(p,review(p,now=NOW))
        receipt['decision']['input_hashes']['implementation']='0'*64
        receipt['receipt_sha256']=digest({k:v for k,v in receipt.items() if k!='receipt_sha256'})
        self.assertEqual('unknown',replay_receipt(receipt,now=NOW)['verdict'])

    def test_stale_exhausted_packet_remains_unknown(self):
        self.assertEqual('unknown',review(exhausted_packet(),now='2026-09-25T01:00:00Z')['verdict'])

    def test_utf8_transport_rejects_unpaired_surrogate_without_positive_verdict(self):
        p=exhausted_packet();p['snapshots']['policy']['body']['Id']='\ud800'
        result=review(p,now=NOW)
        self.assertEqual('unknown',result['verdict'])


if __name__=='__main__':
    unittest.main()
