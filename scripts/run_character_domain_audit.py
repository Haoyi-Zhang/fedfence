#!/usr/bin/env python3
"""Offline character-partition audit and benign integration checks.

The full-code-point sweep checks primitive predicate signatures, NOT every
string, policy, or cloud issuer. Independent recursive/scalar oracles never call
alphabet_from_patterns. All inputs are constructed locally.
"""
from __future__ import annotations
import copy
import hashlib
import itertools
import json
from functools import lru_cache
from pathlib import Path
import sys
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT/'artifact')]
from fedfence.regular import (CHARACTER_DOMAIN,CODEPOINT_LIMIT,DEFAULT_ALPHABET,
    alphabet_from_patterns,validate_support,glob,literal)
from fedfence.github import github_alphabet_from_patterns,issuer_subject_nfa
from fedfence.analyzer import analyze_case
from fedfence.certificate import certificate_for_case,verify_certificate,pair_certificate
from fse_workflow.conformance import _glob_matches,issuer_accepts,effective_policy_accepts,intent_accepts
from fse_workflow.gate import implementation_digest,review
from fse_workflow.io import save_json,digest
from fse_workflow.receipt import make_receipt,replay_receipt
from scripts.character_domain_fixtures import SUB,AUD,BRANCH,NOW,exhausted_case,exhausted_packet
OUT = ROOT/'tosem/results'
# Deliberately spelled out independently of the production collector/helper.
CONSTRUCTOR_SINGLETONS = set('repo:/ref:refs/heads/tags/pull_request:environment:*?')


def require(ok, detail):
    if not ok:
        raise AssertionError(detail)


def recursive_match(pattern,word):
    @lru_cache(None)
    def run(i,j):
        if i==len(pattern):return j==len(word)
        if pattern[i]=='*':return any(run(i+1,k) for k in range(j,len(word)+1))
        return j<len(word) and (pattern[i]=='?' or pattern[i]==word[j]) and run(i+1,j+1)
    return run(0,0)


def words(alphabet,bound):
    return [''.join(t) for n in range(bound+1) for t in itertools.product(alphabet,repeat=n)]


def partition_sweeps():
    rows=[]
    for name,pool in [('preference-pool',set(DEFAULT_ALPHABET)),
                      ('ascii',set(map(chr,range(128)))),
                      ('bmp',set(map(chr,range(0x10000))))]:
        # No test word is added to the support. The remainder is truly needed.
        literals=pool|CONSTRUCTOR_SINGLETONS
        support=github_alphabet_from_patterns(('equals',[''.join(sorted(pool))]))
        others=set(support)-literals
        require(literals.issubset(support) and len(others)==1,(name,'coverage'))
        representative=next(iter(others))
        require(validate_support(support,('equals',[''.join(literals)]))[0],name)
        stream=hashlib.sha256()
        for cp in range(CODEPOINT_LIMIT):
            char=chr(cp)
            projected=char if char in literals else representative
            # Singleton equality, owner/repository predicate, suffix predicate.
            actual=(char if char in literals else None,char not in '/:*?',char not in ':*?')
            reduced=(projected if projected in literals else None,
                     projected not in '/:*?',projected not in ':*?')
            require(actual==reduced,(name,cp,ord(projected)))
            stream.update(bytes((char in literals,actual[1],actual[2])))
        rows.append(dict(pool=name,pool_size=len(pool),literal_classes=len(literals),
            support_size=len(support),other_representative_codepoint=ord(representative),
            checked_codepoints=CODEPOINT_LIMIT,result_stream_sha256=stream.hexdigest(),passed=True))
    return dict(passed=True,partitions=len(rows),codepoints_per_partition=CODEPOINT_LIMIT,
                primitive_signature_comparisons=sum(r['checked_codepoints'] for r in rows),rows=rows,
                scope='Complete code-point enumeration of singleton and constructor predicate signatures for three declared supports; not enumeration of strings or policies.')


def quotient_matcher():
    pats=words(('a','*','?','[','é','𐀀'),3)
    vals=words(('a','é','雪','𐀀','\U0010ffff','*','?','[','\n','\ud800'),2)
    pool=set(DEFAULT_ALPHABET)
    stream=hashlib.sha256();count=matches=0; sample=[]
    for op in ('equals','like'):
        for p in pats:
            literals=pool|set(p if op=='equals' else p.replace('*','').replace('?',''))
            support=alphabet_from_patterns((op,[p]),('equals',sorted(pool)))
            reps=set(support)-literals
            require(len(reps)==1,'missing residual class')
            other=next(iter(reps))
            nfa=literal(p,support) if op=='equals' else glob(p,support)
            for w in vals:
                expected=p==w if op=='equals' else recursive_match(p,w)
                scalar=p==w if op=='equals' else _glob_matches(p,w)
                projected=''.join(ch if ch in literals else other for ch in w)
                symbolic=nfa.accepts(projected)
                require(expected==scalar==symbolic,(op,repr(p),repr(w),expected,scalar,symbolic))
                row=[op,p,w,projected,expected]
                stream.update((json.dumps(row,ensure_ascii=True,separators=(',',':'))+'\n').encode())
                if count%5003==0: sample.append(row)
                matches+=int(expected);count+=1
    return dict(passed=True,checked=count,operators=2,patterns=len(pats),words=len(vals),
        matching=matches,nonmatching=count-matches,result_stream_sha256=stream.hexdigest(),
        sample_rows=sample,pattern_alphabet=['a','*','?','[','é','𐀀'],pattern_max_length=3,
        word_alphabet=['a','é','雪','𐀀','\U0010ffff','*','?','[','\n','\ud800'],word_max_length=2,
        support_padding='all preferred characters as equality literals; concrete words are NOT added',
        scope='Bounded strings; recursive concrete oracle and scalar matcher vs representative-word NFA, including literal metacharacters and supplementary code points.')


def constructor_bridge():
    chars=['!','*','?',':','/','é','雪','𐀀','\U0010ffff','\n','\x00','\ud800']
    templates=['repo:{}/api:pull_request','repo:acme/{}:pull_request',BRANCH+'{}',
               'repo:acme/api:ref:refs/tags/{}','repo:acme/api:environment:{}']
    # Shared syntax is included; inserted characters are not included as literals.
    base_literals=CONSTRUCTOR_SINGLETONS|set(SUB+AUD)
    support=github_alphabet_from_patterns(('equals',[SUB,AUD]))
    other=next(iter(set(support)-base_literals))
    nfa=issuer_subject_nfa([],support);count=0; stream=hashlib.sha256()
    for template,char in itertools.product(templates,chars):
        subject=template.format(char)
        concrete=issuer_accepts({},dict(sub=subject,aud=AUD))
        projected=''.join(c if c in base_literals else other for c in subject)
        symbolic=nfa.accepts(projected)
        require(concrete==symbolic,repr(subject))
        stream.update(json.dumps([subject,concrete,symbolic],ensure_ascii=True).encode());count+=1
    return dict(passed=True,checked=count,positions=len(templates),characters=len(chars),
                result_stream_sha256=stream.hexdigest(),scope='Scalar typed-constructor membership vs quotient NFA at five insertion positions; abstract model only.')


def integrations():
    rows=[]
    for coord in ('sub','aud'):
        for closed in (False,True):
            case=exhausted_case(coord,closed=closed)
            result=analyze_case(case);cert=certificate_for_case(case)
            require(result.safe==closed and verify_certificate(cert)[0],(coord,closed))
            direct=None
            if not closed:
                # This oracle witness is chosen without inspecting the NFA result.
                for ch in ('!','雪','𐀀'):
                    token=dict(sub=BRANCH+ch if coord=='sub' else SUB,
                               aud=ch if coord=='aud' else AUD)
                    if (issuer_accepts(case['spec'],token) and
                            effective_policy_accepts(case['policy'],token) and
                            not intent_accepts(case['spec'],token)):
                        direct=token;break
                require(direct is not None,'no independent concrete obligation')
            rows.append(dict(coordinate=coord,closed_control=closed,expected_safe=closed,
                             actual_safe=result.safe,replay_ok=True,independent_concrete_violation=direct))
    gate_rows=[]
    for closed,stamp,expected in [(False,NOW,'fail'),(True,NOW,'pass'),
                                   (False,'2026-09-25T01:00:00Z','unknown')]:
        p=exhausted_packet(closed=closed);got=review(p,now=stamp)
        require(got['verdict']==expected,(closed,stamp,got))
        replay=replay_receipt(make_receipt(p,got),now=stamp)
        require(replay['receipt_replay_ok'] and replay['verdict']==expected,'full receipt')
        gate_rows.append(dict(closed_control=closed,clock=stamp,expected=expected,
                             verdict=got['verdict'],receipt_replay_ok=True))
    return dict(passed=True,regular_cases=len(rows),strict_packets=len(gate_rows),
                rows=rows,strict_rows=gate_rows,scope='Locally constructed positive/negative/stale review inputs; no provider-issued token or deployment.')


def independent_rejection_challenges():
    literals=set(DEFAULT_ALPHABET)
    control=alphabet_from_patterns(('equals',sorted(literals)))
    require(validate_support(control,('equals',sorted(literals)))[0],'selector control')
    with patch('fedfence.regular.fresh_character',return_value=None):
        omitted=alphabet_from_patterns(('equals',sorted(literals)))
    selector_detected=not validate_support(omitted,('equals',sorted(literals)))[0]
    cert=pair_certificate('benign same-language control',['a*'],['a*'])
    require(verify_certificate(cert)[0],'certificate control')
    incomplete=copy.deepcopy(cert);incomplete['alphabet']='a'
    verifier_rejects=not verify_certificate(incomplete)[0]
    with patch('fedfence.certificate.validate_support',return_value=(True,'injected bypass')):
        bypass_survives=verify_certificate(incomplete)[0]
    require(selector_detected and verifier_rejects and bypass_survives,'rejection sensitivity')
    return dict(passed=True,challenges=2,rows=[
        dict(fault='omit required residual class',control_passed=True,detected=selector_detected,
             detector='independent support cardinality check'),
        dict(fault='bypass certificate support check',control_passed=True,detected=verifier_rejects and bypass_survives,
             detector='incomplete-domain certificate rejection obligation')],
        scope='Two hand-selected benign local fault injections, not mutation-adequacy or bug-rate evidence.')


def safe_json(path,value):
    # Unpaired surrogates are legal Python-str test values, not UTF-8 packet input.
    # Escape them in audit JSON instead of changing the strict packet serializer.
    path.parent.mkdir(exist_ok=True,parents=True)
    path.write_text(json.dumps(value,ensure_ascii=True,sort_keys=True,indent=2)+'\n',encoding='utf-8')


def main():
    result=dict(schema='fedfence-character-domain-audit-v1',passed=True,
                character_domain=CHARACTER_DOMAIN,implementation_sha256=implementation_digest(),
                network_access=False,cloud_accounts_used=False,
                partition=partition_sweeps(),matcher=quotient_matcher(),
                constructor=constructor_bridge(),integration=integrations(),
                rejection=independent_rejection_challenges())
    safe_json(OUT/'character_domain_audit.json',result)
    # A small generated table; all figures still have their prior raw sources.
    rows=[]
    for r in result['partition']['rows']:
        label={'preference-pool':'Preferred pool','ascii':'ASCII','bmp':'Basic multilingual plane'}[r['pool']]
        rows.append(f"{label} & {r['literal_classes']:,} & {r['support_size']:,} & U+{r['other_representative_codepoint']:04X} \\\\")
    table = (r"\begin{tabularx}{\linewidth}{@{}Xrrl@{}}" + "\n" +
             r"\toprule" + "\n" +
             r"Saturated input & Singletons $|S|$ & Support $|A|$ & Residual representative \\" + "\n" +
             r"\midrule" + "\n" + '\n'.join(rows) + "\n" +
             r"\bottomrule" + "\n" + r"\end{tabularx}" + "\n")
    (ROOT.parent/'paper/generated/character_domain_rows.tex').write_text(table)
    print(json.dumps(dict(passed=True,codepoint_predicate_comparisons=result['partition']['primitive_signature_comparisons'],
        quotient_matcher_comparisons=result['matcher']['checked'],constructor_comparisons=result['constructor']['checked'],
        regular_cases=result['integration']['regular_cases'],strict_packets=result['integration']['strict_packets'])))
    return 0
if __name__=='__main__':raise SystemExit(main())
