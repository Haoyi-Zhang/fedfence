#!/usr/bin/env python3
"""Offline benign differential checks and local recomputation measurements.

No cloud/network calls. This is bounded implementation evidence, not provider
validation, a representative performance benchmark, or an incident survey.
"""
from __future__ import annotations
import copy, csv, hashlib, itertools, json, platform, statistics, sys, time
from collections import Counter
from functools import lru_cache
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'artifact')]
from fedfence.regular import glob, union_globs
from fedfence.github import issuer_subject_nfa
from fse_workflow.conformance import _glob_matches, issuer_accepts
from fse_workflow.contract import contract_digest
from fse_workflow.fragment import PREFIX
from fse_workflow.gate import review, implementation_digest
from fse_workflow.io import digest, save_json
from fse_workflow.receipt import make_receipt, replay_receipt
from scripts.make_workflow_examples import packet, rehash
OUT=ROOT/'tosem/results'
NOW='2026-09-23T01:00:00Z'; SUB='repo:acme/api:ref:refs/heads/'; AUD='sts.amazonaws.com'

def oracle_match(pattern: str,word: str)->bool:
    """Independent recursive split enumeration; no regex, NFA, or DP row."""
    @lru_cache(None)
    def visit(i:int,j:int)->bool:
        if i==len(pattern): return j==len(word)
        if pattern[i]=='*': return any(visit(i+1,k) for k in range(j,len(word)+1))
        return j<len(word) and (pattern[i]=='?' or pattern[i]==word[j]) and visit(i+1,j+1)
    return visit(0,0)

def words(alphabet:tuple[str,...],bound:int)->list[str]:
    return [''.join(x) for n in range(bound+1) for x in itertools.product(alphabet,repeat=n)]

def matcher_audit()->dict:
    patterns=words(('a','b','*','?','[',']'),4); values=words(('a','b','[',']','\n'),3)
    alphabet=tuple(sorted(set('ab*?[]\n')));stream=hashlib.sha256()
    count=matches=0;examples=[];start=time.perf_counter()
    for pattern in patterns:
        nfa=glob(pattern,alphabet)
        for value in values:
            want=oracle_match(pattern,value);scalar=_glob_matches(pattern,value);core=nfa.accepts(value)
            if not want==scalar==core: raise AssertionError((pattern,value,want,scalar,core))
            row=[pattern,value,want,scalar,core]
            stream.update((json.dumps(row,ensure_ascii=True,separators=(',',':'))+'\n').encode())
            if count%10007==0: examples.append(row)
            count+=1;matches+=int(want)
    result=dict(schema='fedfence-bounded-matcher-audit-v1',passed=True,
        pattern_alphabet=['a','b','*','?','[',']'],pattern_max_length=4,
        value_alphabet=['a','b','[',']','\n'],value_max_length=3,
        patterns=len(patterns),values=len(values),checked=count,matching_pairs=matches,
        nonmatching_pairs=count-matches,
        implementations=['recursive split oracle','positive prefix DP','retained core NFA'],
        result_stream_sha256=stream.hexdigest(),sample_rows=examples,
        elapsed_seconds=time.perf_counter()-start,
        scope='Exhaustive for declared finite alphabets/lengths only; not all-string equivalence.')
    save_json(OUT/'matcher_differential.json',result);return result

def issuer_audit()->dict:
    subjects=[SUB+'main',SUB+'dev',SUB+'feature/test',
        'repo:acme/api:ref:refs/tags/v1','repo:acme/api:environment:prod',
        'repo:acme/api:pull_request','repo:acme/api:ref:refs/heads/',
        SUB+'with:colon',SUB+'*',SUB+'?', 'repository_id:123:environment:prod',
        'repo:acme/other:ref:refs/heads/main']
    audiences=['',AUD,'vault','audit']
    subject_options=[None,[],['*'],[SUB+'main'],[SUB+'dev'],['repo:acme/api:*'],['repository_id:*'],['']]
    audience_options=[None,[],['?*'],[AUD],['vault'],['']]
    alphabet=tuple(sorted(set(''.join(subjects+audiences+['*?repository_id:']))))
    count=accepted=0; stream=hashlib.sha256()
    for so in subject_options:
      snfa=issuer_subject_nfa(so,alphabet)
      for ao in audience_options:
        anfa=union_globs(ao or ['?*'],alphabet)
        spec={'issuer_subjects':so,'issuer_audiences':ao}
        for sub,aud in itertools.product(subjects,audiences):
            core=snfa.accepts(sub) and anfa.accepts(aud)
            scalar=issuer_accepts(spec,dict(sub=sub,aud=aud))
            if core!=scalar:raise AssertionError((spec,sub,aud,core,scalar))
            stream.update((json.dumps([so,ao,sub,aud,core,scalar],separators=(',',':'))+'\n').encode())
            count+=1; accepted+=int(core)
    result=dict(schema='fedfence-issuer-membership-audit-v1',passed=True,checked=count,
        subjects=subjects,audiences=audiences,subject_refinements=subject_options,
        audience_refinements=audience_options,accepted=accepted,rejected=count-accepted,
        result_stream_sha256=stream.hexdigest(),
        scope='Bounded agreement with the retained typed constructor/refinement NFAs, not live issuer behavior.')
    save_json(OUT/'issuer_membership_differential.json',result);return result

def literal_statement(proto:dict,effect:str,subjects:list[str],audiences:list[str])->dict:
    st=copy.deepcopy(proto);st['Effect']=effect
    st['Condition']={'StringEquals':{PREFIX+'sub':subjects,PREFIX+'aud':audiences}}
    return st

def strict_glob_audit()->dict:
    subject_globs=['*',SUB+'main',SUB+'m*',SUB+'?ain',SUB+'[md]ain','',SUB+'**',SUB+'releas?']
    audience_globs=['*',AUD,'?ault','[sv]*']
    subjects=[SUB+x for x in ('main','dev','release')];audiences=[AUD,'vault']
    universe=list(itertools.product(subjects,audiences));intended={(SUB+'main',AUD),(SUB+'release',AUD)}
    base=packet();base['contract']['intent']['branches']=['main','release']
    proto=base['snapshots']['policy']['body']['Statement'][0];rows=[];start=time.perf_counter()
    fixture_dir=OUT/'bounded_glob_packets';fixture_dir.mkdir(parents=True,exist_ok=True)
    # Every Allow has finite equality bounds; the oracle covers all admissions
    # for each generated policy, not merely sampled witnesses of arbitrary globs.
    for si,sp in enumerate(subject_globs):
      for ai,ap in enumerate(audience_globs):
       for deny_mode in ('none','main-sts','dev-any'):
        for require in (False,True):
            p=copy.deepcopy(base);Q={(SUB+'main',AUD)} if require else set()
            p['contract']['required_tokens']=[dict(sub=s,aud=a,reason='benign required release identity') for s,a in sorted(Q)]
            p['contract']['review']['approved_digest']=contract_digest(p['contract'])
            bounded=literal_statement(proto,'Allow',subjects,audiences)
            bounded['Condition']['StringLike']={PREFIX+'sub':sp,PREFIX+'aud':ap};statements=[bounded]
            include_release=(si+ai)%2==1
            if include_release:statements.append(literal_statement(proto,'Allow',[SUB+'release'],[AUD]))
            if deny_mode!='none':
                ds=[SUB+'main'] if deny_mode=='main-sts' else [SUB+'dev']
                da=[AUD] if deny_mode=='main-sts' else audiences
                statements.append(literal_statement(proto,'Deny',ds,da))
            p['snapshots']['policy']['body']['Statement']=statements;rehash(p,'policy')
            A={t for t in universe if oracle_match(sp,t[0]) and oracle_match(ap,t[1])}
            if include_release:A.add((SUB+'release',AUD))
            D=set() if deny_mode=='none' else ({(SUB+'main',AUD)} if deny_mode=='main-sts' else {(SUB+'dev',a) for a in audiences})
            accepted=A-D;expected='fail' if accepted-intended or Q-accepted else 'pass'
            got=review(p,now=NOW,timeout=30.0)
            if got['verdict']!=expected or not got['replay_ok']:
                raise AssertionError((si,ai,deny_mode,require,expected,got))
            checks=got['required_token_checks']
            if checks['required']!=len(Q) or checks['satisfied']!=len(Q&accepted) or checks['invalid']:
                raise AssertionError(('positive disagreement',p,got))
            number=len(rows);fn=f'case-{number:03}.json';save_json(fixture_dir/fn,p)
            rows.append(dict(case=number,subject_pattern=sp,audience_pattern=ap,deny_mode=deny_mode,
                extra_release_allow=include_release,required_count=len(Q),expected=expected,verdict=got['verdict'],
                replay_ok=got['replay_ok'],accepted_count=len(accepted),missing_required=len(Q-accepted),
                overgrant_count=len(accepted-intended),packet_file='bounded_glob_packets/'+fn,packet_sha256=digest(p)))
    with (OUT/'strict_glob_differential.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
    result=dict(schema='fedfence-strict-bounded-glob-v1',passed=True,checked=len(rows),
        subject_patterns=subject_globs,audience_patterns=audience_globs,deny_modes=3,required_settings=2,
        verdicts=dict(Counter(r['verdict'] for r in rows)),universe=[list(t) for t in universe],
        intent=[list(t) for t in sorted(intended)],
        complete_policy_bound='Each Allow intersects finite StringEquals subject/audience bounds; no other Allow exists.',
        independent_oracle='Recursive glob matching and direct tuple set Allow-minus-Deny.',
        csv_sha256=hashlib.sha256((OUT/'strict_glob_differential.csv').read_bytes()).hexdigest(),
        elapsed_seconds=time.perf_counter()-start,
        scope='Benign generated fixtures; no real account, provider equivalence, or population inference.')
    save_json(OUT/'strict_glob_differential.json',result);return result

def scaling()->dict:
    rows=[];sizes=[1,2,4,8,16,32]
    for n in sizes:
        p=packet();names=[f'branch{i:02}' for i in range(n)];subjects=[SUB+x for x in names]
        p['contract']['intent']['branches']=names
        p['contract']['required_tokens']=[dict(sub=s,aud=AUD,reason='benign scaling identity') for s in subjects]
        p['contract']['review']['approved_digest']=contract_digest(p['contract'])
        proto=p['snapshots']['policy']['body']['Statement'][0]
        p['snapshots']['policy']['body']['Statement']=[literal_statement(proto,'Allow',subjects,[AUD])];rehash(p,'policy')
        loss=copy.deepcopy(p)
        loss['snapshots']['policy']['body']['Statement'].append(literal_statement(proto,'Deny',[subjects[0]],[AUD]));rehash(loss,'policy')
        baseline=review(p,now=NOW,timeout=60.0)
        assert baseline['verdict']=='pass' and baseline['replay_ok']
        receipt=make_receipt(p,baseline)
        assert review(loss,now=NOW,timeout=60.0)['verdict']=='fail'
        assert replay_receipt(receipt,now=NOW,timeout=60.0)['receipt_replay_ok']
        tasks=[('review-pass',p),('review-positive-loss',loss),('receipt-replay',receipt)]
        for repetition in range(3):
            for task,obj in tasks[repetition:]+tasks[:repetition]:
                start=time.perf_counter()
                result=replay_receipt(obj,now=NOW,timeout=60.0) if task=='receipt-replay' else review(obj,now=NOW,timeout=60.0)
                duration=time.perf_counter()-start;want='fail' if task=='review-positive-loss' else 'pass'
                assert result['verdict']==want
                assert (result['receipt_replay_ok'] if task=='receipt-replay' else result['replay_ok'])
                rows.append(dict(required_tokens=n,task=task,repetition=repetition,seconds=duration,expected=want,verdict=result['verdict']))
    with (OUT/'local_scaling.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
    summary=[]
    for n in sizes:
      for task in ('review-pass','review-positive-loss','receipt-replay'):
        vs=[r['seconds'] for r in rows if r['required_tokens']==n and r['task']==task]
        summary.append(dict(required_tokens=n,task=task,repetitions=len(vs),median_seconds=statistics.median(vs),min_seconds=min(vs),max_seconds=max(vs)))
    result=dict(schema='fedfence-local-scaling-v1',passed=True,sizes=sizes,repetitions=3,recorded_runs=len(rows),
        warmup_runs=len(sizes)*3,summary=summary,environment=dict(python=sys.version,platform=platform.platform()),
        csv_sha256=hashlib.sha256((OUT/'local_scaling.csv').read_bytes()).hexdigest(),
        scope='Single local interpreter/process environment, subprocess startup included; descriptive medians and observed ranges, not confidence intervals or tool comparisons.')
    save_json(OUT/'local_scaling.json',result);return result

def main()->int:
    OUT.mkdir(parents=True,exist_ok=True);results={}
    for name,run in [('matcher',matcher_audit),('issuer',issuer_audit),('strict_glob',strict_glob_audit),('scaling',scaling)]:
        results[name]=run();print(name,'passed',flush=True)
    save_json(OUT/'final_validation_summary.json',dict(schema='fedfence-final-validation-v1',passed=True,
        implementation_sha256=implementation_digest(),network_access=False,cloud_accounts_used=False,results=results))
    return 0
if __name__=='__main__':raise SystemExit(main())
