#!/usr/bin/env python3
"""Offline, benign consistency experiments; no network, cloud or external oracle."""
from __future__ import annotations
import copy, csv, itertools, json, platform, sys, time
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT))
from fse_workflow.io import save_json, digest
from fse_workflow.normalized_study import decide, certificate, replay
from fse_workflow.gate import review, implementation_digest
from fse_workflow.fragment import PREFIX
from fse_workflow.contract import contract_digest
from scripts.make_workflow_examples import packet, rehash
OUT=ROOT/'tosem/results'; OUT.mkdir(parents=True,exist_ok=True)
NOW='2026-09-23T01:00:00Z'

def subsets(xs):
    return [{x for i,x in enumerate(xs) if mask>>i&1} for mask in range(1<<len(xs))]

def finite():
    atoms=[('repo:fixture/app:ref:refs/heads/'+s,'sts.amazonaws.com') for s in ['main','dev','test']]
    sets=subsets(atoms); counts=Counter(); n=0; samples=[]; started=time.perf_counter()
    for G,I,A,D,Q in itertools.product(sets,repeat=5):
        admitted=G & (A-D); inconsistent=not Q.issubset(G&I)
        for invalid in (False,True):
            expected='unknown' if invalid or inconsistent else 'fail' if admitted-I or Q-admitted else 'pass'
            p=dict(explicit_issuer=sorted(G),allow=sorted(A),deny=sorted(D),intent=sorted(I),required=sorted(Q),invalid=['synthetic-invalid-premise'] if invalid else [])
            r=decide(**p); assert r.status==expected,(p,r,expected)
            assert set(r.admitted)==admitted,(p,r,admitted)
            if n%257==0:
                rr=replay(certificate(p,r)); assert digest(rr.to_json())==digest(r.to_json())
                samples.append(dict(index=n,packet=p,result=r.to_json()))
            counts[r.status]+=1; n+=1
    obj=dict(schema='fedfence-tosem-exhaustive-v1',atoms=atoms,relation_combinations=8**5,validity_settings=2,checked=n,verdicts=dict(counts),replay_samples=len(samples),passed=True,elapsed_seconds=time.perf_counter()-started,oracle='direct Python set operations; no cloud or formal refinement proof')
    save_json(OUT/'two_sided_exhaustive.json',obj); save_json(OUT/'two_sided_samples.json',samples); return obj

def strict():
    # Literal policies have exactly these possible accepted tuples. The issuer
    # grammar is unbounded, but no policy glob in this experiment can admit more.
    atoms=[('repo:acme/api:ref:refs/heads/'+s,a) for s in ['main','dev'] for a in ['sts.amazonaws.com','fixture-audience']][:3]
    sets=subsets(atoms); intended={atoms[0]}; required={atoms[0]}; base=packet()
    base['contract']['required_tokens']=[dict(sub=atoms[0][0],aud=atoms[0][1],reason='synthetic main deployment')]
    base['contract']['review']['approved_digest']=contract_digest(base['contract'])
    proto=base['snapshots']['policy']['body']['Statement'][0]; rows=[]; t0=time.perf_counter()
    for ai,A in enumerate(sets[1:],1):
        for di,D in enumerate(sets):
            p=copy.deepcopy(base); statements=[]
            for effect,tokens in [('Allow',A),('Deny',D)]:
                for s,a in sorted(tokens):
                    st=copy.deepcopy(proto); st['Effect']=effect
                    st['Condition']={'StringEquals':{PREFIX+'sub':s,PREFIX+'aud':a}}
                    statements.append(st)
            p['snapshots']['policy']['body']['Statement']=statements; rehash(p,'policy')
            effective=A-D
            expected='fail' if effective-intended or required-effective else 'pass'
            start=time.perf_counter(); r=review(p,now=NOW); elapsed=time.perf_counter()-start
            assert r['verdict']==expected,(ai,di,expected,r)
            assert r['replay_ok'],(ai,di,r)
            rows.append(dict(allow_mask=ai,deny_mask=di,statements=len(statements),verdict=r['verdict'],expected=expected,replay_ok=r['replay_ok'],seconds=elapsed))
            save_json(OUT/'strict_progress.json',dict(completed=len(rows),last=rows[-1]))
    with (OUT/'strict_literal_differential.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    obj=dict(schema='fedfence-tosem-strict-differential-v1',checked=len(rows),passed=True,verdicts=dict(Counter(r['verdict'] for r in rows)),total_seconds=time.perf_counter()-t0,oracle='direct finite tuple sets for literal policies; independently written expected outcome, shared Python runtime',scope='7 nonempty Allow subsets times 8 Deny subsets over three benign tuples; no issuer/backend completeness claim')
    save_json(OUT/'strict_literal_differential.json',obj); return obj

def metamorphic():
    base=packet(); exact=review(base,now=NOW); rows=[]
    def probe(name,p,expected,changed):
        r=review(p,now=NOW,previous=exact)
        assert r['verdict']==expected,(name,r)
        assert set(r['changed_fields'])==set(changed),(name,r['changed_fields'],changed)
        rows.append(dict(name=name,verdict=r['verdict'],changed_fields=r['changed_fields']))
    probe('unchanged-fresh-packet',copy.deepcopy(base),'pass',[])
    p=copy.deepcopy(base); p['snapshots']['workflow']['body']['revision']='synthetic-revision-B'; rehash(p,'workflow'); probe('workflow-byte-change',p,'pass',['workflow'])
    p=copy.deepcopy(base); p['snapshots']['issuer']['source']='synthetic-alternate-source'; probe('issuer-source-metadata-change',p,'pass',['issuer'])
    p=copy.deepcopy(base); st=p['snapshots']['policy']['body']['Statement'][0]; st['Condition']['StringEquals'].pop(PREFIX+'sub');st['Condition']['StringLike']={PREFIX+'sub':'repo:acme/api:*'};rehash(p,'policy');probe('subject-widening',p,'fail',['policy'])
    # A stale packet fails before dependency hashes are computed; report that
    # honestly rather than asserting a complete dependency diff for invalid input.
    p=copy.deepcopy(base);p['snapshots']['governance']['observed_at']='2026-09-20T00:00:00Z';probe('stale-governance',p,'unknown',[])
    p=copy.deepcopy(base);p['contract']['intent']['branches'].append('release');p['contract']['review']['approved_digest']=contract_digest(p['contract']);probe('reviewed-intent-expansion',p,'pass',['contract'])
    obj=dict(schema='fedfence-tosem-dependency-metamorphic-v1',rows=rows,passed=True,checked=len(rows),interpretation='workflow content invalidates dependencies but is not executed or semantically interpreted')
    save_json(OUT/'dependency_metamorphic.json',obj); return obj

if __name__=='__main__':
    summary=dict(finite=finite(),strict=strict(),metamorphic=metamorphic(),environment=dict(python=sys.version,platform=platform.platform(),processor=platform.processor(),implementation_sha256=implementation_digest()),network_access=False,cloud_accounts_used=False)
    save_json(OUT/'validation_summary.json',summary)
    print(json.dumps({k:v for k,v in summary.items() if k!='environment'},indent=2))
