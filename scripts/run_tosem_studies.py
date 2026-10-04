#!/usr/bin/env python3
"""Recompute source-backed evidence without conflating entry points or units."""
from __future__ import annotations
import csv, hashlib, json, sys
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from fse_workflow.io import load_json,save_json,digest
from fse_workflow.public_changes import analyze_change
from fse_workflow.normalized_study import decide,certificate,replay
OUT=ROOT/'tosem/results';OUT.mkdir(parents=True,exist_ok=True)

def source_validate(r):
    p=ROOT/r['source_snapshot']; raw=p.read_bytes(); assert hashlib.sha256(raw).hexdigest()==r['source_sha256']
    text=raw.decode(); assert all(s in text for vals in r['source_assertions'].values() for s in vals)
    return dict(path=r['source_snapshot'],sha256=r['source_sha256'],digest_verified=True,assertions_verified=True,source_authenticity_verified=False)

def public():
    corpus=load_json(ROOT/'study/public_change_corpus.json');corrections=load_json(ROOT/'study/corrections.json')
    rows=[]; sources=[]; role_transitions=[]
    for r in corpus['changes']:
        sources.append(dict(repository=r['repository'],commit=r['commit'],**source_validate(r)))
        if r['repository'] in [corrections['sports_store']['repository'],corrections['microticket']['repository']]:continue
        got=analyze_change(r); role_transitions.append(dict(id=r['id'],repository=r['repository'],role='source-selected-role',before=got['before']['verdict'],after=got['after']['verdict']))
        for phase in ['before','after']:
            rows.append(dict(id=r['id'],repository=r['repository'],role='source-selected-role',configuration=phase,entry_point='regular-language-study-adapter',result=got[phase],conditional_on=None))
    s=corrections['sports_store']
    for role in s['roles']:
        common={k:role[k] for k in ['explicit_issuer','intent','required']}; phase_results={}
        for phase in ['before','after']:
            p=dict(**common,allow=role[phase+'_allow']);r=decide(**p);c=certificate(p,r)
            assert digest(replay(c).to_json())==digest(r.to_json())
            phase_results[phase]=r.status
            rows.append(dict(id='sports-store-role-split',repository=s['repository'],role=role['role'],configuration=phase,entry_point='finite-explicit-issuer-study-adapter',result=dict(verdict=r.status,**r.to_json(),replay_ok=True),conditional_on='supplied seven-tuple issuer relation'))
        role_transitions.append(dict(id='sports-store-role-split',repository=s['repository'],role=role['role'],**phase_results))
    m=corrections['microticket'];phase_results={}
    for cfg in m['configurations']:
        p={k:m[k] for k in ['explicit_issuer','intent','required']};p['allow']=cfg['allow']
        r=decide(**p);assert r.status==cfg['expected'];assert replay(certificate(p,r)).status==r.status
        phase_results[cfg['name']]=r.status
        rows.append(dict(id='microticket-variable-branches',repository=m['repository'],role=m['role'],configuration=cfg['name'],entry_point='finite-explicit-issuer-study-adapter',result=dict(verdict=r.status,**r.to_json(),replay_ok=True),conditional_on=cfg.get('conditional_on')))
    role_transitions.append(dict(id='microticket-variable-branches',repository=m['repository'],role=m['role'],before=phase_results['before'],after=phase_results['after-observed-binding'],default_empty=phase_results['after-default-empty'],conditional_on='nonempty observed binding; assignment not established by supplied evidence'))
    assert len(rows)==21 and len(role_transitions)==10
    summary=dict(commits=len(sources),role_contracts=len(role_transitions),evaluations=len(rows),ordinary_role_phases=20,additional_variable_branch=1,verdicts=dict(Counter(r['result']['verdict'] for r in rows)),entry_points=dict(Counter(r['entry_point'] for r in rows)),verified_patch_digests=len(sources),safety_or_full_study_replay_checks=sum(r['result']['replay_ok'] for r in rows),source_authenticity_verified=False,owner_confirmed=False,independent_accuracy_measure=False,cloud_validation=False)
    save_json(OUT/'public_study.json',dict(schema='fedfence-tosem-public-study-v1',summary=summary,role_transitions=role_transitions,rows=rows,sources=sources))
    fields=['id','repository','role','configuration','entry_point','verdict','conditional_on']
    with (OUT/'public_study.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields);w.writeheader()
        for r in rows:w.writerow({**{k:r[k] for k in fields if k!='verdict'},'verdict':r['result']['verdict']})
    return summary

def frontier():
    m=load_json(ROOT/'study/source_frontier_sample.json');rows=[]
    for r in m['records']:
        assert hashlib.sha256(r['excerpt'].encode()).hexdigest()==r['excerpt_sha256']
        candidates=[]
        if r.get('source_snapshot'):candidates=[ROOT/'study'/r['source_snapshot'],ROOT/r['source_snapshot']]
        full=next((p for p in candidates if p.is_file()),None)
        rows.append(dict(repository=r['repository'],commit=r['commit'],path=r['path'],excerpt_sha256=r['excerpt_sha256'],excerpt_verified=True,full_source_available=full is not None,original_annotation=r['primary_frontier_class'],extraction_result='not-executed',audience_annotation=r['audience_constraint']))
    annotations=Counter(r['original_annotation'] for r in rows)
    summary=dict(records=len(rows),verified_excerpts=len(rows),full_source_files=sum(r['full_source_available'] for r in rows),annotation_counts=dict(annotations),annotation_literal_or_foldable=sum(r['original_annotation'] in ['literal_source_policy','constant_foldable_hcl'] for r in rows),executed_extractions=0,extraction_accuracy_estimated=False)
    save_json(OUT/'source_frontier.json',dict(schema='fedfence-tosem-frontier-v1',summary=summary,rows=rows,interpretation='Inherited excerpt annotations, not outcomes of a full-source extractor. Missing files are unavailable, not demonstrated non-normalizable.'))
    return summary

def runtime():
    m=load_json(ROOT/'study/runtime_compatibility_corpus.json');rows=[]
    for r in m['records']:
        body=dict(r);wanted=body.pop('record_sha256');actual=hashlib.sha256(json.dumps(body,sort_keys=True,separators=(',',':')).encode()).hexdigest();assert actual==wanted
        rows.append(dict(**r,record_digest_verified=True,live_run_replayed=False,variable_assignment_verified=False))
    summary=dict(records=len(rows),verified_record_digests=len(rows),reports_annotated_breakage=sum('hardening' not in r['observation'].lower() for r in rows),records_with_success_run_id=sum(bool(r['public_success_run']) for r in rows),live_workflows_run=0,independent_root_cause_adjudication=False)
    save_json(OUT/'maintenance_metadata.json',dict(schema='fedfence-tosem-maintenance-v1',summary=summary,rows=rows,interpretation='Counts of supplied metadata and reported observations, not refreshed public API results.'))
    return summary

if __name__=='__main__':
    result=dict(public=public(),frontier=frontier(),maintenance=runtime());save_json(OUT/'studies_summary.json',result);print(json.dumps(result,indent=2))
