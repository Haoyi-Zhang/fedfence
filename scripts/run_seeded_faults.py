#!/usr/bin/env python3
"""Eight hand-selected benign semantic fault challenges in temporary copies.
Not a representative mutation score or an external effectiveness benchmark.
"""
from __future__ import annotations
import os, shutil, subprocess, sys, tempfile, hashlib, re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from fse_workflow.io import save_json
BASE='test_tosem_consistency.TOSEMConsistencyTests.'
FAULTS=[
 ('ignore-invalid-priority','decision.py','if invalid:return', 'if False:return',BASE+'test_gate_invalid_dominates_overgrant'),
 ('omit-positive-loss','decision.py','if overgrant or missing_required:return','if overgrant:return','test_gate_decision_precedence.DecisionPrecedenceTest.test_only_missing'),
 ('skip-expiration','contract.py','if age < 0 or age > contract["max_snapshot_age_seconds"]:', 'if age < 0:',BASE+'test_snapshot_age_exact_boundary'),
 ('merge-provider-principals','fragment.py','if len(provider_arns) > 1:', 'if False:',BASE+'test_mixed_provider_principals_refused'),
 ('coerce-token-coordinates','normalized_study.py','if any(not isinstance(v, str) or not v for v in values):\n        raise ValueError("token coordinates must be nonempty strings; no coercion")\n    return values','return tuple(str(v) for v in values)',BASE+'test_normalized_no_coordinate_coercion'),
 ('replay-status-only','normalized_study.py','if digest(got.to_json()) != digest(cert["decision"]):','if got.status != cert["decision"]["status"]:',BASE+'test_normalized_entire_result_replayed'),
 ('skip-receipt-envelope-digest','receipt.py','if digest({k:v for k,v in receipt.items() if k != "receipt_sha256"}) != receipt["receipt_sha256"]:', 'if False:',BASE+'test_receipt_unsealed_tamper'),
 ('receipt-verdict-only','receipt.py','if digest(semantic_view(got)) != digest(receipt["decision"]):','if got["verdict"] != receipt["decision"]["verdict"]:',BASE+'test_receipt_implementation_change')]
# Resolve the declared shared-rule test class from the actual source rather than
# assuming a historic class name.
source=(ROOT/'tests/test_gate_decision_precedence.py').read_text()
cls=re.search(r'class\s+(\w+)\(',source).group(1)
FAULTS[1]=(*FAULTS[1][:4],f'test_gate_decision_precedence.{cls}.test_only_missing')
rows=[];logroot=ROOT/'logs/seeded_faults';logroot.mkdir(parents=True,exist_ok=True)
for name,file,old,new,test in FAULTS:
    with tempfile.TemporaryDirectory(prefix='fedfence-benign-fault-') as td:
        target=Path(td)
        for directory in ['fse_workflow','tests','scripts']:
            shutil.copytree(ROOT/directory,target/directory,ignore=shutil.ignore_patterns('__pycache__'))
        shutil.copytree(ROOT/'artifact/fedfence',target/'artifact/fedfence',ignore=shutil.ignore_patterns('__pycache__'))
        env={**os.environ,'PYTHONPATH':str(target/'tests')+os.pathsep+str(target),'PYTHONDONTWRITEBYTECODE':'1'}
        cmd=[sys.executable,'-m','unittest',test]
        baseline=subprocess.run(cmd,cwd=target,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        assert baseline.returncode==0,(name,'baseline failed',baseline.stdout)
        p=target/'fse_workflow'/file;data=p.read_text();assert data.count(old)==1,(name,'ambiguous patch')
        p.write_text(data.replace(old,new,1))
        faulty=subprocess.run(cmd,cwd=target,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        killed=faulty.returncode!=0 and 'FAIL:' in faulty.stdout and 'ERROR:' not in faulty.stdout
        (logroot/(name+'.log')).write_text('BASELINE\n'+baseline.stdout+'\nSEEDED FAULT\n'+faulty.stdout)
        row=dict(name=name,file='fse_workflow/'+file,test=test,baseline_passed=True,assertion_detected_fault=killed,syntax_or_import_error='ERROR:' in faulty.stdout,source_change_sha256=hashlib.sha256((old+'\n=>\n'+new).encode()).hexdigest())
        rows.append(row);print(row,flush=True)
        assert killed,(name,faulty.stdout)
save_json(ROOT/'tosem/results/seeded_faults.json',dict(passed=True,hand_selected_faults=len(rows),detected=sum(r['assertion_detected_fault'] for r in rows),rows=rows,scope='One preselected regression test per single seeded semantic defect; no representative mutation adequacy estimate; isolated temporary copies only'))
