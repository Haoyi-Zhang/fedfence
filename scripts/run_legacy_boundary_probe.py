"""Reproduce a cross-backend boundary problem without asserting cloud exploitation."""
from pathlib import Path
import sys
import copy
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT)); sys.path.insert(0,str(ROOT/'baseline/artifact'))
from fedfence.analyzer import analyze_case
from fse_workflow.fragment import PREFIX
from fse_workflow.gate import review
from fse_workflow.io import save_json
from scripts.make_workflow_examples import packet, rehash

p=packet()
st=p['snapshots']['policy']['body']['Statement'][0]
main=st['Condition']['StringEquals'][PREFIX+'sub']; dev=main.replace('/main','/dev')
st['Condition']['StringEquals'][PREFIX+'sub']=[main,dev]
deny=copy.deepcopy(st); deny['Effect']='Deny'
deny['Condition']['StringEquals'][PREFIX+'sub']=dev
# Parser recognizes this field, but the legacy regular backend only builds sub/aud Deny rectangles.
deny['Condition']['StringEquals'][PREFIX+'job_workflow_ref']='acme/api/.github/workflows/release.yml@refs/heads/main'
p['snapshots']['policy']['body']['Statement'].append(deny); rehash(p,'policy')
case={'name':'selected-deny-coordinate-probe','policy':p['snapshots']['policy']['body'],
      'spec':{'allowed_subjects':[main], 'allowed_audiences':['sts.amazonaws.com']},
      'repository_governance':{'protected_environments':[]}}
legacy=analyze_case(case)
new=review(p,now='2026-09-23T01:00:00Z')
assert legacy.safe is True, legacy
assert new['verdict']=='unknown', new
# Direct concrete tuple: admitted by Allow; not removed by the selected-workflow Deny.
token={'sub':dev,'aud':'sts.amazonaws.com','job_workflow_ref':'acme/api/.github/workflows/unreviewed.yml@refs/heads/dev'}
assert token['sub'] in st['Condition']['StringEquals'][PREFIX+'sub']
assert token['job_workflow_ref'] != deny['Condition']['StringEquals'][PREFIX+'job_workflow_ref']
summary={'legacy_regular_backend_safe':legacy.safe,'fse_gate_verdict':new['verdict'],
         'new_finding_codes':[f['code'] for f in new['findings']], 'concrete_model_tuple':token,
         'finding':'selected-claim Deny condition is accepted by parser but ignored by two-claim regular backend',
         'fix':'reject before dispatch to this backend; selected-claim end-to-end adapter remains future work',
         'scope':'synthetic implementation boundary regression; not a live-cloud exploit or corpus finding', 'passed':True}
save_json(ROOT/'fse/results/legacy_boundary_probe.json',summary)
save_json(ROOT/'fse/results/legacy_boundary_probe_case.json',case)
print(summary)
