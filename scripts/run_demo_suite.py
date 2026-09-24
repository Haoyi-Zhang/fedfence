from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT))
from fse_workflow.io import load_json,save_json
from fse_workflow.gate import review,compare
from fse_workflow.reporting import render_summary
expected={'before':'pass','after_wildcard':'fail','after_stale':'unknown','after_unsupported':'unknown',
          'environment_missing':'unknown','environment_reviewed':'pass',
          'availability_before':'pass','availability_after':'fail'}
rows=[]
for name, verdict in expected.items():
    p=load_json(ROOT/'examples/release_gate'/f'{name}.json')
    r=review(p,now='2026-09-23T01:00:00Z')
    save_json(ROOT/'fse/results'/f'demo_{name}.json',r)
    rows.append({'example':name,'expected':verdict,'actual':r['verdict'],'passed':r['verdict']==verdict})
    print(name); print(render_summary(r)); print()
r=compare(load_json(ROOT/'examples/release_gate/before.json'),load_json(ROOT/'examples/release_gate/after_wildcard.json'),now='2026-09-23T01:00:00Z')
save_json(ROOT/'fse/results/demo_regression.json',r)
assert r['confirmed_admission_regression']
availability=compare(load_json(ROOT/'examples/release_gate/availability_before.json'),load_json(ROOT/'examples/release_gate/availability_after.json'),now='2026-09-23T01:00:00Z')
save_json(ROOT/'fse/results/demo_availability_regression.json',availability)
assert availability['contract_unchanged']
assert availability['confirmed_contract_regression'] and availability['confirmed_required_identity_regression']
assert not availability['confirmed_admission_regression']
assert availability['before']['verdict']=='pass' and availability['after']['verdict']=='fail'
assert any(f.get('code')=='required-token-not-admitted' for f in availability['after']['findings'])
assert all(x['passed'] for x in rows)
save_json(ROOT/'fse/results/demo_summary.json',{'rows':rows,'all_expected':True,'evidence_type':'synthetic walkthroughs'})
