from __future__ import annotations
import json, pathlib, sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from fse_workflow.normalized_study import decide, certificate, replay
from fse_workflow.normalized_study_contract_test import run as contract_run

def main():
 c=json.loads((ROOT/'study/corrections.json').read_text())
 rows=[]
 # sports-store roles, before/after, plus subject swaps
 for role in c['sports_store']['roles']:
  common=dict(explicit_issuer=role['explicit_issuer'],intent=role['intent'],required=role['required'])
  b=decide(allow=role['before_allow'],**common); a=decide(allow=role['after_allow'],**common)
  assert replay(certificate({**common,'allow':role['after_allow']},a)).status==a.status
  rows.append({'repository':c['sports_store']['repository'],'role':role['role'],'before':b.status,'after':a.status})
 rolemap={r['role']:r for r in c['sports_store']['roles']}
 for ce in c['sports_store']['cross_role_counterexamples']:
  role=rolemap[ce['role']]
  probe=decide(explicit_issuer=[ce['must_reject']],allow=role['after_allow'],intent=[ce['must_reject']],required=[])
  assert ce['must_reject'] not in probe.admitted,(ce,probe)
 # microticket branches
 m=c['microticket']; common=dict(explicit_issuer=m['explicit_issuer'],intent=m['intent'],required=m['required'])
 for cfg in m['configurations']:
  r=decide(allow=cfg['allow'],**common); assert r.status==cfg['expected'],(cfg,r)
  rows.append({'repository':m['repository'],'role':m['role'],'configuration':cfg['name'],'result':r.status,'conditional_on':cfg.get('conditional_on')})
 result={'schema':'fedfence.repair-audit.v1','issuer_contract':contract_run(),'rows':rows,
         'denominators':c['denominator_definition'],'status':'pass'}
 out=ROOT/'results/repair_audit.json'; out.parent.mkdir(exist_ok=True); out.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
 print(json.dumps(result,sort_keys=True))
if __name__=='__main__': main()
