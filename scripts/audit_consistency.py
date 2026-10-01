from __future__ import annotations
import json,pathlib,re
ROOT=pathlib.Path(__file__).resolve().parents[1]; PAPER=ROOT.parent/'paper'
src=json.loads((ROOT/'results/source_frontier_audit.json').read_text())
assert src['summary']['total']==24
assert src['summary']['source_available']==24
pub=json.loads((ROOT/'results/public_change_study.json').read_text())
assert pub['denominators']=={'commits':9,'roles':10,'evaluated_configurations':21}
assert pub['recovery']['complete']
repair=json.loads((ROOT/'results/repair_audit.json').read_text()); assert repair['status']=='pass'
t=(PAPER/'main.tex').read_text()
for stale in ['0.98~s','1.03~s','946.0769','986.2235']: assert stale not in t
assert 'minimum\\_cardinality=None' in t and 'inspect\\_projection' in t and 'mixed\\_classes' in t
assert 'study-only normalized backend' in t
cor=json.loads((ROOT/'study/corrections.json').read_text()); roles=cor['sports_store']['roles']
assert len(roles)==2 and sorted(len(r['after_allow']) for r in roles)==[1,6]
assert not cor['microticket']['actions_success_metadata_is_assignment_proof']
assert (ROOT/'UNAVAILABLE_EVIDENCE.json').exists()
out={'schema':'fedfence.consistency-audit.v1','status':'pass','source_files':24,'public_denominators':pub['denominators']}
(ROOT/'results/consistency_audit.json').write_text(json.dumps(out,indent=2,sort_keys=True)+'\n'); print(json.dumps(out,sort_keys=True))
