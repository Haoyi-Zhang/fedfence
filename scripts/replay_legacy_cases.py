from pathlib import Path
import sys
import time
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'artifact'))
from fedfence.analyzer import analyze_case
from fse_workflow.io import load_json,save_json
rows=[]
for path in sorted((ROOT/'baseline/artifact/cases').glob('*.json')):
    case=load_json(path); t=time.perf_counter(); result=analyze_case(case)
    rows.append({'case':path.name,'expected_safe':case.get('expected_safe'), 'actual_safe':result.safe,
                 'agrees':case.get('expected_safe')==result.safe,
                 'elapsed_seconds':time.perf_counter()-t})
r={'rows':rows,'agreements':sum(x['agrees'] for x in rows),'total':len(rows),
   'meaning':'re-execution of pre-existing curated labels only; not independent field ground truth'}
save_json(ROOT/'fse/results/legacy_case_replay.json',r)
print(r['agreements'],r['total'])
raise SystemExit(0 if all(x['agrees'] for x in rows) else 1)
