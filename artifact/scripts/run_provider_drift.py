#!/usr/bin/env python3
from __future__ import annotations
import csv, json, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from fedfence.analyzer import analyze_case
OUT=ROOT/'results'

def main()->int:
    OUT.mkdir(exist_ok=True)
    rows=[]
    for p in sorted((ROOT/'provider_drift_cases').glob('*.json')):
        case=json.loads(p.read_text())
        res=analyze_case(case)
        exp=bool(case.get('expected_safe'))
        pred=bool(res.safe)
        rows.append({'file':p.name,'case':case.get('name',p.stem),'source_basis':case.get('source_basis',''),
                     'expected_safe':exp,'fedfence_safe':pred,'correct':exp==pred,
                     'findings':len(res.findings),'witnesses':'; '.join(getattr(f,'witness','') or '' for f in res.findings)})
    with (OUT/'provider_drift_cases.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
    overall={'cases':len(rows),'correct':sum(1 for r in rows if r['correct']),'passed':all(r['correct'] for r in rows),
             'purpose':'source-grounded GitHub OIDC semantic drift fixtures: immutable subject claims, repository_id, and job_workflow_ref'}
    (OUT/'provider_drift_overall.json').write_text(json.dumps(overall,indent=2,sort_keys=True)+'\n')
    print(json.dumps(overall,indent=2,sort_keys=True))
    return 0 if overall['passed'] else 1
if __name__=='__main__':
    raise SystemExit(main())
