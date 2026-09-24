"""Separate syntactic eligibility from correctness or deployment coverage."""
from pathlib import Path
import sys
from collections import Counter
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT))
from fse_workflow.fragment import inspect_policy
from fse_workflow.io import load_json, save_json
rows=[]
for path in sorted((ROOT/'baseline/artifact/cases').glob('*.json')):
    obj=load_json(path)
    if 'states' in obj:
        rows.append({'case':path.name,'status':'separate-finite-event-backend','issues':[]})
        continue
    r=inspect_policy(obj.get('policy'))
    rows.append({'case':path.name,'status':'eligible' if r['supported'] else 'outside-gate-profile','issues':r['issues']})
summary={'rows':rows,'counts':dict(Counter(x['status'] for x in rows)),
         'denominator':'37 existing curated cases, not a sample of deployments',
         'meaning':'syntax profile eligibility only; no prevalence or accuracy estimate'}
save_json(ROOT/'fse/results/legacy_fragment_inventory.json',summary)
print(summary['counts'])
