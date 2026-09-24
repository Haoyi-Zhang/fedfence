from pathlib import Path
import json,sys
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from fse_workflow.io import load_json
p=ROOT/'fse/results/public_change_latency.json'
d=load_json(p)
assert d['schema']=='fedfence-public-change-latency-v2'
assert d['repeats']==7 and len(d['rows'])==9
assert d['all_changes']['median_ms']>0 and d['all_changes']['p95_ms']>=d['all_changes']['median_ms']
print(json.dumps({'validated':str(p.relative_to(ROOT)),'sha256':__import__('hashlib').sha256(p.read_bytes()).hexdigest(),'note':'frozen seven-repetition latency result; expensive rerun available via scripts/benchmark_public_changes.py'},indent=2))
