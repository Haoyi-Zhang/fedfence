from __future__ import annotations
from collections import Counter
from pathlib import Path
import csv, hashlib, json, sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from fse_workflow.io import load_json, save_json


def main() -> int:
    manifest=load_json(ROOT/'study/runtime_compatibility_corpus.json')
    assert manifest['schema']=='fedfence-runtime-compatibility-corpus-v1'
    rows=manifest['records']
    if len(rows)!=12:
        raise ValueError(f'expected frozen 12-record corpus, got {len(rows)}')
    seen=set()
    for row in rows:
        key=(row['repository'],row['commit'])
        if key in seen: raise ValueError(f'duplicate record: {key}')
        seen.add(key)
        check=dict(row); expected=check.pop('record_sha256')
        actual=hashlib.sha256(json.dumps(check,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        if actual!=expected: raise ValueError(f'record digest mismatch: {key}')
        if len(row['commit'])!=40: raise ValueError(f'invalid SHA: {key}')
    repairs=Counter(r['repair'] for r in rows)
    evidence=Counter(e for r in rows for e in r['evidence'])
    breakage=[r for r in rows if 'hardening' not in r['observation'].lower()]
    result={
      'schema':'fedfence-runtime-compatibility-result-v1',
      'records':len(rows),
      'unique_repositories':len({r['repository'] for r in rows}),
      'runtime_breakage_or_denial_reports':len(breakage),
      'hardening_without_reported_outage':len(rows)-len(breakage),
      'repair_strategies':dict(sorted(repairs.items())),
      'evidence_markers':dict(sorted(evidence.items())),
      'public_actions_success_runs':sum(r['public_success_run'] is not None for r in rows),
      'public_success_run_ids':[r['public_success_run'] for r in rows if r['public_success_run']],
      'interpretation':'purposive source-backed maintenance corpus; commit claims are not independent root-cause adjudication or prevalence evidence',
      'selection_statement':manifest['selection_statement'],
    }
    outdir=ROOT/'fse/results';outdir.mkdir(parents=True,exist_ok=True)
    save_json(outdir/'runtime_compatibility_summary.json',result)
    with (outdir/'runtime_compatibility_rows.csv').open('w',newline='',encoding='utf-8') as f:
      fields=['repository','commit','date','context','repair','observation','evidence','public_success_run','source_url']
      w=csv.DictWriter(f,fieldnames=fields);w.writeheader()
      for r in rows:
        row={k:r[k] for k in fields};row['evidence']=';'.join(row['evidence']);w.writerow(row)
    print(json.dumps(result,indent=2,ensure_ascii=False))
    return 0

if __name__=='__main__':
    raise SystemExit(main())
