from __future__ import annotations
from collections import Counter
from pathlib import Path
import csv, hashlib, json, sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from fse_workflow.io import load_json, save_json


def main() -> int:
    manifest=load_json(ROOT/'study/source_frontier_sample.json')
    assert manifest['schema']=='fedfence-public-source-frontier-v1'
    rows=manifest['records']
    if len(rows)!=24:
        raise ValueError(f'expected frozen 24-record sample, got {len(rows)}')
    ids=set()
    for row in rows:
        key=(row['repository'],row['path'],row['commit'])
        if key in ids:
            raise ValueError(f'duplicate source record: {key}')
        ids.add(key)
        if hashlib.sha256(row['excerpt'].encode()).hexdigest()!=row['excerpt_sha256']:
            raise ValueError(f'excerpt digest mismatch: {key}')
        if len(row['commit'])!=40 or not row['source_url'].endswith(f"/{row['path']}"):
            raise ValueError(f'invalid pinned source metadata: {key}')
    classes=Counter(r['primary_frontier_class'] for r in rows)
    audiences=Counter(r['audience_constraint'] for r in rows)
    feature_counts=Counter(x for r in rows for x in r['features'])
    directly_normalizable=sum(r['primary_frontier_class'] in {'literal_source_policy','constant_foldable_hcl'} for r in rows)
    result={
        'schema':'fedfence-source-frontier-result-v1',
        'sample_size':len(rows),
        'unique_repositories':len({r['repository'] for r in rows}),
        'primary_classes':dict(sorted(classes.items())),
        'audience_constraints':dict(sorted(audiences.items())),
        'literal_or_constant_foldable':directly_normalizable,
        'requires_instantiation_or_host_evaluation':len(rows)-directly_normalizable,
        'unsupported_operator_records':sum('ForAnyValue:StringLike' in r['features'] for r in rows),
        'missing_audience_condition_records':audiences.get('missing',0),
        'top_features':feature_counts.most_common(12),
        'interpretation':'query-defined source-normalization frontier sample; not prevalence, safety, or extractor accuracy',
        'sampling_statement':manifest['sampling_statement'],
    }
    outdir=ROOT/'fse/results'; outdir.mkdir(parents=True,exist_ok=True)
    save_json(outdir/'source_frontier_summary.json',result)
    with (outdir/'source_frontier_rows.csv').open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=['repository','path','commit','primary_frontier_class','audience_constraint','features','source_url'])
        w.writeheader()
        for r in rows:
            w.writerow({**{k:r[k] for k in ['repository','path','commit','primary_frontier_class','audience_constraint','source_url']},'features':';'.join(r['features'])})
    print(json.dumps(result,indent=2,ensure_ascii=False))
    return 0

if __name__=='__main__':
    raise SystemExit(main())
