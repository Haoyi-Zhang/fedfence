#!/usr/bin/env python3
from __future__ import annotations
import csv, json, sys, urllib.parse, time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from fedfence.analyzer import analyze_case, load_case  # noqa: E402


def category(url: str) -> str:
    host = urllib.parse.urlparse(url).netloc.lower()
    if host.endswith('docs.github.com') or host.endswith('docs.aws.amazon.com') or host.endswith('aws.amazon.com') or host.endswith('docs.gitlab.com') or host.endswith('cloud.google.com') or host.endswith('learn.microsoft.com'):
        return 'official-provider'
    if host.endswith('github.com') or host.endswith('gist.github.com'):
        return 'public-repository-or-discussion'
    if host.endswith('stackoverflow.com'):
        return 'public-troubleshooting'
    return 'public-article'


def load_rows_from_dir(dirname: str, group: str, analyze: bool) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for path in sorted((ROOT/dirname).glob('*.json')):
        obj = load_case(path)
        url = str(obj.get('source_url',''))
        row: dict[str, object] = {
            'group': group,
            'file': path.name,
            'example': obj.get('name', path.stem),
            'expected_safe': bool(obj.get('expected_safe')),
            'source': obj.get('public_source',''),
            'url': url,
            'domain': urllib.parse.urlparse(url).netloc,
            'category': category(url),
            'fedfence_safe': '',
            'correct': '',
            'findings': '',
            'ms': '',
        }
        if analyze:
            t0 = time.perf_counter(); res = analyze_case(obj); ms = (time.perf_counter()-t0)*1000
            row['fedfence_safe'] = bool(res.safe)
            row['correct'] = bool(res.safe) == bool(obj.get('expected_safe'))
            row['findings'] = ';'.join(f.kind for f in res.findings)
            row['ms'] = round(ms, 3)
        rows.append(row)
    return rows


def main() -> int:
    rows = load_rows_from_dir('public_examples', 'registered-public-examples', analyze=False)
    optional = load_rows_from_dir('external_evidence', 'optional-public-issue-challenge', analyze=True)
    all_rows = rows + optional
    out = ROOT/'results'; out.mkdir(exist_ok=True)
    fields = ['group','file','example','expected_safe','source','url','domain','category','fedfence_safe','correct','findings','ms']
    with (out/'external_evidence_manifest.csv').open('w', newline='') as f:
        w=csv.DictWriter(f, fieldnames=fields); w.writeheader(); w.writerows(all_rows)
    if optional:
        with (out/'external_evidence_cases.csv').open('w', newline='') as f:
            w=csv.DictWriter(f, fieldnames=fields); w.writeheader(); w.writerows(optional)
    by_cat = {}
    for r in all_rows:
        d = by_cat.setdefault((r['group'], r['category']), {'group': r['group'], 'category': r['category'], 'examples': 0, 'unsafe': 0, 'analyzed': 0, 'correct': 0})
        d['examples'] += 1; d['unsafe'] += int(not bool(r['expected_safe']))
        if r['correct'] != '':
            d['analyzed'] += 1; d['correct'] += int(bool(r['correct']))
    cats = sorted(by_cat.values(), key=lambda x: (x['group'], x['category']))
    with (out/'external_evidence_summary.csv').open('w', newline='') as f:
        w=csv.DictWriter(f, fieldnames=['group','category','examples','unsafe','analyzed','correct']); w.writeheader(); w.writerows(cats)
    overall={
        'registered_public_examples': len(rows),
        'optional_public_issue_challenge': len(optional),
        'optional_correct': sum(1 for r in optional if r.get('correct') is True),
        'optional_unsafe': sum(1 for r in optional if not bool(r['expected_safe'])),
        'categories': len(cats),
        'official_provider_examples': sum(1 for r in all_rows if r['category']=='official-provider'),
        'public_repository_or_discussion_examples': sum(1 for r in all_rows if r['category']=='public-repository-or-discussion'),
        'network_access': False,
        'claim': 'source-grounded optional challenge set; not a prevalence scan or live-cloud validation',
    }
    (out/'external_evidence_overall.json').write_text(json.dumps(overall, indent=2, sort_keys=True)+'\n')
    (ROOT/'external_evidence'/'README.md').write_text(
        '# Optional public-issue challenge set\n\n'
        'The registered abstract profile counts the 20 files under `public_examples/`.\n'
        'This directory is optional extra evidence: public issue, README, marketplace, and provider-documentation snippets normalized into the same local case format.\n'
        'The artifact does not perform network access, does not claim a prevalence measurement, and does not require live cloud accounts. URLs are retained for human inspection.\n'
    )
    print(json.dumps(overall, indent=2, sort_keys=True))
    return 0 if (not optional or overall['optional_correct'] == len(optional)) else 1
if __name__ == '__main__':
    raise SystemExit(main())
