#!/usr/bin/env python3
from __future__ import annotations
import csv, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from fedfence.certificate import certificate_for_case, verify_certificate  # noqa: E402

GROUPS = [
    ('registered', ROOT/'cases'),
    ('registered-public', ROOT/'public_examples'),
    ('optional-hardening', ROOT/'hardening_cases'),
    ('optional-public-issue', ROOT/'external_evidence'),
    ('provider-drift', ROOT/'provider_drift_cases'),
]

def load(path: Path) -> dict:
    return json.loads(path.read_text())

def main() -> int:
    rows=[]
    for group, directory in GROUPS:
        for path in sorted(directory.glob('*.json')):
            case = load(path)
            cert = certificate_for_case(case)
            ok, msg = verify_certificate(cert)
            replay = cert.get('replay_summary', {})
            replay_safe = bool(replay.get('safe'))
            expected_present = isinstance(case.get('expected_safe'), bool)
            expected = bool(case.get('expected_safe')) if expected_present else ''
            rows.append({
                'group': group,
                'file': path.name,
                'case': case.get('name', path.stem),
                'expected_safe': expected,
                'replay_safe': replay_safe,
                'matches_expected_label': (replay_safe == expected) if expected_present else '',
                'certificate_verified': bool(ok),
                'blocking_kinds': ';'.join(replay.get('blocking_kinds', [])),
                'all_kinds': ';'.join(replay.get('all_kinds', [])),
                'verifier_note': '; '.join(msg) if isinstance(msg, list) else str(msg),
            })
    out=ROOT/'results'; out.mkdir(exist_ok=True)
    fields=list(rows[0].keys())
    with (out/'replay_oracle.csv').open('w', newline='') as f:
        w=csv.DictWriter(f, fieldnames=fields); w.writeheader(); w.writerows(rows)
    by_group={}
    for r in rows:
        d=by_group.setdefault(r['group'], {'rows':0,'verified':0,'matches_expected':0,'expected_rows':0})
        d['rows'] += 1
        d['verified'] += int(bool(r['certificate_verified']))
        if r['matches_expected_label'] != '':
            d['expected_rows'] += 1
            d['matches_expected'] += int(bool(r['matches_expected_label']))
    overall={
        'rows': len(rows),
        'verified': sum(1 for r in rows if r['certificate_verified']),
        'expected_labeled_rows': sum(1 for r in rows if r['matches_expected_label'] != ''),
        'matches_expected_labels': sum(1 for r in rows if r['matches_expected_label'] is True),
        'groups': by_group,
        'imports_high_level_analyzer': False,
        'shared_tcb': ['policy parser', 'GitHub issuer constructors', 'generic NFA primitives'],
        'claim': 'replay-safe labels are recomputed from the certificate verifier rather than read from expected_safe fields',
    }
    (out/'replay_oracle_overall.json').write_text(json.dumps(overall, indent=2, sort_keys=True)+'\n')
    print(json.dumps(overall, indent=2, sort_keys=True))
    return 0 if overall['verified']==overall['rows'] and overall['matches_expected_labels']==overall['expected_labeled_rows'] else 1
if __name__ == '__main__':
    raise SystemExit(main())
