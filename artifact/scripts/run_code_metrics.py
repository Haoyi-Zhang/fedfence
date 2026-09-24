#!/usr/bin/env python3
from __future__ import annotations
import csv, json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / 'results'
CATEGORIES = {
    'core_checker': ROOT / 'fedfence',
    'reproduction_harness': ROOT / 'scripts',
    'registered_cases': ROOT / 'cases',
    'optional_hardening_cases': ROOT / 'hardening_cases',
    'public_examples': ROOT / 'public_examples',
    'external_evidence': ROOT / 'external_evidence',
    'provider_drift_cases': ROOT / 'provider_drift_cases',
    'governance_exports': ROOT / 'governance_exports',
    'deployment_manifest': ROOT / 'deployment_manifest',
}


def code_loc(path: Path) -> tuple[int, int, int]:
    files = logical = physical = 0
    for p in sorted(path.rglob('*.py')):
        if '__pycache__' in p.parts:
            continue
        files += 1
        for line in p.read_text(errors='ignore').splitlines():
            physical += 1
            stripped = line.strip()
            if stripped and not stripped.startswith('#'):
                logical += 1
    return files, physical, logical


def json_count(path: Path) -> int:
    return len(list(path.glob('*.json'))) if path.exists() else 0


def main() -> int:
    RESULTS.mkdir(exist_ok=True)
    rows = []
    totals = {'python_files': 0, 'physical_loc': 0, 'logical_loc': 0, 'json_objects': 0}
    for name, path in CATEGORIES.items():
        if name in {'core_checker', 'reproduction_harness'}:
            files, physical, logical = code_loc(path)
            row = {'component': name, 'files': files, 'physical_loc': physical, 'logical_loc': logical, 'json_objects': 0}
            totals['python_files'] += files
            totals['physical_loc'] += physical
            totals['logical_loc'] += logical
        else:
            count = json_count(path)
            row = {'component': name, 'files': count, 'physical_loc': 0, 'logical_loc': 0, 'json_objects': count}
            totals['json_objects'] += count
        rows.append(row)
    manifest_checks = {
        'registered_cases_exactly_37': json_count(ROOT / 'cases') == 37,
        'hardening_cases_separate': json_count(ROOT / 'hardening_cases') == 3,
        'public_examples_exactly_20': json_count(ROOT / 'public_examples') == 20,
        'provider_drift_cases_at_least_4': json_count(ROOT / 'provider_drift_cases') >= 4,
        'governance_export_fixtures_at_least_6': json_count(ROOT / 'governance_exports') >= 6,
        'deployment_manifest_present': json_count(ROOT / 'deployment_manifest') >= 1,
        'certificate_replay_separated_from_analyzer': 'from .analyzer import' not in (ROOT / 'fedfence' / 'certificate.py').read_text(errors='ignore'),
    }
    out = {'passed': all(manifest_checks.values()), 'totals': totals, 'components': rows, 'manifest_checks': manifest_checks}
    with (RESULTS / 'code_metrics.csv').open('w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['component', 'files', 'physical_loc', 'logical_loc', 'json_objects'])
        w.writeheader(); w.writerows(rows)
    (RESULTS / 'code_metrics.json').write_text(json.dumps(out, indent=2, sort_keys=True) + '\n')
    print(json.dumps(out, indent=2, sort_keys=True), flush=True)
    return 0 if out['passed'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
