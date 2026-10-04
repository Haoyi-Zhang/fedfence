#!/usr/bin/env python3
"""Rebuild a separate copy after deleting generated outputs (no network).

The destination must not exist. The caller deliberately chooses its location;
this command never clears or overwrites an existing destination. Wall-clock
measurements and PDF bytes are not required to agree across builds.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT.parent
JSON_FILES = [
    'unit_tests.json', 'core_self_check.json', 'finite_semantics_audit.json',
    'two_sided_exhaustive.json', 'two_sided_samples.json',
    'strict_literal_differential.json', 'relational_audit.json',
    'dependency_metamorphic.json', 'seeded_faults.json', 'repair_audit.json',
    'public_study.json', 'source_frontier.json', 'maintenance_metadata.json',
    'matcher_differential.json', 'issuer_membership_differential.json',
    'strict_glob_differential.json', 'character_domain_audit.json',
]

def hash_object(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()


def stable(value: object) -> object:
    """Exclude only named runtime durations from the selected JSON artifacts."""
    if isinstance(value, dict):
        return {k: stable(v) for k, v in value.items() if k not in {'elapsed_seconds', 'total_seconds', 'seconds'}}
    if isinstance(value, list):
        return [stable(v) for v in value]
    return value


def fingerprints(package: Path) -> dict[str, str]:
    results = package / 'artifact/tosem/results'
    answer = {name: hash_object(stable(json.loads((results / name).read_text()))) for name in JSON_FILES}
    # Timing CSV semantic columns must agree, but timing samples are new data.
    with (results / 'local_scaling.csv').open(newline='') as stream:
        rows = list(csv.DictReader(stream))
    answer['local_scaling.csv:non-timing-columns'] = hash_object([
        {k: v for k, v in row.items() if k != 'seconds'} for row in rows])
    answer['implementation_sha256'] = json.loads((results / 'reproduction.json').read_text())['implementation_sha256']
    return answer


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--destination', type=Path, required=True)
    args = parser.parse_args()
    destination = args.destination.resolve()
    if destination.exists() or PACKAGE == destination or PACKAGE in destination.parents:
        parser.error('destination must be absent and outside the current package')
    baseline = fingerprints(PACKAGE)
    shutil.copytree(PACKAGE, destination, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    removed: list[str] = []
    def remove_file(path: Path) -> None:
        if path.is_file():
            removed.append(str(path.relative_to(destination)))
            path.unlink()
    for relative in ['artifact/tosem/results', 'artifact/logs', 'paper/generated']:
        for file in sorted((destination / relative).rglob('*')):
            remove_file(file)
    # Compatibility outputs are recreated by current drivers, not used as inputs.
    for relative in ['artifact/fse/results/unit_tests.json',
                     'artifact/fse/results/finite_semantics_audit.json',
                     'artifact/results/repair_audit.json']:
        remove_file(destination / relative)
    for name in ['FedFence_TOSEM.pdf', 'main.pdf', 'main.aux', 'main.bbl', 'main.blg',
                 'main.fdb_latexmk', 'main.fls', 'main.log', 'main.out', 'main.toc']:
        remove_file(destination / 'paper' / name)
    # Stale release reports are not evidence in the clean copy.
    for name in ['CLEAN_REBUILD.md', 'PACKAGE_SHA256SUMS', 'AUDIT_REPORT.md']:
        remove_file(destination / 'artifact/docs' / name)
    log = destination / 'artifact/logs/clean-rebuild.log'
    log.parent.mkdir(exist_ok=True)
    with log.open('w') as stream:
        run = subprocess.run(['make', 'reproduce'], cwd=destination / 'artifact',
            env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONOPTIMIZE': '0'},
            stdout=stream, stderr=subprocess.STDOUT, check=False)
    record = dict(schema='fedfence-clean-rebuild-check-v2', command=['make', 'reproduce'],
        exit_code=run.returncode, removed_generated_file_count=len(removed),
        removed_before_rebuild=removed, baseline_semantic_fingerprints=baseline,
        network_access=False, cloud_accounts_used=False,
        timing_equality_required=False, pdf_byte_equality_required=False,
        scope='Independent directory in the same local environment, not an independent lab or platform.')
    if run.returncode == 0:
        rebuilt = fingerprints(destination)
        audit = json.loads((destination/'artifact/tosem/results/final_audit.json').read_text())
        reproduction = json.loads((destination/'artifact/tosem/results/reproduction.json').read_text())
        record.update(rebuilt_semantic_fingerprints=rebuilt,
            semantic_outputs_agree=baseline == rebuilt,
            evidence_steps=len(reproduction['steps']), consistency_checks=len(audit['checks']),
            all_consistency_checks_passed=audit['passed'], paper=audit['paper'],
            implementation_sha256=audit['implementation_sha256'],
            passed=baseline == rebuilt and audit['passed'])
    else:
        record['passed'] = False
    out = destination / 'artifact/tosem/results/clean_rebuild_validation.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(record, indent=2, ensure_ascii=False) + '\n')
    print(json.dumps({k:record[k] for k in ['passed','exit_code','removed_generated_file_count']}, indent=2))
    return 0 if record['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
