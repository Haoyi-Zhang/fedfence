"""Time-bounded offline checks from the flat artifact repository root.

Runs owned finite/synthetic models and passive parsing of supplied frozen data.
No paper build, source download, public workflow, cloud API, or external tool.
Recorded costs are local measurements, not universal scientific validation.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=ROOT/'scientific-check-output')
    parser.add_argument('--whole-seconds', type=int, default=1200)
    args = parser.parse_args()
    if sys.flags.optimize or not 1 <= args.whole_seconds <= 1200:
        parser.error('assertions must be enabled and whole-seconds must lie in 1..1200')
    # Each invocation keeps its own logs; old successful logs cannot mask failure.
    args.out.mkdir(parents=True, exist_ok=False)
    env = {**os.environ, 'PYTHONUTF8': '1', 'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONOPTIMIZE': '0'}
    commands = [
        ('unit-tests', ['scripts/run_fse_tests.py'], 300),
        ('core-self-check', ['artifact/scripts/self_check.py'], 120),
        ('projection-audit', ['scripts/run_finite_audit.py'], 120),
        ('relational-audit', ['scripts/run_relational_audit.py'], 120),
        ('two-sided-validation', ['scripts/run_tosem_validation.py'], 240),
        ('character-domain', ['scripts/run_character_domain_audit.py', '--no-paper-table'], 180),
        ('matcher-issuer-globs-scaling', ['scripts/run_final_validation.py'], 300),
        ('repair-audit', ['scripts/run_repair_audit.py'], 120),
        ('source-studies', ['scripts/run_tosem_studies.py'], 180),
    ]
    started = time.monotonic()
    rows = []
    for name, tail, cap in commands:
        remaining = args.whole_seconds - (time.monotonic() - started)
        command = [sys.executable, '-B', *tail]
        row = dict(name=name, command=command, exit_code=None, timed_out=False)
        step_start = time.monotonic()
        with (args.out/(name+'.log')).open('w', encoding='utf-8') as stream:
            try:
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command, args.whole_seconds)
                run = subprocess.run(command, cwd=ROOT, env=env, stdout=stream,
                                     stderr=subprocess.STDOUT, timeout=min(cap, remaining))
                row['exit_code'] = run.returncode
            except subprocess.TimeoutExpired:
                row['timed_out'] = True
                stream.write('\nThe declared execution budget was exhausted.\n')
            except OSError as exc:
                row['error'] = str(exc)
                stream.write('\n'+str(exc)+'\n')
        row['seconds'] = time.monotonic() - step_start
        rows.append(row)
        record = dict(steps=rows, passed=len(rows) == len(commands) and all(r['exit_code'] == 0 for r in rows),
                      elapsed_seconds=time.monotonic()-started, whole_seconds=args.whole_seconds,
                      python=sys.version, platform=platform.platform(),
                      scope='Local finite/synthetic consistency and supplied-data integrity; not provider equivalence or paper/PDF QA.')
        (args.out/'execution.json').write_text(json.dumps(record, indent=2)+'\n', encoding='utf-8')
        print(json.dumps(row), flush=True)
        if row['exit_code'] != 0:
            return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
