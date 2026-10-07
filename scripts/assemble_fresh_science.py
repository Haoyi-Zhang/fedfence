"""Prepare an absent execution copy; assemble actually generated native evidence.

Does not launch scientific drivers, download, dispatch CI, delete files, or
rewrite retained receipts. Collection calls the unchanged passive native audit.
This is a non-adversarial reproduction guard, not execution authentication.
"""
from __future__ import annotations

import argparse
import datetime
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
STATE = '_fresh-science'
EVIDENCE = 'fresh-native-evidence'
GENERATED = ('tosem/results', 'fse/results', 'results',
             'scientific-check-output', 'scalar-regression-output')
RESERVED = (STATE, EVIDENCE)
PREPARE_SCHEMA = 'fedfence-fresh-preparation-v1'


def require(condition, detail):
    if not condition:
        raise ValueError(detail)


def plain(path):
    """Reject links/reparse points and special files, before following a path."""
    info = path.lstat()
    require(not stat.S_ISLNK(info.st_mode) and
            not getattr(info, 'st_file_attributes', 0) & 0x400,
            'link/reparse point: ' + str(path))
    require(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode),
            'special file: ' + str(path))


def checked_root(path, *, existing):
    path = Path(os.path.abspath(path))
    for parent in reversed((path, *path.parents)):
        if parent.exists() or parent.is_symlink():
            plain(parent)
    if existing:
        require(path.is_dir(), 'missing directory: ' + str(path))
    return path


def below(name, prefixes):
    return any(name == p or name.startswith(p + '/') for p in prefixes)


def inventory(root):
    """Immutable copy inputs, excluding only declared output roots and caches."""
    import hashlib

    files = {}

    def walk(folder):
        for path in sorted(folder.iterdir()):
            plain(path)
            name = path.relative_to(root).as_posix()
            if path.name in ('.git', '__pycache__') or path.suffix in ('.pyc', '.pyo'):
                continue
            if below(name, GENERATED + RESERVED):
                continue
            if path.is_dir():
                walk(path)
            else:
                files[name] = hashlib.sha256(path.read_bytes()).hexdigest()

    walk(root)
    return files


def copy_fresh(source, workdir):
    source = checked_root(source, existing=True)
    workdir = checked_root(workdir, existing=False)
    require(not workdir.exists(), 'workdir already exists')
    require(not workdir.is_relative_to(source) and not source.is_relative_to(workdir),
            'source/workdir must be disjoint, not nested')
    require(workdir.parent.is_dir(), 'workdir parent must already exist')
    require(not any((source / name).exists() for name in RESERVED),
            'source already contains a fresh-campaign state/evidence directory')
    before = inventory(source)
    workdir.mkdir()
    for name in before:
        destination = workdir / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open('xb') as stream:
            stream.write((source / name).read_bytes())
    require(inventory(source) == before == inventory(workdir), 'copy/source bytes changed')
    require(not any((workdir / name).exists() for name in GENERATED + RESERVED),
            'generated output present before execution')
    return before


def passive_auditor(root):
    spec = importlib.util.spec_from_file_location(
        '_fedfence_passive_native_audit', root / 'scripts/audit_current_science.py')
    require(spec is not None and spec.loader is not None, 'missing passive auditor')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def output_map(auditor):
    """Destination-relative -> generated-origin-relative; never a retained fallback."""
    files = {name + '.json': 'tosem/results/' + name + '.json' for name in auditor.RECORDS}
    files.update({name + '.csv': 'tosem/results/' + name + '.csv' for name in
                  ('strict_literal_differential', 'strict_glob_differential',
                   'local_scaling', 'public_study')})
    files.update({name + '.log': 'scientific-check-output/' + name + '.log'
                  for name, _ in auditor.STEPS})
    files.update({'execution.json': 'scientific-check-output/execution.json',
                  'unit_tests.json': 'fse/results/unit_tests.json',
                  'finite_semantics_audit.json': 'fse/results/finite_semantics_audit.json',
                  'repair_audit.json': 'results/repair_audit.json'})
    files.update({f'bounded_glob_packets/case-{i:03}.json':
                  f'tosem/results/bounded_glob_packets/case-{i:03}.json' for i in range(192)})
    require(len(files) == 225 and len(set(files.values())) == 225, 'native evidence layout')
    return files


def snapshot(root, auditor):
    return dict(source_files=auditor.science_sources(root),
                study_inputs=auditor.study_inputs(root),
                implementation_sha256=auditor.linux_implementation_digest(root))


def write_new(path, record):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(record, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write('\n')


def verify_inventory(root, expected):
    require(inventory(root) == expected, 'immutable copied source/input/support bytes changed')


def prepare(source, workdir):
    source = checked_root(source, existing=True)
    workdir = checked_root(workdir, existing=False)
    copied = copy_fresh(source, workdir)
    auditor = passive_auditor(workdir)
    record = dict(schema=PREPARE_SCHEMA, source=str(source), workdir=str(workdir),
                  prepared_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  immutable_files=copied, absent_output_roots=list(GENERATED),
                  output_map=output_map(auditor), **snapshot(workdir, auditor))
    verify_inventory(workdir, copied)
    (workdir / STATE).mkdir()
    (workdir / STATE / 'tmp').mkdir()
    write_new(workdir / STATE / 'prepare.json', record)
    return dict(prepared=True, workdir=str(workdir), immutable_files=len(copied),
                evidence_files=len(record['output_map']),
                prepare_sha256=auditor.sha(workdir / STATE / 'prepare.json'),
                scope='Copy/snapshot only; no scientific execution or positive receipt.')


def collect(workdir):
    root = checked_root(workdir, existing=True)
    # Validate immutable files before importing even the passive local auditor.
    manifest = root / STATE / 'prepare.json'
    plain(manifest)
    preparation = json.loads(manifest.read_text(encoding='utf-8'))
    require(preparation['schema'] == PREPARE_SCHEMA and preparation['workdir'] == str(root),
            'preparation identity')
    verify_inventory(root, preparation['immutable_files'])
    auditor = passive_auditor(root)
    preparation = auditor.load(manifest)
    require(preparation['absent_output_roots'] == list(GENERATED) and
            preparation['output_map'] == output_map(auditor), 'preparation layout changed')
    require(all(preparation[k] == v for k, v in snapshot(root, auditor).items()),
            'prepared scientific source/input binding changed')
    require(not (root / EVIDENCE).exists(), 'fresh evidence directory already exists')
    attempt = root / STATE / 'assembly-attempt.json'
    receipt_path = root / STATE / 'current-science-receipt.json'
    report_path = root / STATE / 'native-audit.json'
    require(not any(p.exists() for p in (attempt, receipt_path, report_path)),
            'collection already attempted; preserve this attempt and prepare a new workdir')
    try:
        origins = {name: auditor.bounded_path(root, origin)
                   for name, origin in preparation['output_map'].items()}
        # bounded_path resolves paths; separately reject every newly generated link.
        for origin in preparation['output_map'].values():
            checked_root((root / origin).parent, existing=True)
            plain(root / origin)
        scalar = root / STATE / 'scalar-tests.log'
        plain(scalar)
        text = scalar.read_text(encoding='utf-8')
        require(re.search(r'Ran 7 tests in [\d.]+s\s+OK\s*$', text) is not None and
                len(re.findall(r'^test_.* \.\.\. ok$', text, re.M)) == 7,
                'separate scalar seven-method log/count agreement')
        require(platform.system() == 'Linux' and sys.implementation.name == 'cpython' and
                sys.version_info[:3] == (3, 12, 14) and not sys.flags.optimize,
                'collection requires native Linux CPython 3.12.14 with assertions enabled')
        evidence = root / EVIDENCE
        evidence.mkdir()
        evidence_files = {}
        for name, origin in origins.items():
            destination = evidence / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open('xb') as stream:
                stream.write(origin.read_bytes())
            require(auditor.sha(destination) == auditor.sha(origin), 'evidence copy changed')
            evidence_files[destination.relative_to(root).as_posix()] = auditor.sha(destination)
        receipt = dict(schema='fedfence-current-science-receipt-v1',
                       evidence_kind='retained-native-nine-stage-campaign',
                       result_directory=EVIDENCE, execution=EVIDENCE + '/execution.json',
                       evidence_files=evidence_files, **snapshot(root, auditor),
                       fresh_preparation=dict(path=STATE + '/prepare.json', sha256=auditor.sha(manifest)),
                       scope='Fresh generated-output assembly; no execution/source authentication or timing-gain claim.')
        # No positive receipt is written unless every unchanged native check accepts.
        result = auditor.audit(root, receipt)
        verify_inventory(root, preparation['immutable_files'])
        require(all(auditor.sha(origin) == evidence_files[EVIDENCE + '/' + name]
                    for name, origin in origins.items()), 'generated evidence changed during audit')
        write_new(receipt_path, receipt)
        write_new(report_path, result)
        write_new(attempt, dict(passed=True, scalar_methods=7, native_audit=result,
                               receipt=receipt_path.relative_to(root).as_posix()))
        return dict(passed=True, receipt=str(receipt_path), report=str(report_path),
                    evidence_files=len(evidence_files), ordinary_methods=204, scalar_methods=7)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        write_new(attempt, dict(passed=False, error=str(exc),
                               positive_receipt_written=receipt_path.exists()))
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='phase', required=True)
    first = sub.add_parser('prepare')
    first.add_argument('--source', type=Path, default=ROOT)
    first.add_argument('--workdir', type=Path, required=True)
    second = sub.add_parser('collect')
    second.add_argument('--workdir', type=Path, required=True)
    args = parser.parse_args()
    if not args.workdir.is_absolute() or sys.flags.optimize:
        parser.error('workdir must be absolute and assertions enabled')
    try:
        result = prepare(args.source, args.workdir) if args.phase == 'prepare' else collect(args.workdir)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(json.dumps(dict(passed=False, error=str(exc))))
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
