"""Passive audit of a retained nine-stage campaign, not a scientific rerun.

No imports of the implementation, subprocesses, downloads, or source execution.
The ten-stage TOSEM audit remains separate and is not weakened by this audit.
"""
from __future__ import annotations
import argparse
import ast
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path
import re
import statistics

ROOT = Path(__file__).resolve().parents[1]
STEPS = (
    ('unit-tests', ['scripts/run_fse_tests.py']),
    ('core-self-check', ['artifact/scripts/self_check.py']),
    ('projection-audit', ['scripts/run_finite_audit.py']),
    ('relational-audit', ['scripts/run_relational_audit.py']),
    ('two-sided-validation', ['scripts/run_tosem_validation.py']),
    ('character-domain', ['scripts/run_character_domain_audit.py', '--no-paper-table']),
    ('matcher-issuer-globs-scaling', ['scripts/run_final_validation.py']),
    ('repair-audit', ['scripts/run_repair_audit.py']),
    ('source-studies', ['scripts/run_tosem_studies.py']),
)
RECORDS = ('two_sided_exhaustive', 'strict_literal_differential', 'dependency_metamorphic',
           'relational_audit', 'character_domain_audit', 'matcher_differential',
           'issuer_membership_differential', 'strict_glob_differential', 'local_scaling',
           'public_study', 'source_frontier', 'maintenance_metadata', 'studies_summary',
           'validation_summary', 'final_validation_summary', 'two_sided_samples')


def load(path):
    def unique(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise ValueError('duplicate JSON key: ' + key)
            obj[key] = value
        return obj
    return json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=unique,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


def require(condition, detail):
    if not condition:
        raise ValueError(detail)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def bounded_path(root, name):
    path = (root / name).resolve(strict=True)
    require(path.is_relative_to(root.resolve()) and path.is_file(), 'path outside audit root')
    return path


def science_sources(root):
    files = [p for folder in ('artifact/fedfence', 'fse_workflow', 'tests')
             for p in (root / folder).glob('*.py')]
    files += [root / tail[0] for _, tail in STEPS]
    files += [root / 'scripts' / name for name in
              ('run_scientific_checks.py', 'make_workflow_examples.py', 'character_domain_fixtures.py')]
    return {p.relative_to(root).as_posix(): sha(p) for p in sorted(set(files))}


def study_inputs(root):
    return {p.relative_to(root).as_posix(): sha(p) for p in sorted((root / 'study').rglob('*')) if p.is_file()}


def linux_implementation_digest(root):
    # Reconstruct the pathname serialization actually used by the Linux gate.
    h = hashlib.sha256()
    for folder in ('artifact/fedfence', 'fse_workflow'):
        for path in sorted((root / folder).glob('*.py')):
            h.update(path.relative_to(root).as_posix().encode())
            h.update(b'\0')
            h.update(path.read_bytes())
    return h.hexdigest()


def audit(root, receipt, evidence_root=None):
    # Relocation changes storage only, never the original receipt or source bindings.
    root = root.resolve()
    evidence_root = root if evidence_root is None else (root / evidence_root).resolve(strict=True)
    require(evidence_root.is_dir() and evidence_root.is_relative_to(root), 'evidence root outside artifact')
    require(receipt['schema'] == 'fedfence-current-science-receipt-v1', 'receipt schema')
    require(receipt['evidence_kind'] == 'retained-native-nine-stage-campaign', 'evidence kind')
    require(receipt['source_files'] == science_sources(root), 'scientific source bytes changed')
    require(receipt['study_inputs'] == study_inputs(root), 'supplied study bytes changed')
    prefix = receipt['result_directory']
    expected_files = {prefix + '/' + name + '.json' for name in RECORDS}
    expected_files.update(prefix + '/' + name + '.csv' for name in
                          ('strict_literal_differential', 'strict_glob_differential', 'local_scaling', 'public_study'))
    expected_files.update(prefix + '/' + name + '.log' for name, _ in STEPS)
    expected_files.update(prefix + '/' + name for name in
                          ('execution.json', 'unit_tests.json', 'finite_semantics_audit.json', 'repair_audit.json'))
    expected_files.update(prefix + f'/bounded_glob_packets/case-{i:03}.json' for i in range(192))
    require(set(receipt['evidence_files']) == expected_files and receipt['execution'] == prefix + '/execution.json',
            'complete current evidence set')
    if 'fresh_preparation' in receipt:
        item = receipt['fresh_preparation']
        prepared_path = bounded_path(evidence_root, item['path'])
        require(sha(prepared_path) == item['sha256'], 'original fresh preparation bytes')
        prepared = load(prepared_path)
        origins = {}
        for name in expected_files:
            leaf = name[len(prefix) + 1:]
            folder = ('scientific-check-output' if leaf.endswith('.log') or leaf == 'execution.json'
                      else 'fse/results' if leaf in ('unit_tests.json', 'finite_semantics_audit.json')
                      else 'results' if leaf == 'repair_audit.json' else 'tosem/results')
            origins[leaf] = folder + '/' + leaf
        require(prepared['schema'] == 'fedfence-fresh-preparation-v1' and
                all(prepared[k] == receipt[k] for k in ('source_files', 'study_inputs', 'implementation_sha256'))
                and prepared['output_map'] == origins, 'fresh preparation scientific/origin binding')
        # The retained complete support snapshot is historical, not a reseal of edited consumers.
    for name, expected in receipt['evidence_files'].items():
        require(sha(bounded_path(evidence_root, name)) == expected, 'evidence bytes changed: ' + name)
    base = bounded_path(evidence_root, receipt['execution']).parent
    record = load(base / 'execution.json')
    require(record['passed'] is True and len(record['steps']) == 9, 'nine-stage completion')
    require(0 < record['elapsed_seconds'] <= record['whole_seconds'] <= 1200, 'execution budget')
    for row, (name, tail) in zip(record['steps'], STEPS):
        require(row['name'] == name and row['command'][1:] == ['-B', *tail], 'stage identity')
        require(type(row['exit_code']) is int and row['exit_code'] == 0 and
                row['timed_out'] is False and row['seconds'] >= 0, 'stage failure/timeout')
        require((base / (name + '.log')).stat().st_size > 0, 'missing stage log')
    require('3.12.14' in record['python'] and record['platform'].startswith('Linux-'), 'native environment')
    unit = load(base / 'unit_tests.json')
    discovered = sum(sum(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and
                         n.name.startswith('test_') for n in ast.walk(ast.parse(p.read_text(encoding='utf-8'))))
                     for p in (root / 'tests').glob('test_*.py'))
    require(type(unit['tests_run']) is int and unit['tests_run'] == discovered == 204, 'current test count')
    require(unit['passed'] is True and all(type(unit[k]) is int and unit[k] == 0
            for k in ('failures', 'errors', 'skipped')), 'unit failure/error/skip')
    log = (base / 'unit-tests.log').read_text(encoding='utf-8')
    require(re.search(r'Ran 204 tests in [\d.]+s\s+OK\s*$', log) is not None and
            len(re.findall(r'^test_.* \.\.\. ok$', log, re.M)) == 204, 'unit log/count agreement')
    data = {name: load(base / (name + '.json')) for name in RECORDS}
    implementation = linux_implementation_digest(root)
    validation, final, domain = (data[name] for name in
                                ('validation_summary', 'final_validation_summary', 'character_domain_audit'))
    require(final['passed'] is True, 'final validation pass')
    for item in (validation, final, domain):
        reported = item.get('implementation_sha256', item.get('environment', {}).get('implementation_sha256'))
        require(reported == implementation == receipt['implementation_sha256'], 'native implementation binding')
        require(item['network_access'] is False and item['cloud_accounts_used'] is False, 'offline scope')
    require(validation['environment']['python'] == record['python'] and
            validation['environment']['platform'] == record['platform'], 'validation environment')
    require(final['results']['scaling']['environment'] == data['local_scaling']['environment'] and
            data['local_scaling']['environment']['python'] == record['python'] and
            data['local_scaling']['environment']['platform'] == record['platform'], 'timing environment')
    for name, expected in (('finite', 'two_sided_exhaustive'), ('strict', 'strict_literal_differential'),
                           ('metamorphic', 'dependency_metamorphic')):
        require(validation[name] == data[expected] and data[expected]['passed'] is True, 'validation component')
    for name, expected in (('matcher', 'matcher_differential'), ('issuer', 'issuer_membership_differential'),
                           ('strict_glob', 'strict_glob_differential'), ('scaling', 'local_scaling')):
        require(final['results'][name] == data[expected] and data[expected]['passed'] is True, 'final component')
    finite = data['two_sided_exhaustive']
    require(finite['checked'] == 65536 and finite['verdicts'] ==
            {'pass': 4096, 'fail': 3904, 'unknown': 57536} and finite['replay_samples'] == 256, 'finite partition')
    # Direct tuple-set recheck of the retained inspection rows; no implementation execution.
    samples = data['two_sided_samples']
    require(len(samples) == 256 and [s['index'] for s in samples] == list(range(0, 65536, 257)), 'sample selection')
    for sample in samples:
        packet = sample['packet']
        G, A, D, I, Q = (set(map(tuple, packet[name])) for name in
                         ('explicit_issuer', 'allow', 'deny', 'intent', 'required'))
        admitted = G & (A - D)
        status = 'unknown' if packet['invalid'] or not Q <= G & I else 'fail' if admitted - I or Q - admitted else 'pass'
        require(sample['result']['status'] == status and
                set(map(tuple, sample['result']['admitted'])) == admitted, 'finite sample semantics')
    strict = data['strict_literal_differential']
    with (base / 'strict_literal_differential.csv').open(newline='', encoding='utf-8') as stream:
        literal_rows = list(csv.DictReader(stream))
    require(len(literal_rows) == strict['checked'] == 56 and strict['verdicts'] == {'pass': 9, 'fail': 47}, 'literal counts')
    require(all(r['verdict'] == r['expected'] and r['replay_ok'] == 'True' for r in literal_rows), 'literal row disagreement')
    relation = data['relational_audit']
    require(relation['passed'] is True and relation['checks'] == dict(two_sided_realizability=16384,
            governance_restriction=20736, intent_monotonicity=20736, observation_refinement=16384), 'relational counts')
    projection = load(base / 'finite_semantics_audit.json')
    require(projection['passed'] is True and projection['checked_models'] == 65536 and
            bool(projection['incorrect_existential_lifting_counterexample']), 'preserved negative projection example')
    core = (base / 'core-self-check.log').read_text(encoding='utf-8')
    require('self-check passed (3945 bounded and symbolic comparisons)' in core, 'core count')
    require(domain['passed'] is True and domain['character_domain'] == 'python-str-codepoints-v1' and
            domain['partition']['primitive_signature_comparisons'] == 3342336 and
            domain['matcher']['checked'] == 57498 and domain['constructor']['checked'] == 60 and
            domain['integration']['regular_cases'] == 4 and domain['integration']['strict_packets'] == 3 and
            domain['rejection']['challenges'] == 2, 'character-domain counts')
    require(all(r['actual_safe'] == r['expected_safe'] and r['replay_ok'] is True
                for r in domain['integration']['rows']) and
            all(r['verdict'] == r['expected'] and r['receipt_replay_ok'] is True
                for r in domain['integration']['strict_rows']) and
            all(r['control_passed'] is True and r['detected'] is True
                for r in domain['rejection']['rows']), 'character controls')
    require(data['matcher_differential']['checked'] == 242580 and
            data['issuer_membership_differential']['checked'] == 2304, 'matcher/issuer counts')
    globs = data['strict_glob_differential']
    require(globs['checked'] == 192 and globs['verdicts'] == {'pass': 64, 'fail': 128} and
            sha(base / 'strict_glob_differential.csv') == globs['csv_sha256'], 'glob CSV binding')
    with (base / 'strict_glob_differential.csv').open(newline='', encoding='utf-8') as stream:
        rows = list(csv.DictReader(stream))
    require(len(rows) == 192 and Counter(r['verdict'] for r in rows) == globs['verdicts'], 'glob row counts')
    for row in rows:
        packet = load(bounded_path(base, row['packet_file']))
        canonical = json.dumps(packet, sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(',', ':')).encode()
        require(hashlib.sha256(canonical).hexdigest() == row['packet_sha256'] and
                row['verdict'] == row['expected'] and row['replay_ok'] == 'True', 'glob packet/result binding')
    scaling = data['local_scaling']
    require(scaling['recorded_runs'] == 54 and scaling['warmup_runs'] == 18 and
            sha(base / 'local_scaling.csv') == scaling['csv_sha256'], 'current scaling CSV binding')
    with (base / 'local_scaling.csv').open(newline='', encoding='utf-8') as stream:
        timing = list(csv.DictReader(stream))
    require(len(timing) == 54 and len(scaling['summary']) == 18 and
            all(float(r['seconds']) > 0 and r['verdict'] == r['expected'] for r in timing), 'timing rows')
    for row in scaling['summary']:
        values = [float(r['seconds']) for r in timing if int(r['required_tokens']) == row['required_tokens'] and r['task'] == row['task']]
        require(len(values) == row['repetitions'] == 3 and row['median_seconds'] == statistics.median(values) and
                row['min_seconds'] == min(values) and row['max_seconds'] == max(values), 'timing summary')
    studies = data['studies_summary']
    require(studies == {k: data[v]['summary'] for k, v in
            (('public', 'public_study'), ('frontier', 'source_frontier'), ('maintenance', 'maintenance_metadata'))}, 'study summary agreement')
    public, frontier, maintenance = (studies[k] for k in ('public', 'frontier', 'maintenance'))
    require((public['commits'], public['role_contracts'], public['evaluations']) == (9, 10, 21) and
            public['verdicts'] == {'pass': 10, 'fail': 10, 'unknown': 1} and
            not any(public[k] for k in ('source_authenticity_verified', 'owner_confirmed', 'independent_accuracy_measure', 'cloud_validation')), 'public units/limits')
    require(public['verified_patch_digests'] == 9 and public['safety_or_full_study_replay_checks'] == 21 and
            all(r['result']['replay_ok'] is True for r in data['public_study']['rows']), 'public replay counts')
    for source in data['public_study']['sources']:
        require(sha(bounded_path(root, source['path'])) == source['sha256'] and
                source['digest_verified'] is True and source['source_authenticity_verified'] is False,
                'supplied patch binding')
    require((frontier['records'], frontier['full_source_files'], frontier['executed_extractions']) == (24, 0, 0) and
            (maintenance['records'], maintenance['reports_annotated_breakage'], maintenance['records_with_success_run_id'], maintenance['live_workflows_run']) == (12, 11, 2, 0), 'source/maintenance units')
    repair = load(base / 'repair_audit.json')
    require(repair['status'] == 'pass' and repair['issuer_contract']['checks'] == 7 and
            repair['issuer_contract']['status'] == 'pass', 'repair count')
    return dict(passed=True, tests_run=204, stages=9, core_comparisons=3945, projection_models=65536,
                finite_decisions=65536, finite_inspection_rows_rechecked=256, strict_literal_cases=56,
                character_predicate_comparisons=3342336, quotient_pairs=57498, constructor_checks=60,
                matcher_pairs=242580, issuer_checks=2304, strict_glob_cases=192,
                current_timed_runs=54, current_warmups=18, current_timing_summary_cells=18,
                public_commits=9, role_contracts=10, configurations=21, excerpts=24,
                full_source_extractions=0, metadata_records=12, live_workflows=0,
                implementation_sha256=implementation, source_files=len(receipt['source_files']),
                evidence_files=len(receipt['evidence_files']), supplied_study_files=len(receipt['study_inputs']),
                python=record['python'], platform=record['platform'],
                elapsed_seconds=record['elapsed_seconds'],
                scope='Passive source/output/count consistency audit of the retained native nine-stage run; not a new scientific run, proof verification, ten-stage reproduction, or provider authentication.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--receipt', type=Path, default=ROOT / 'tosem/results/current_science_receipt.json')
    parser.add_argument('--evidence-root', type=Path, default=ROOT,
                        help='storage root beneath artifact for an unmodified relocated receipt')
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    try:
        receipt_path = args.receipt if args.receipt.is_absolute() else ROOT / args.receipt
        result = audit(ROOT, load(receipt_path), args.evidence_root)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        result = dict(passed=False, error=str(exc))
    if args.report:
        # Never overwrite an earlier attempt or create a successful-looking old report.
        with args.report.open('x', encoding='utf-8') as stream:
            json.dump(result, stream, indent=2)
            stream.write('\n')
    print(json.dumps(result, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
