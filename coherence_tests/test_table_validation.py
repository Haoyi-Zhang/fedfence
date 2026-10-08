"""Passive table-consumer regressions; writes stay in owned temporary fixtures.

No scientific implementation, provider, campaign or ordinary-suite execution.
Source copies are parsed only to preserve the selected unit-record denominator.
"""
from contextlib import redirect_stdout
import copy
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import audit_current_science as evidence
import generate_tosem_tables as tables

RECORDS = ('unit_tests', 'two_sided_exhaustive', 'strict_literal_differential',
           'relational_audit', 'public_study', 'source_frontier', 'maintenance_metadata',
           'finite_semantics_audit', 'matcher_differential', 'issuer_membership_differential',
           'strict_glob_differential', 'local_scaling', 'character_domain_audit', 'core_self_check')


class TableValidation(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory(prefix='p113-table-validation-')
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / 'artifact'
        names = ['tosem/results/' + name + '.json' for name in RECORDS]
        names += ['tosem/results/' + name + '.csv' for name in
                  ('local_scaling', 'strict_literal_differential', 'strict_glob_differential')]
        names += [p.relative_to(ROOT).as_posix() for p in (ROOT / 'tests').glob('test_*.py')]
        names += ['scripts/audit_current_science.py', 'scripts/generate_tosem_tables.py']
        for name in names:
            destination = root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, destination)
        return root

    def mutate(self, root, name, edit):
        path = root / 'tosem/results' / (name + '.json')
        value = evidence.load(path)
        edit(value)
        path.write_text(json.dumps(value, allow_nan=False), encoding='utf-8')

    def assert_rejected(self, root, message, cli=False):
        with self.assertRaisesRegex(ValueError, message):
            tables.generate(root)
        out = root.parent / 'generated'
        out.mkdir(exist_ok=True)
        sentinel = out / 'relational_rows.tex'
        sentinel.write_text('owned pre-existing output\n', encoding='utf-8')
        before = {p.name: p.read_bytes() for p in out.iterdir()}
        for check in (False, True):
            stdout = io.StringIO()
            args = ['--out', str(out)] + (['--check'] if check else [])
            with patch.object(tables, 'ROOT', root), redirect_stdout(stdout):
                with self.assertRaisesRegex(ValueError, message):
                    tables.main(args)
            self.assertEqual('', stdout.getvalue())
            self.assertEqual(before, {p.name: p.read_bytes() for p in out.iterdir()})
            self.assertNotIn('No counterexample', sentinel.read_text(encoding='utf-8'))
            if cli:
                result = subprocess.run([sys.executable, '-B',
                                         str(root / 'scripts/generate_tosem_tables.py'), *args],
                                        cwd=root, capture_output=True, text=True, timeout=15)
                self.assertNotEqual(0, result.returncode)
                self.assertRegex(result.stderr, message)
                self.assertEqual('', result.stdout)
                self.assertEqual(before, {p.name: p.read_bytes() for p in out.iterdir()})

    def test_current_selected_records_accepted(self):
        actual = tables.generate(ROOT)
        root = self.fixture()
        self.assertEqual(actual, tables.generate(root))
        self.assertEqual(10, len(actual))
        self.assertEqual(204, json.loads(actual['generation.json'])['macros']['TestCount'])
        self.assertEqual(4, actual['relational_rows.tex'].count('No counterexample'))
        out = root.parent / 'generated'
        with patch.object(tables, 'ROOT', root), redirect_stdout(io.StringIO()):
            self.assertEqual(0, tables.main(['--out', str(out), '--check']))
            self.assertFalse(out.exists())
            self.assertEqual(0, tables.main(['--out', str(out)]))
        self.assertEqual(set(actual), {p.name for p in out.iterdir()})
        for name, value in actual.items():
            self.assertEqual(value, (out / name).read_text(encoding='utf-8'))

    def test_relational_failed_same_counts_rejected(self):
        root = self.fixture()
        before = evidence.load(root / 'tosem/results/relational_audit.json')
        self.mutate(root, 'relational_audit', lambda r: r.update(passed=False))
        after = evidence.load(root / 'tosem/results/relational_audit.json')
        self.assertEqual(before['checks'], after['checks'])
        self.assert_rejected(root, 'relational_audit.*passed', cli=True)

    def test_unit_failures_same_count_rejected(self):
        root = self.fixture()
        self.mutate(root, 'unit_tests', lambda r: r.update(failures=1))
        unit = evidence.load(root / 'tosem/results/unit_tests.json')
        self.assertEqual(204, unit['tests_run'])
        self.assertIs(True, unit['passed'])
        self.assert_rejected(root, 'unit failure/error/skip', cli=True)

    def test_unit_errors_skips_and_failed_state_rejected(self):
        for field, value, message in (('errors', 1, 'unit failure/error/skip'),
                                      ('skipped', 1, 'unit failure/error/skip'),
                                      ('passed', False, 'unit_tests.*passed')):
            with self.subTest(field=field):
                root = self.fixture()
                self.mutate(root, 'unit_tests', lambda r: r.update({field: value}))
                self.assert_rejected(root, message)

    def test_all_selected_audit_success_states_rejected(self):
        names = set(RECORDS) - {'unit_tests', 'relational_audit', 'public_study',
                                'source_frontier', 'maintenance_metadata'}
        for name in sorted(names):
            with self.subTest(record=name):
                root = self.fixture()
                self.mutate(root, name, lambda r: r.update(passed=False))
                self.assert_rejected(root, name + '.*passed')

    def test_supported_schema_and_legacy_shapes(self):
        for name in RECORDS:
            with self.subTest(record=name):
                root = self.fixture()
                self.mutate(root, name, lambda r: r.update(schema='unsupported-fixture-v999'))
                self.assert_rejected(root, name + '.*schema')

    def test_missing_versioned_schema_and_nonboolean_success_rejected(self):
        for edit, message in ((lambda r: r.pop('schema'), 'relational_audit.*schema'),
                              (lambda r: r.update(passed=1), 'relational_audit.*passed')):
            with self.subTest(message=message):
                root = self.fixture()
                self.mutate(root, 'relational_audit', edit)
                self.assert_rejected(root, message)

    def test_legacy_fallback_and_optional_core_preserved(self):
        root = self.fixture()
        expected = tables.generate(root)
        fallback = root / 'fse/results'
        fallback.mkdir(parents=True)
        for name in ('unit_tests.json', 'finite_semantics_audit.json'):
            (root / 'tosem/results' / name).replace(fallback / name)
        self.assertEqual(expected, tables.generate(root))
        (root / 'tosem/results/core_self_check.json').unlink()
        outputs = tables.generate(root)
        self.assertNotIn('CoreComparisons', json.loads(outputs['generation.json'])['macros'])

    def test_count_and_verdict_consistency_rejected(self):
        cases = (
            ('two_sided_exhaustive', lambda r: r['verdicts'].update(unknown=r['verdicts']['unknown'] + 1)),
            ('strict_literal_differential', lambda r: r['verdicts'].update({'pass': 10, 'fail': 46})),
            ('strict_glob_differential', lambda r: r['verdicts'].update({'pass': 65, 'fail': 127})),
            ('relational_audit', lambda r: r['checks'].update(two_sided_realizability=16385)),
            ('matcher_differential', lambda r: r.update(matching_pairs=r['matching_pairs'] + 1)),
            ('issuer_membership_differential', lambda r: r.update(accepted=r['accepted'] + 1)),
            ('public_study', lambda r: r['summary']['verdicts'].update({'pass': 11, 'fail': 9})),
            ('source_frontier', lambda r: r['summary']['annotation_counts'].update(literal_source_policy=6)),
            ('maintenance_metadata', lambda r: r['summary'].update(records_with_success_run_id=3)),
        )
        for name, edit in cases:
            with self.subTest(record=name):
                root = self.fixture()
                self.mutate(root, name, edit)
                self.assert_rejected(root, name)

    def test_character_domain_nested_failure_rejected(self):
        root = self.fixture()
        self.mutate(root, 'character_domain_audit', lambda r: r['matcher'].update(passed=False))
        self.assert_rejected(root, 'character_domain_audit')

    def test_no_new_study_success_or_all_pass_requirement(self):
        root = self.fixture()
        public = evidence.load(root / 'tosem/results/public_study.json')
        self.assertNotIn('passed', public)
        self.assertEqual({'pass', 'fail', 'unknown'}, set(public['summary']['verdicts']))
        self.assertEqual(tables.generate(ROOT), tables.generate(root))

    def test_current_receipt_records_still_accepted(self):
        storage = Path('tosem/results/native-science')
        receipt = storage / '_fresh-science/current-science-receipt.json'
        recorded = evidence.load(ROOT / receipt)
        audited = evidence.audit(ROOT, recorded, storage)
        self.assertIs(True, audited['passed'])
        outputs = tables.generate(ROOT, receipt, storage)
        self.assertEqual(10, len(outputs))
        self.assertEqual(204, json.loads(outputs['generation.json'])['macros']['TestCount'])
        with tempfile.TemporaryDirectory(prefix='p113-receipt-check-') as temporary:
            out = Path(temporary) / 'generated'
            with redirect_stdout(io.StringIO()):
                self.assertEqual(0, tables.main(['--current-receipt', str(receipt),
                                               '--evidence-root', str(storage),
                                               '--out', str(out), '--check']))
            self.assertFalse(out.exists())

    def test_shared_validation_rejects_failed_receipt_records(self):
        storage = Path('tosem/results/native-science')
        receipt_path = storage / '_fresh-science/current-science-receipt.json'
        receipt = evidence.load(ROOT / receipt_path)
        original_load = evidence.load
        for name, change, message in (('relational_audit', {'passed': False}, 'relational_audit.*passed'),
                                      ('unit_tests', {'failures': 1}, 'unit failure/error/skip')):
            with self.subTest(record=name):
                selected = (ROOT / storage / receipt['result_directory'] / (name + '.json')).resolve()

                def failed_record(path):
                    value = original_load(path)
                    if Path(path).resolve() == selected:
                        value = copy.deepcopy(value)
                        value.update(change)
                    return value

                # In-memory negative records only: never rewrite or reseal retained evidence.
                with patch.object(evidence, 'load', side_effect=failed_record):
                    with self.assertRaisesRegex(ValueError, message):
                        evidence.audit(ROOT, receipt, storage)
                    with self.assertRaisesRegex(ValueError, message):
                        tables.generate(ROOT, receipt_path, storage)
                    with tempfile.TemporaryDirectory(prefix='p113-failed-receipt-') as temporary:
                        out = Path(temporary) / 'generated'
                        for check in (False, True):
                            args = ['--current-receipt', str(receipt_path), '--evidence-root',
                                    str(storage), '--out', str(out)] + (['--check'] if check else [])
                            with redirect_stdout(io.StringIO()), self.assertRaisesRegex(ValueError, message):
                                tables.main(args)
                            self.assertFalse(out.exists())


if __name__ == '__main__':
    unittest.main()
