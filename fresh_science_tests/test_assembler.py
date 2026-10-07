"""Portable assembler guards only; never run a gate or fabricate science outputs.

All fixture/copy outputs are kept under an explicit new --out directory.
The unchanged ordinary 204 methods and scalar seven methods remain separate.
"""
from __future__ import annotations
import argparse
import ast
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('fresh_assembler', ROOT / 'scripts/assemble_fresh_science.py')
assembler = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(assembler)
OUT = None


class AssemblerGuards(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.actual = OUT / 'n'
        cls.prepared = assembler.prepare(ROOT, cls.actual)
        cls.auditor = assembler.passive_auditor(ROOT)

    def fixture(self, name):
        folder = OUT / name
        folder.mkdir()
        for filename in ('source.txt', 'study/kept.txt', 'artifact/results/retained.txt',
                         'artifact/reference_results/retained.txt',
                         'tosem/results/old.txt', 'fse/results/old.txt', 'results/old.txt',
                         'scientific-check-output/old.log', 'scalar-regression-output/old.log',
                         '__pycache__/old.pyc'):
            path = folder / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('owned inert copy-guard fixture: ' + filename, encoding='utf-8')
        return folder

    def test_01_exact_225_origin_mapping(self):
        files = assembler.output_map(self.auditor)
        self.assertEqual(225, len(files))
        self.assertEqual(192, sum(name.startswith('bounded_glob_packets/') for name in files))
        self.assertEqual('fse/results/unit_tests.json', files['unit_tests.json'])
        self.assertEqual('fse/results/finite_semantics_audit.json', files['finite_semantics_audit.json'])
        self.assertEqual('results/repair_audit.json', files['repair_audit.json'])
        self.assertEqual('scientific-check-output/execution.json', files['execution.json'])
        self.assertTrue(all(assembler.below(origin, assembler.GENERATED) for origin in files.values()))

    def test_02_omit_only_outer_generated_roots(self):
        source = self.fixture('copy-source')
        destination = OUT / 'copy-destination'
        wanted = assembler.inventory(source)
        self.assertEqual({'source.txt', 'study/kept.txt', 'artifact/results/retained.txt',
                          'artifact/reference_results/retained.txt'}, set(wanted))
        self.assertEqual(wanted, assembler.copy_fresh(source, destination))
        self.assertEqual(wanted, assembler.inventory(source))
        self.assertTrue((source / 'tosem/results/old.txt').is_file())
        self.assertTrue(all(not (destination / name).exists() for name in assembler.GENERATED))

    def test_03_existing_and_nested_paths_refused(self):
        source = self.fixture('path-source')
        with self.assertRaisesRegex(ValueError, 'already exists'):
            assembler.copy_fresh(source, source)
        with self.assertRaisesRegex(ValueError, 'not nested'):
            assembler.copy_fresh(source, source / 'nested')
        self.assertFalse((source / 'nested').exists())
        with self.assertRaisesRegex(ValueError, 'already exists'):
            assembler.copy_fresh(source, OUT)

    def test_04_immutable_drift_and_additions_rejected(self):
        source = self.fixture('drift-source')
        expected = assembler.inventory(source)
        (source / 'source.txt').write_text('owned changed bytes', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'bytes changed'):
            assembler.verify_inventory(source, expected)
        expected = assembler.inventory(source)
        (source / 'added.txt').write_text('owned added input', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'bytes changed'):
            assembler.verify_inventory(source, expected)

    def test_05_reserved_campaign_source_refused(self):
        source = self.fixture('reserved-source')
        (source / assembler.STATE).mkdir()
        with self.assertRaisesRegex(ValueError, 'already contains'):
            assembler.copy_fresh(source, OUT / 'reserved-destination')
        self.assertFalse((OUT / 'reserved-destination').exists())

    def test_06_real_preparation_has_absent_outputs_and_exact_bindings(self):
        self.assertTrue(self.prepared['prepared'])
        record = self.auditor.load(self.actual / assembler.STATE / 'prepare.json')
        self.assertEqual(self.auditor.science_sources(ROOT), record['source_files'])
        self.assertEqual(self.auditor.study_inputs(ROOT), record['study_inputs'])
        self.assertEqual(assembler.inventory(ROOT), record['immutable_files'])
        self.assertTrue(all(not (self.actual / name).exists() for name in assembler.GENERATED))
        self.assertFalse((self.actual / assembler.STATE / 'current-science-receipt.json').exists())

    def test_07_unrun_collection_fails_without_positive_receipt(self):
        with self.assertRaises(OSError):
            assembler.collect(self.actual)
        attempt = self.auditor.load(self.actual / assembler.STATE / 'assembly-attempt.json')
        self.assertFalse(attempt['passed'])
        self.assertFalse(attempt['positive_receipt_written'])
        self.assertFalse((self.actual / assembler.STATE / 'current-science-receipt.json').exists())
        with self.assertRaisesRegex(ValueError, 'already attempted'):
            assembler.collect(self.actual)

    def test_08_ordinary_204_and_nine_stages_not_rewritten(self):
        count = sum(sum(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and
                        n.name.startswith('test_') for n in ast.walk(ast.parse(p.read_text(encoding='utf-8'))))
                    for p in (ROOT / 'tests').glob('test_*.py'))
        self.assertEqual(204, count)
        self.assertEqual(9, len(self.auditor.STEPS))
        self.assertNotIn('scalar_tests', ''.join(tail[0] for _, tail in self.auditor.STEPS))
        driver = (ROOT / 'scripts/run_scientific_checks.py').read_text(encoding='utf-8')
        for _, tail in self.auditor.STEPS:
            self.assertIn(tail[0], driver)


def main():
    global OUT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('-v', '--verbose', action='store_true')
    args = parser.parse_args()
    OUT = assembler.checked_root(args.out, existing=False)
    if OUT.exists() or OUT.is_relative_to(ROOT) or ROOT.is_relative_to(OUT):
        parser.error('--out must be new and disjoint from the artifact directory')
    OUT.mkdir()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(AssemblerGuards)
    result = unittest.TextTestRunner(verbosity=2 if args.verbose else 1).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
