"""Passive current-evidence consumers: no scientific driver or implementation imports."""
from pathlib import Path
import copy
import json
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts'))
import audit_current_science as audit
import generate_tosem_tables as tables
import assemble_fresh_science as assembler

STORAGE = Path('tosem/results/native-science')
RECEIPT = STORAGE/'_fresh-science/current-science-receipt.json'


class EvidenceConsumers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.receipt = audit.load(ROOT/RECEIPT)

    def fixture(self):
        # Only supplied passive inputs are copied. Never copy/run a gate or policy command.
        temporary = tempfile.TemporaryDirectory(prefix='p113-consumer-')
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)/'artifact'
        names = set(self.receipt['source_files']) | set(self.receipt['study_inputs'])
        public = audit.load(ROOT/STORAGE/self.receipt['result_directory']/'public_study.json')
        names.update(s['path'] for s in public['sources'])
        names.update(('tosem/results/local_scaling.json', 'tosem/results/local_scaling.csv'))
        names.update('scripts/'+name for name in ('audit_current_science.py', 'generate_tosem_tables.py',
                                                  'assemble_fresh_science.py'))
        names.update(p.relative_to(ROOT).as_posix() for p in (ROOT/STORAGE).rglob('*') if p.is_file())
        for name in names:
            destination = root/name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT/name, destination)
        return root

    def rejected_without_writes(self, root):
        out = root.parent/'generated'
        out.mkdir()
        for name in tables.generate(ROOT, RECEIPT, STORAGE):
            (out/name).write_bytes(b'pre-existing owned output\n')
        before = {p.name: p.read_bytes() for p in out.iterdir()}
        with patch.object(tables, 'ROOT', root), self.assertRaises((ValueError, OSError, KeyError)):
            tables.main(['--current-receipt', str(RECEIPT), '--evidence-root', str(STORAGE), '--out', str(out)])
        self.assertEqual(before, {p.name: p.read_bytes() for p in out.iterdir()})

    def test_actual_relocated_225_and_native_sidecar_agree(self):
        actual = audit.audit(ROOT, self.receipt, STORAGE)
        self.assertEqual(actual, audit.load(ROOT/STORAGE/'_fresh-science/native-audit.json'))
        self.assertEqual((actual['tests_run'], actual['stages'], actual['evidence_files']), (204, 9, 225))

    def test_actual_tables_and_recorded_identity(self):
        outputs = tables.generate(ROOT, RECEIPT, STORAGE)
        metadata = json.loads(outputs['generation.json'])
        self.assertEqual(len(outputs), 10)
        self.assertEqual(metadata['macros']['TestCount'], 204)
        self.assertEqual(metadata['native_run']['run_id'], 37670050420)
        self.assertEqual(metadata['native_run']['head'], '07258c854b9136504952d2b842866074500847bf')
        self.assertEqual(metadata['current_science_receipt_sha256'], audit.sha(ROOT/RECEIPT))
        self.assertEqual(metadata['source'], 'artifact/tosem/results/native-science/fresh-native-evidence')
        self.assertEqual(metadata['native_run']['stages'], 9)
        historical = audit.load(ROOT/'tosem/results/local_scaling.json')
        tables.validate_scaling(ROOT/'tosem/results', historical)
        self.assertEqual(json.loads(outputs['plot_provenance.json'])['csv_sha256'], historical['csv_sha256'])

    def test_historical_default_cannot_claim_current_204(self):
        # Genuine root evidence is now current; stale evidence is an explicit
        # in-memory negative fixture, never an assumption about delivered data.
        outputs = tables.generate(ROOT)
        self.assertEqual(json.loads(outputs['generation.json'])['macros']['TestCount'], 204)
        unit_record = (ROOT/'tosem/results/unit_tests.json').resolve()
        original_load = tables.strict_load

        def stale_unit_record(path):
            value = original_load(path)
            if Path(path).resolve() == unit_record:
                value = copy.deepcopy(value)
                value['tests_run'] = 194
            return value

        with patch.object(tables, 'strict_load', side_effect=stale_unit_record):
            with self.assertRaisesRegex(ValueError, 'unit-test record is stale'):
                tables.generate(ROOT)

    def test_evidence_tamper_rejected(self):
        root = self.fixture()
        packet = root/STORAGE/self.receipt['result_directory']/'bounded_glob_packets/case-000.json'
        packet.write_bytes(packet.read_bytes()+b'\n')
        self.rejected_without_writes(root)

    def test_preparation_bytes_rejected(self):
        root = self.fixture()
        path = root/STORAGE/'_fresh-science/prepare.json'
        path.write_bytes(path.read_bytes()+b'\n')
        self.rejected_without_writes(root)

    def test_manufactured_wrong_origin_map_rejected(self):
        # A synthetic in-memory receipt/temporary manifest tests the origin guard;
        # neither original receipt nor supplied output is rewritten or resealed.
        root = self.fixture()
        path = root/STORAGE/'_fresh-science/prepare.json'
        prepared = audit.load(path)
        prepared['output_map']['unit_tests.json'] = 'tosem/results/unit_tests.json'
        path.write_text(json.dumps(prepared), encoding='utf-8')
        receipt = copy.deepcopy(self.receipt)
        receipt['fresh_preparation']['sha256'] = audit.sha(path)
        with self.assertRaisesRegex(ValueError, 'origin binding'):
            audit.audit(root, receipt, STORAGE)

    def test_historical_csv_tamper_before_any_writes(self):
        root = self.fixture()
        path = root/'tosem/results/local_scaling.csv'
        path.write_bytes(path.read_bytes()+b'\n')
        self.rejected_without_writes(root)

    def test_late_historical_summary_before_any_writes(self):
        root = self.fixture()
        path = root/'tosem/results/local_scaling.json'
        value = audit.load(path)
        value['summary'][-1]['median_seconds'] += 1
        path.write_text(json.dumps(value), encoding='utf-8')
        self.rejected_without_writes(root)

    def test_invalid_ci_identity_before_any_writes(self):
        root = self.fixture()
        path = root/STORAGE/'_fresh-science/ci-identity.json'
        value = audit.load(path)
        value['GITHUB_SHA'] = 'not-a-commit'
        path.write_text(json.dumps(value), encoding='utf-8')
        self.rejected_without_writes(root)

    def test_no_ci_identity_does_not_invent_one(self):
        audited = audit.audit(ROOT, self.receipt, STORAGE)
        # Path has no adjacent CI sidecar; no file mutation is needed.
        value = tables.run_metadata(ROOT, self.receipt, ROOT/'local-only-receipt.json', ROOT/STORAGE, audited)
        self.assertNotIn('run_id', value)
        self.assertNotIn('head', value)
        self.assertIn('identity_authority', value)

    def test_check_writes_nothing_and_success_writes_all(self):
        with tempfile.TemporaryDirectory(prefix='p113-output-') as temporary:
            out = Path(temporary)/'generated'
            args = ['--current-receipt', str(RECEIPT), '--evidence-root', str(STORAGE), '--out', str(out)]
            self.assertEqual(tables.main(args+['--check']), 0)
            self.assertFalse(out.exists())
            self.assertEqual(tables.main(args), 0)
            expected = tables.generate(ROOT, RECEIPT, STORAGE)
            self.assertEqual(set(expected), {p.name for p in out.iterdir()})
            for name, value in expected.items():
                self.assertEqual((out/name).read_text(encoding='utf-8'), value)

    def test_storage_bounds_and_declared_exclusion(self):
        with self.assertRaisesRegex(ValueError, 'outside artifact'):
            audit.audit(ROOT, self.receipt, ROOT.parent)
        # Use the same owned short-path fixture on Windows; long historical
        # reference filenames are unrelated to this generated-exclusion check.
        names = assembler.inventory(self.fixture())
        self.assertFalse(any(n.startswith(STORAGE.as_posix()+'/') for n in names))
        self.assertTrue(assembler.below(STORAGE.as_posix(), assembler.GENERATED))
        self.assertIn('scripts/audit_current_science.py', names)
        self.assertEqual(audit.science_sources(ROOT), self.receipt['source_files'])


if __name__ == '__main__':
    unittest.main()
