"""Bounded build-entrypoint regressions; no scientific campaign is executed."""
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ARTIFACT = Path(__file__).resolve().parents[1]
PAPER = ARTIFACT.parent / "paper"


class BuildEntrypointTests(unittest.TestCase):
    def test_alias_forwards_arguments_and_exit_code(self):
        current = Mock(return_value=17)
        with patch.dict(sys.modules, {"reproduce_tosem": SimpleNamespace(main=current)}):
            alias = runpy.run_path(str(ARTIFACT / "scripts/reproduce.py"))
            self.assertEqual(alias["main"](["--paper"]), 17)
        current.assert_called_once_with(["--paper"])

    def test_retired_helper_does_not_create_results(self):
        path = ARTIFACT / "results/public_change_study.json"
        before = path.read_bytes() if path.exists() else None
        helper = runpy.run_path(str(ARTIFACT / "scripts/build_public_study_result.py"))
        with self.assertRaisesRegex(SystemExit, "Retired:"):
            helper["main"]()
        self.assertEqual(path.read_bytes() if path.exists() else None, before)

    @unittest.skipUnless(PAPER.is_dir(), "Requires the companion paper folder")
    def test_status_query_never_reseals_record(self):
        path = ARTIFACT / "paper_support/build_environment.json"
        before = path.read_bytes()
        recorder = runpy.run_path(str(ARTIFACT / "paper_support/record_build_environment.py"))
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(recorder["main"]([]), 0)
        actual = json.loads(output.getvalue())
        self.assertEqual(actual["status_pdf_matches_record"],
                         actual["pdf_sha256"] == recorder["sha"](PAPER / "FedFence_TOSEM.pdf"))
        self.assertEqual(path.read_bytes(), before)

    @unittest.skipUnless(PAPER.is_dir(), "Requires the companion paper folder")
    def test_failed_native_build_preserves_record_and_registered_pdf(self):
        recorder = runpy.run_path(str(ARTIFACT / "paper_support/record_build_environment.py"))
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            record, pdf = folder / "build_environment.json", folder / "FedFence_TOSEM.pdf"
            record.write_bytes(b"retained record")
            pdf.write_bytes(b"retained pdf")
            globals_ = recorder["build"].__globals__
            with patch.dict(globals_, {"SUPPORT": folder, "RECORD": record}), \
                    patch.object(subprocess, "run", side_effect=[
                        SimpleNamespace(returncode=0),
                        subprocess.CalledProcessError(1, ["latexmk"])]):
                with self.assertRaises(subprocess.CalledProcessError):
                    recorder["build"](pdf, "latexmk")
            self.assertEqual(record.read_bytes(), b"retained record")
            self.assertEqual(pdf.read_bytes(), b"retained pdf")

    @unittest.skipUnless(PAPER.is_dir(), "Requires the companion paper folder")
    def test_make_connects_raw_data_tables_and_producer(self):
        make = (PAPER / "Makefile").read_text(encoding="utf-8")
        for name in ("local_scaling.csv", "local_scaling.json", "generated/tables.tex",
                     "generated/scaling_rows.tex", "../artifact/plots/libertine-labels.afm",
                     "../artifact/plots/draw_local_costs.py", "--build --latexmk"):
            self.assertIn(name, make)
        self.assertIn("figures/local-costs.pdf: FORCE $(SCALING_INPUTS) $(SCALING_TABLES)", make)
        self.assertIn("figures: figures/local-costs.pdf", make)

    @unittest.skipUnless(PAPER.is_dir(), "Requires the companion paper folder")
    def test_stale_table_rows_are_rejected_before_drawing(self):
        wrapper = runpy.run_path(str(PAPER / "figures/draw_local_costs.py"))
        producer = wrapper["load_producer"]()
        tables = producer["load_scaling"](ARTIFACT / "tosem/results")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            generated = root / "generated"
            generated.mkdir()
            for name, rows in tables.items():
                (generated / name).write_text(
                    producer["dat_text"](rows, ("n", "median", "lower", "upper")),
                    encoding="utf-8")
            (generated / "scaling_rows.tex").write_text("stale rows\n", encoding="utf-8")
            (generated / "tables.tex").write_text("stale rows\n", encoding="utf-8")
            with patch.dict(wrapper["selected_tables"].__globals__, {"PAPER": root}):
                with self.assertRaisesRegex(ValueError, "Stale Table 9"):
                    wrapper["selected_tables"](producer)


if __name__ == "__main__":
    unittest.main(verbosity=2)
