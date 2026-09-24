from __future__ import annotations
import unittest
from pathlib import Path

from fse_workflow.io import load_json
from fse_workflow.public_changes import analyze_corpus

ROOT = Path(__file__).resolve().parents[1]


class PublicChangeCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = analyze_corpus(load_json(ROOT / "study" / "public_change_corpus.json"))

    def test_all_sources_are_distinct_real_commits(self):
        rows = self.result["changes"]
        self.assertEqual(9, len(rows))
        self.assertEqual(9, len({(row["repository"], row["commit"]) for row in rows}))

    def test_source_stated_outcomes(self):
        self.assertEqual(9, self.result["summary"]["source_aligned"])
        self.assertEqual(9, self.result["summary"]["source_snapshots_verified"])
        self.assertTrue(all(row["source_snapshot_verified"] for row in self.result["changes"]))
        self.assertEqual({"fail->pass": 8, "fail->unknown": 1}, self.result["summary"]["transition_counts"])

    def test_baseline_accounting(self):
        summary = self.result["summary"]
        self.assertEqual({"aligned": 18, "total": 18}, summary["fedfence_phase_alignment"])
        self.assertEqual({"aligned": 9, "total": 17}, summary["baseline_alignment"]["presence"])
        self.assertEqual({"aligned": 12, "total": 17}, summary["baseline_alignment"]["wildcard_ban"])
        self.assertEqual({"aligned": 12, "total": 17}, summary["baseline_alignment"]["exact_ref_only"])

    def test_no_external_accuracy_overclaim(self):
        summary = self.result["summary"]
        self.assertEqual(0, summary["owner_confirmed"])
        self.assertEqual(0, summary["independently_adjudicated"])
        self.assertFalse(summary["prevalence_claim"])
        self.assertFalse(summary["accuracy_claim"])

    def test_environment_case_requires_governance(self):
        row = next(row for row in self.result["changes"] if row["id"] == "michele-environment-cut")
        self.assertEqual("unknown", row["after"]["verdict"])
        self.assertTrue(any(f["kind"] == "unprotected-environment" for f in row["after"]["findings"]))

    def test_simple_baselines_do_not_model_same_property(self):
        row = next(row for row in self.result["changes"] if row["id"] == "shadow-release-branches")
        self.assertEqual("pass", row["after"]["verdict"])
        self.assertEqual("fail", row["after"]["baselines"]["wildcard_ban"])
        row2 = next(row for row in self.result["changes"] if row["id"] == "arriagada-main-branch")
        self.assertEqual("pass", row2["before"]["baselines"]["presence"])
        self.assertEqual("fail", row2["before"]["verdict"])

    def test_compatibility_repair_uses_positive_obligation(self):
        row = next(row for row in self.result["changes"] if row["id"] == "microticket-immutable-compatibility")
        self.assertEqual("fail", row["before"]["verdict"])
        self.assertTrue(row["before"]["safe_boolean"])
        self.assertEqual(1, len(row["before"]["required_token_checks"]["missing"]))
        self.assertEqual("pass", row["after"]["verdict"])
        self.assertEqual(1, row["after"]["required_token_checks"]["satisfied"])

    def test_screening_and_change_kinds_are_explicit(self):
        summary = self.result["summary"]
        self.assertEqual({"security-hardening": 7, "cross-plane-hardening": 1, "compatibility-repair": 1}, summary["change_kinds"])
        self.assertEqual({"declared": 1, "satisfied_after": 1}, summary["required_tokens"])
        self.assertEqual(17, self.result["selection"]["candidates_screened"])


if __name__ == "__main__":
    unittest.main()
