"""Separate local guards: these methods are not part of the historical 204."""
from copy import deepcopy
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "artifact"))
from fedfence.iac import extract_file
from fedfence.repair import synthesize_repair
from fse_workflow.fragment import PREFIX
from fse_workflow.io import load_json, save_json
from owned_demo.release_bundle import publish, OPERATIONS
from scripts.run_owned_release_demo import (FIXTURES, direct_trust_relation,
                                           verify_bundle, workflow_contract)


class OwnedReleaseTests(unittest.TestCase):
    def setUp(self):
        self.workflow = load_json(FIXTURES / "workflow.json")
        self.contract, self.required, self.allowed = workflow_contract(self.workflow)
        self.case = extract_file(FIXTURES / "source.tf.json")[0].case
        repaired, _ = synthesize_repair(self.case)
        self.policy = {"trust": repaired["policy"], "permissions": self.allowed}
        self.tokens = [{"sub": t["sub"], "aud": t["aud"]} for t in self.contract["required_tokens"]]

    def work(self, directory):
        root = Path(directory)
        (root / "input").mkdir()
        (root / "input/catalog.json").write_bytes((FIXTURES / "input/catalog.json").read_bytes())
        return root

    def test_generated_admissions_match_separate_workflow_contract(self):
        self.assertEqual({(t["sub"], t["aud"]) for t in self.tokens}, direct_trust_relation(self.policy["trust"]))
        self.assertEqual(6, len(self.required))
        self.assertEqual(8, len(self.allowed))

    def test_empty_required_permissions_refused(self):
        self.workflow["required_permissions"] = []
        with self.assertRaisesRegex(ValueError, "executable operations"):
            workflow_contract(self.workflow)

    def test_requirement_cannot_be_omitted_by_changing_its_reason(self):
        self.workflow["required_permissions"][0]["reason"] = ""
        with self.assertRaisesRegex(ValueError, "rationale"):
            workflow_contract(self.workflow)

    def test_untrusted_job_is_not_an_execution_choice(self):
        self.workflow["jobs"].append({"id": "untrusted-pr", "branch": "dev"})
        with self.assertRaisesRegex(ValueError, "fixed owned jobs"):
            workflow_contract(self.workflow)

    def test_removing_each_required_permission_blocks_its_operation(self):
        # Six separate bounded negative controls, not six deployments.
        for grant in self.required:
            with self.subTest(grant=grant), tempfile.TemporaryDirectory(dir=FIXTURES) as directory:
                policy = deepcopy(self.policy)
                policy["permissions"].remove(grant)
                root = self.work(directory)
                with self.assertRaisesRegex(PermissionError, "missing"):
                    publish(root, policy, {"sub": grant["sub"], "aud": grant["aud"]})
                self.assertFalse((root / "dist/index.html").exists())

    def test_optional_read_is_not_needed_for_success(self):
        policy = deepcopy(self.policy)
        policy["permissions"] = deepcopy(self.required)
        for token in self.tokens:
            with self.subTest(token=token), tempfile.TemporaryDirectory(dir=FIXTURES) as directory:
                root = self.work(directory)
                self.assertEqual([{"action": a, "resource": r} for a, r in OPERATIONS], publish(root, policy, token))
                verify_bundle(root)

    def test_explicit_deny_preserves_tuple_correlation(self):
        trust = deepcopy(self.policy["trust"])
        denial = deepcopy(trust["Statement"][0]); denial["Effect"] = "Deny"
        denial["Condition"]["StringEquals"][PREFIX + "sub"] = self.tokens[0]["sub"]
        trust["Statement"].append(denial)
        self.assertEqual({(self.tokens[1]["sub"], self.tokens[1]["aud"])}, direct_trust_relation(trust))

    def test_malformed_catalog_is_not_published(self):
        with tempfile.TemporaryDirectory(dir=FIXTURES) as directory:
            root = self.work(directory)
            save_json(root / "input/catalog.json", [{"id": "bad", "name": "Bad", "price_cents": True}])
            with self.assertRaisesRegex(ValueError, "integer price"):
                publish(root, self.policy, self.tokens[0])
            self.assertFalse((root / "dist").exists())


if __name__ == "__main__":
    unittest.main()
