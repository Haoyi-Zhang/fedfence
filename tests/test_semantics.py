import unittest
from fse_workflow.semantics import inspect_projection, observation_bases


def state(i, intended, mintable=True, **claims):
    return {"id": str(i), "intended": intended, "mintable": mintable, "claims": claims}

class ProjectionTests(unittest.TestCase):
    def test_environment_branch_collision(self):
        xs = [state("main", True, sub="env:prod", ref="main"), state("dev", False, sub="env:prod", ref="dev")]
        r = inspect_projection(xs, ["sub"])
        self.assertFalse(r["saturated"])
        self.assertEqual([], r["must_safe_observations"])
        self.assertEqual(1, len(r["existential_intent_images"]))
        self.assertTrue(inspect_projection(xs, ["sub", "ref"])["saturated"])

    def test_unmintable_state_does_not_block_saturation(self):
        xs = [state("main", True, sub="env:prod"), state("dev", False, False, sub="env:prod")]
        self.assertTrue(inspect_projection(xs, ["sub"])["saturated"])

    def test_unmintable_positive_cannot_license_negative(self):
        xs = [state("main", True, False, sub="env:prod"), state("dev", False, sub="env:prod")]
        r = inspect_projection(xs, ["sub"])
        self.assertEqual([], r["must_safe_observations"])
        self.assertEqual([], r["existential_intent_images"])

    def test_omitted_state_changes_basis(self):
        xs = [state("main", True, sub="env:prod", ref="main")]
        self.assertEqual([[]], observation_bases(xs, ["sub", "ref"])["minimum_cardinality_bases"])
        xs.append(state("dev", False, sub="env:prod", ref="dev"))
        self.assertEqual([["ref"]], observation_bases(xs, ["sub", "ref"])["minimum_cardinality_bases"])
        self.assertFalse(observation_bases(xs, ["sub", "ref"])["complete_provider_model"])

    def test_inclusion_minimal_differs_from_minimum(self):
        xs = [state("p", True, a="1", b="0", c="0"), state("n1", False, a="0", b="1", c="0"), state("n2", False, a="0", b="0", c="1")]
        r = observation_bases(xs, ["a", "b", "c"])
        self.assertEqual([["a"], ["b", "c"]], r["inclusion_minimal_bases"])
        self.assertEqual([["a"]], r["minimum_cardinality_bases"])
        self.assertEqual(1, r["minimum_cardinality"])

    def test_constant_predicate_has_empty_basis(self):
        xs = [state("a", True, sub="x"), state("b", True, sub="y")]
        self.assertEqual([[]], observation_bases(xs, ["sub"])["inclusion_minimal_bases"])

    def test_no_basis_reports_none(self):
        xs = [state("a", True, sub="x"), state("b", False, sub="x")]
        self.assertIsNone(observation_bases(xs, ["sub"])["minimum_cardinality"])

    def test_duplicate_states_rejected(self):
        with self.assertRaises(ValueError):
            inspect_projection([state("a", True, sub="x"), state("a", False, sub="y")], ["sub"])

    def test_missing_claim_rejected(self):
        with self.assertRaises(ValueError):
            inspect_projection([state("a", True, sub="x")], ["ref"])

    def test_missing_mintability_rejected(self):
        with self.assertRaises(ValueError):
            inspect_projection([{"id":"x", "intended": True, "claims": {}}], [])

    def test_duplicate_basis_candidates_rejected(self):
        with self.assertRaises(ValueError):
            observation_bases([], ["sub", "sub"])
