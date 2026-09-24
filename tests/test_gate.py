from __future__ import annotations
import copy
import json
from pathlib import Path
import tempfile
import unittest

from fse_workflow.contract import contract_digest
from fse_workflow.fragment import PREFIX, inspect_policy
from fse_workflow.gate import review, compare
from fse_workflow.io import digest, load_json
from scripts.make_workflow_examples import packet, rehash

NOW = "2026-09-23T01:00:00Z"
ROOT = Path(__file__).resolve().parents[1]

class GateTests(unittest.TestCase):
    def assert_unknown(self, p, code):
        r = review(p, now=NOW)
        self.assertEqual("unknown", r["verdict"], r)
        self.assertEqual(2, r["exit_code"])
        self.assertIn(code, [x.get("code") for x in r["findings"]])
        return r

    def test_exact_branch_pass(self):
        r = review(packet(), now=NOW)
        self.assertEqual("pass", r["verdict"])
        self.assertTrue(r["replay_ok"])
        self.assertFalse(r["source_authenticity_verified"])
        self.assertFalse(r["reviewer_identity_verified"])

    def test_unmodified_rerun_does_not_trust_cache(self):
        p = packet(); previous = review(p, now=NOW)
        previous["verdict"] = "fail"
        r = review(p, now=NOW, previous=previous)
        self.assertEqual("pass", r["verdict"])
        self.assertFalse(r["cache_used_for_verdict"])
        self.assertEqual([], r["changed_fields"])

    def test_policy_change_is_regression(self):
        p = packet(); after = copy.deepcopy(p)
        st = after["snapshots"]["policy"]["body"]["Statement"][0]
        st["Condition"]["StringEquals"].pop(PREFIX+"sub")
        st["Condition"]["StringLike"] = {PREFIX+"sub": "repo:acme/api:*"}
        rehash(after, "policy")
        r = compare(p, after, now=NOW)
        self.assertTrue(r["confirmed_admission_regression"])
        self.assertEqual(["policy"], r["after"]["changed_fields"])
        self.assertIn("pull_request", r["after"]["findings"][0]["witness"])

    def test_changed_intent_requires_new_review(self):
        p = packet(); p["contract"]["intent"]["branches"].append("dev")
        self.assert_unknown(p, "unapproved-contract-change")

    def test_review_digest_alone_not_authentication(self):
        p = packet(); p["contract"]["review"]["reviewer"] = p["contract"]["author"]
        self.assert_unknown(p, "unreviewed-intent")

    def test_policy_derived_intent_blocked(self):
        p = packet(); p["contract"]["review"]["basis"] = "copied-from-policy"
        self.assert_unknown(p, "unreviewed-intent")

    def test_missing_review_reference(self):
        p = packet(); p["contract"]["review"]["reference"] = ""
        self.assert_unknown(p, "unreviewed-intent")

    def test_stale_governance(self):
        p = packet(); p["snapshots"]["governance"]["observed_at"] = "2026-09-20T00:00:00Z"
        self.assert_unknown(p, "stale-snapshot")

    def test_future_timestamp(self):
        p = packet(); p["snapshots"]["issuer"]["observed_at"] = "2026-09-24T00:00:00Z"
        self.assert_unknown(p, "stale-snapshot")

    def test_naive_timestamp(self):
        p = packet(); p["snapshots"]["issuer"]["observed_at"] = "2026-09-23T00:00:00"
        self.assert_unknown(p, "invalid-timestamp")

    def test_empty_timestamp(self):
        p = packet(); p["snapshots"]["workflow"]["observed_at"] = None
        self.assert_unknown(p, "invalid-timestamp")

    def test_tampered_snapshot(self):
        p = packet(); p["snapshots"]["governance"]["body"]["new"] = "change"
        self.assert_unknown(p, "snapshot-digest-mismatch")

    def test_missing_workflow_snapshot(self):
        p = packet(); del p["snapshots"]["workflow"]
        self.assert_unknown(p, "missing-snapshot")

    def test_repository_scope_mismatch(self):
        p = packet(); p["snapshots"]["governance"]["body"]["repository"] = "other/repo"
        rehash(p, "governance"); self.assert_unknown(p, "scope-mismatch")

    def test_role_scope_mismatch(self):
        p = packet(); p["snapshots"]["policy"]["target_role"] = "unrelated"
        self.assert_unknown(p, "scope-mismatch")

    def test_issuer_profile_mismatch(self):
        p = packet(); p["snapshots"]["issuer"]["body"]["subject_mode"] = "immutable"
        rehash(p, "issuer"); self.assert_unknown(p, "unsupported-issuer-profile")

    def test_unknown_operator_allow(self):
        p = packet(); st = p["snapshots"]["policy"]["body"]["Statement"][0]
        st["Condition"]["StringEqualsIfExists"] = {PREFIX+"aud": "sts.amazonaws.com"}
        rehash(p,"policy"); self.assert_unknown(p, "unsupported-operator")

    def test_unsupported_deny_blocks_even_if_allow_exact(self):
        p = packet(); st = copy.deepcopy(p["snapshots"]["policy"]["body"]["Statement"][0])
        st["Effect"] = "Deny"; st["Condition"]["Null"] = {PREFIX+"sub": "false"}
        p["snapshots"]["policy"]["body"]["Statement"].append(st)
        rehash(p,"policy"); self.assert_unknown(p, "unsupported-operator")

    def test_selected_claim_not_silently_dropped(self):
        p = packet(); p["snapshots"]["policy"]["body"]["Statement"][0]["Condition"]["StringEquals"][PREFIX+"job_workflow_ref"] = "release.yml@main"
        rehash(p,"policy"); self.assert_unknown(p, "unsupported-claim")

    def test_unknown_effect(self):
        p = packet(); p["snapshots"]["policy"]["body"]["Statement"][0]["Effect"] = "allow"
        rehash(p,"policy"); self.assert_unknown(p, "invalid-effect")

    def test_nonobject_statement(self):
        p = packet(); p["snapshots"]["policy"]["body"]["Statement"].append("uninterpreted")
        rehash(p,"policy"); self.assert_unknown(p, "invalid-statement")

    def test_no_allow_unknown_not_safe(self):
        p = packet(); p["snapshots"]["policy"]["body"]["Statement"][0]["Effect"] = "Deny"
        rehash(p,"policy"); self.assert_unknown(p, "no-supported-allow")

    def test_notaction_not_filtered_away(self):
        p = packet(); st = copy.deepcopy(p["snapshots"]["policy"]["body"]["Statement"][0]); del st["Action"]
        st["NotAction"] = "sts:AssumeRole"; p["snapshots"]["policy"]["body"]["Statement"].append(st)
        rehash(p,"policy"); self.assert_unknown(p, "unsupported-statement-field")

    def test_wildcard_principal(self):
        p = packet(); p["snapshots"]["policy"]["body"]["Statement"][0]["Principal"]["Federated"] = "*"
        rehash(p,"policy"); self.assert_unknown(p, "unsupported-principal")

    def test_empty_condition_value(self):
        p = packet(); p["snapshots"]["policy"]["body"]["Statement"][0]["Condition"]["StringEquals"][PREFIX+"aud"] = []
        rehash(p,"policy"); self.assert_unknown(p, "invalid-condition-value")

    def test_interpolation(self):
        p = packet(); p["snapshots"]["policy"]["body"]["Statement"][0]["Condition"]["StringEquals"][PREFIX+"aud"] = "${aud}"
        rehash(p,"policy"); self.assert_unknown(p, "unresolved-interpolation")

    def test_intent_wildcard_not_offered_as_default(self):
        p = packet(); p["contract"]["intent"]["branches"] = ["*"]
        p["contract"]["review"]["approved_digest"] = contract_digest(p["contract"])
        self.assert_unknown(p, "invalid-intent")

    def test_missing_environment_premise(self):
        p = load_json(ROOT/"examples/release_gate/environment_missing.json")
        self.assert_unknown(p, "missing-governance-premise")

    def test_reviewed_environment(self):
        p = load_json(ROOT/"examples/release_gate/environment_reviewed.json")
        r = review(p, now=NOW); self.assertEqual("pass", r["verdict"], r)

    def test_environment_bypass_blocks(self):
        p = load_json(ROOT/"examples/release_gate/environment_reviewed.json")
        p["snapshots"]["governance"]["body"]["environments"]["prod"]["bypass_disabled"] = False
        rehash(p,"governance"); self.assert_unknown(p, "missing-governance-premise")

    def test_environment_extra_ref_blocks(self):
        p = load_json(ROOT/"examples/release_gate/environment_reviewed.json")
        p["snapshots"]["governance"]["body"]["environments"]["prod"]["allowed_refs"].append("refs/heads/dev")
        rehash(p,"governance"); self.assert_unknown(p, "unjustified-governance-premise")

    def test_timeout_does_not_pass(self):
        r = review(packet(), now=NOW, timeout=0.000001)
        self.assertEqual("unknown", r["verdict"])
        self.assertEqual("analysis-timeout", r["findings"][-1]["code"])

    def test_empty_or_malformed_packet(self):
        self.assert_unknown({}, "invalid-packet")
        self.assert_unknown(None, "invalid-packet")

    def test_json_duplicate_keys_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/"bad.json"; p.write_text('{"Statement": [], "Statement": {}}')
            with self.assertRaises(ValueError): load_json(p)

    def test_effective_deny_exact_repair(self):
        p = packet(); st = p["snapshots"]["policy"]["body"]["Statement"][0]
        main = st["Condition"]["StringEquals"][PREFIX+"sub"]; dev = main.replace("/main", "/dev")
        st["Condition"]["StringEquals"][PREFIX+"sub"] = [main, dev]
        deny = copy.deepcopy(st); deny["Effect"] = "Deny"; deny["Condition"]["StringEquals"][PREFIX+"sub"] = dev
        p["snapshots"]["policy"]["body"]["Statement"].append(deny); rehash(p,"policy")
        r = review(p,now=NOW); self.assertEqual("pass", r["verdict"], r)

    def test_deny_correlations_not_coordinatewise(self):
        p = packet(); st = p["snapshots"]["policy"]["body"]["Statement"][0]
        main = st["Condition"]["StringEquals"][PREFIX+"sub"]; dev = main.replace("/main", "/dev")
        st["Condition"]["StringEquals"] = {PREFIX+"sub": [main, dev], PREFIX+"aud": ["sts.amazonaws.com", "other"]}
        d1 = copy.deepcopy(st); d1["Effect"] = "Deny"; d1["Condition"]["StringEquals"] = {PREFIX+"sub": dev, PREFIX+"aud":"sts.amazonaws.com"}
        d2 = copy.deepcopy(st); d2["Effect"] = "Deny"; d2["Condition"]["StringEquals"] = {PREFIX+"sub": main, PREFIX+"aud":"other"}
        p["snapshots"]["policy"]["body"]["Statement"] += [d1,d2]; rehash(p,"policy")
        r = review(p,now=NOW); self.assertEqual("fail", r["verdict"],r)
        self.assertTrue(any("/dev" in f.get("witness","") and "other" in f["witness"] for f in r["findings"]))

class RequiredTokenTests(unittest.TestCase):
    def approved(self, p):
        p["contract"]["review"]["approved_digest"] = contract_digest(p["contract"])
        return p

    def test_required_token_satisfied(self):
        p = packet()
        sub = p["snapshots"]["policy"]["body"]["Statement"][0]["Condition"]["StringEquals"][PREFIX+"sub"]
        p["contract"]["required_tokens"] = [{"sub": sub, "aud": "sts.amazonaws.com", "reason": "main deployment must keep working"}]
        self.approved(p)
        r = review(p, now=NOW)
        self.assertEqual("pass", r["verdict"], r)
        self.assertEqual(1, r["required_token_checks"]["satisfied"])

    def test_required_token_regression_fails_even_when_policy_is_safe(self):
        p = packet()
        required_sub = p["snapshots"]["policy"]["body"]["Statement"][0]["Condition"]["StringEquals"][PREFIX+"sub"]
        p["contract"]["intent"]["branches"].append("release")
        p["contract"]["required_tokens"] = [{"sub": required_sub, "aud": "sts.amazonaws.com", "reason": "main deployment must keep working"}]
        # Policy admits only release, which is still inside the widened intent but drops main.
        p["snapshots"]["policy"]["body"]["Statement"][0]["Condition"]["StringEquals"][PREFIX+"sub"] = required_sub.replace("/main", "/release")
        rehash(p, "policy")
        self.approved(p)
        r = review(p, now=NOW)
        self.assertEqual("fail", r["verdict"], r)
        self.assertTrue(r["backend_analysis"]["safe"])
        self.assertTrue(any(f.get("code") == "required-token-not-admitted" for f in r["findings"]))

    def test_required_token_outside_intent_is_unknown(self):
        p = packet()
        p["contract"]["required_tokens"] = [{
            "sub": "repo:acme/api:ref:refs/heads/dev",
            "aud": "sts.amazonaws.com",
            "reason": "contradictory fixture",
        }]
        self.approved(p)
        r = review(p, now=NOW)
        self.assertEqual("unknown", r["verdict"], r)
        self.assertTrue(any(f.get("code") == "required-token-outside-contract-model" for f in r["findings"]))

    def test_required_token_honors_tuple_level_deny(self):
        p = packet()
        st = p["snapshots"]["policy"]["body"]["Statement"][0]
        main = st["Condition"]["StringEquals"][PREFIX+"sub"]
        st["Condition"]["StringEquals"][PREFIX+"aud"] = ["sts.amazonaws.com", "other"]
        deny = copy.deepcopy(st)
        deny["Effect"] = "Deny"
        deny["Condition"]["StringEquals"] = {PREFIX+"sub": main, PREFIX+"aud": "other"}
        p["snapshots"]["policy"]["body"]["Statement"].append(deny)
        p["contract"]["required_tokens"] = [{"sub": main, "aud": "sts.amazonaws.com", "reason": "STS path remains available"}]
        rehash(p, "policy")
        self.approved(p)
        r = review(p, now=NOW)
        self.assertEqual("pass", r["verdict"], r)
        self.assertEqual(1, r["required_token_checks"]["satisfied"])

    def test_duplicate_required_token_rejected(self):
        p = packet()
        sub = p["snapshots"]["policy"]["body"]["Statement"][0]["Condition"]["StringEquals"][PREFIX+"sub"]
        token = {"sub": sub, "aud": "sts.amazonaws.com", "reason": "duplicate"}
        p["contract"]["required_tokens"] = [token, copy.deepcopy(token)]
        self.approved(p)
        r = review(p, now=NOW)
        self.assertEqual("unknown", r["verdict"])
        self.assertTrue(any(f.get("code") == "invalid-required-token" for f in r["findings"]))

class ChangeClassificationTests(unittest.TestCase):
    def test_security_and_availability_regressions_are_distinct(self):
        security = compare(
            load_json(ROOT / "examples/release_gate/before.json"),
            load_json(ROOT / "examples/release_gate/after_wildcard.json"),
            now=NOW,
        )
        self.assertEqual("admission-expansion", security["regression_kind"])
        self.assertTrue(security["confirmed_admission_regression"])
        self.assertFalse(security["confirmed_required_identity_regression"])
        availability = compare(
            load_json(ROOT / "examples/release_gate/availability_before.json"),
            load_json(ROOT / "examples/release_gate/availability_after.json"),
            now=NOW,
        )
        self.assertEqual("required-identity-loss", availability["regression_kind"])
        self.assertFalse(availability["confirmed_admission_regression"])
        self.assertTrue(availability["confirmed_required_identity_regression"])

class ScalarGlobSemanticsTests(unittest.TestCase):
    def test_square_brackets_are_literals_not_fnmatch_classes(self):
        from fse_workflow.conformance import _glob_matches
        self.assertTrue(_glob_matches("repo:acme/api:ref:refs/heads/[prod]", "repo:acme/api:ref:refs/heads/[prod]"))
        self.assertFalse(_glob_matches("repo:acme/api:ref:refs/heads/[prod]", "repo:acme/api:ref:refs/heads/p"))
