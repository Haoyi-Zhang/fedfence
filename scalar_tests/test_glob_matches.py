"""Portable, scalar-only tests on owned bounded strings (Python 3.10+).

Run from the artifact root: python -B scalar_tests/test_glob_matches.py -v
This optional suite imports only conformance.py and the standard library, not
gates, policies, providers, symbolic analysis, receipts or before/private files.
"""
from __future__ import annotations

import importlib.util
import itertools
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "fse_workflow/conformance.py"
SPEC = importlib.util.spec_from_file_location("scalar_glob_under_test", SOURCE)
SCALAR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SCALAR)


def words(alphabet: str, maximum_length: int) -> list[str]:
    return ["".join(chars) for length in range(maximum_length + 1)
            for chars in itertools.product(alphabet, repeat=length)]


def definition(pattern: str, actual: str) -> bool:
    """Whole-string definition by bounded star expansion, not prefix DP."""
    if not pattern:
        return not actual
    head, tail = pattern[0], pattern[1:]
    if head == "*":
        return any(definition(tail, actual[k:]) for k in range(len(actual) + 1))
    return bool(actual and (head == "?" or head == actual[0])
                and definition(tail, actual[1:]))


class GlobMatchesTests(unittest.TestCase):
    def test_bounded_recursive_definition(self):
        patterns = words("ab*?", 4)  # 341 patterns, including the empty pattern.
        actuals = words("ab", 4)    # 31 strings; exactly 10,571 pairs.
        for pattern, actual in itertools.product(patterns, actuals):
            with self.subTest(pattern=pattern, actual=actual):
                self.assertEqual(definition(pattern, actual),
                                 SCALAR._glob_matches(pattern, actual))

    def test_literal_and_codepoint_controls(self):
        cases = [("[ab]", "a", False), ("[ab]", "[ab]", True),
                 (r"a\b", r"a\b", True), ("a?b", "a\nb", True),
                 ("caf?", "café", True), ("?", "雪", True),
                 ("?", "\U00010000", True), ("?", "\ud800", True),
                 ("?", "e\u0301", False), ("é", "e\u0301", False),
                 ("*?*", "\x00", True), ("*\\?", "a\\雪", True),
                 ("a**b", "axxb", True), ("a**b", "axxc", False),
                 ("**?**", "\n", True)]
        for pattern, actual, expected in cases:
            with self.subTest(pattern=pattern, actual=actual):
                self.assertEqual(expected, definition(pattern, actual))
                self.assertEqual(expected, SCALAR._glob_matches(pattern, actual))

    def test_literal_fastpath_is_not_wildcard_cell_work(self):
        actual = "a" * 3000
        self.assertTrue(SCALAR._glob_matches(actual, actual))
        self.assertFalse(SCALAR._glob_matches(actual, actual + "b"))

    def test_cell_cap_inclusive_and_one_column_over(self):
        # Owned strings only: 1000*(1999+1) is exactly the declared cap.
        pattern = "*" * 1000
        self.assertTrue(SCALAR._glob_matches(pattern, "a" * 1999))
        with self.assertRaises(SCALAR.ConformanceBudgetExceeded) as raised:
            SCALAR._glob_matches(pattern, "a" * 2000)
        self.assertEqual("positive-analysis-budget", raised.exception.code)
        self.assertEqual("positive glob match exceeds 2000000 cell budget",
                         str(raised.exception))

    def test_injected_deadlines_at_every_check(self):
        # Replace only this module's clock binding; never sample real time.
        for pattern, actual in [("a*?b", "axxb"), ("*", ""),
                                ("", ""), ("literal", "literal")]:
            checks = 1 + (len(pattern) if "*" in pattern or "?" in pattern else 0)
            for threshold in range(checks + 2):  # 17 declared controls.
                calls = []

                def clock():
                    value = float(len(calls))
                    calls.append(value)
                    return value

                with self.subTest(pattern=pattern, threshold=threshold):
                    with patch.object(SCALAR, "time", SimpleNamespace(monotonic=clock)):
                        if threshold < checks:
                            with self.assertRaises(SCALAR.ConformanceBudgetExceeded) as raised:
                                SCALAR._glob_matches(pattern, actual, deadline=float(threshold))
                            self.assertEqual("positive-analysis-budget", raised.exception.code)
                            self.assertEqual("positive conformance check exhausted the review budget",
                                             str(raised.exception))
                        else:
                            self.assertEqual(definition(pattern, actual), SCALAR._glob_matches(
                                pattern, actual, deadline=float(threshold)))
                    expected_calls = min(threshold + 1, checks)
                    self.assertEqual([float(i) for i in range(expected_calls)], calls)

    def test_nonstring_inputs_are_not_coerced(self):
        for pattern, actual in [(None, "a"), ([], "a"), (False, "a"),
                                ("*", None), ("*", 3)]:
            with self.subTest(pattern=pattern, actual=actual):
                with self.assertRaises(SCALAR.ConformanceError) as raised:
                    SCALAR._glob_matches(pattern, actual)
                self.assertIs(type(raised.exception), SCALAR.ConformanceError)
                self.assertEqual("glob pattern and value must be strings", str(raised.exception))

    def test_expired_deadline_precedes_type_validation(self):
        calls = []

        def clock():
            calls.append(0.0)
            return 0.0

        with patch.object(SCALAR, "time", SimpleNamespace(monotonic=clock)):
            with self.assertRaises(SCALAR.ConformanceBudgetExceeded):
                SCALAR._glob_matches(None, "a", deadline=0.0)
        self.assertEqual([0.0], calls)


if __name__ == "__main__":
    unittest.main()
