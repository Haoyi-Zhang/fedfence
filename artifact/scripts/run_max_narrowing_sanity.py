#!/usr/bin/env python3
"""Finite-set audit for Theorem maxrepair.

Theorem: for fixed universe U and languages P,G,I subset U,
P* = P ∩ (I ∪ (U \\ G)) is the greatest Q ⊆ P such that G ∩ Q ⊆ I.
This script exhaustively checks that fact on a five-element universe and records
why the tempting formula P ∩ (I ∪ G) is not greatest.
"""
from __future__ import annotations
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"
N = 5
U = (1 << N) - 1


def elems(mask: int) -> list[str]:
    return [f"u{i}" for i in range(N) if mask & (1 << i)]


def is_safe(G: int, Q: int, I: int) -> bool:
    return (G & Q & ~I & U) == 0


def submasks(mask: int):
    s = mask
    while True:
        yield s
        if s == 0:
            break
        s = (s - 1) & mask


def main() -> int:
    checked_triples = 0
    checked_candidates = 0
    failures: list[dict[str, object]] = []
    wrong_counterexample = None
    for G in range(U + 1):
        for P in range(U + 1):
            for I in range(U + 1):
                checked_triples += 1
                star = P & (I | (U ^ G))
                if (star & ~P) != 0 or not is_safe(G, star, I):
                    failures.append({"G": elems(G), "P": elems(P), "I": elems(I), "star": elems(star), "kind": "star_not_safe_or_not_narrowing"})
                    continue
                for Q in submasks(P):
                    checked_candidates += 1
                    if is_safe(G, Q, I) and (Q & ~star) != 0:
                        failures.append({"G": elems(G), "P": elems(P), "I": elems(I), "Q": elems(Q), "star": elems(star), "kind": "safe_Q_not_subset_star"})
                        break
                wrong = P & (I | G)
                if wrong_counterexample is None:
                    # Need a safe Q subset P that is not included in wrong. This shows
                    # P ∩ (I ∪ G) is not greatest because it throws away issuer-unmintable words.
                    for Q in submasks(P):
                        if is_safe(G, Q, I) and (Q & ~wrong) != 0:
                            wrong_counterexample = {"G": elems(G), "P": elems(P), "I": elems(I), "wrong_formula": elems(wrong), "safe_Q": elems(Q), "correct_star": elems(star)}
                            break
    summary = {
        "universe_size": N,
        "checked_triples": checked_triples,
        "checked_candidate_narrowings": checked_candidates,
        "passed": not failures,
        "failures": failures[:5],
        "wrong_formula_counterexample_found": wrong_counterexample is not None,
        "wrong_formula_counterexample": wrong_counterexample,
        "formula": "P_star = P ∩ (I ∪ (U \\ G))",
        "wrong_formula": "P ∩ (I ∪ G)",
    }
    RESULTS.mkdir(exist_ok=True)
    (RESULTS / "max_narrowing_sanity.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["passed"] and summary["wrong_formula_counterexample_found"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
