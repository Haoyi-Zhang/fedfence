"""Specification helpers for FedFence intent and issuer metadata.

The public JSON schema keeps legacy keys for readability but the checker treats
intent values as literals unless they are placed in an explicit glob key.  This
is important because release names may contain '*' or '?' as ordinary characters
while IAM StringLike uses those characters as metacharacters.
"""
from __future__ import annotations
from typing import Any, Mapping, Sequence, Tuple

from .regular import NFA, union, union_globs, union_literals, empty


def _list(x: Any) -> list[str]:
    if x is None:
        return []
    if isinstance(x, list):
        return [str(v) for v in x]
    return [str(x)]


def subject_intent_parts(spec: Mapping[str, Any]) -> Tuple[list[str], list[str]]:
    """Return (literal subjects, glob subjects) for role intent.

    Backward compatibility: ``allowed_subjects`` are exact constructor strings.
    Wildcard intent must be declared in ``allowed_subject_globs``.  This prevents
    accidental widening when an exact branch or environment name contains a
    literal '*' or '?'.
    """
    lits = _list(spec.get("allowed_subject_literals")) + _list(spec.get("allowed_subjects"))
    globs = _list(spec.get("allowed_subject_globs"))
    return lits, globs


def audience_intent_parts(spec: Mapping[str, Any]) -> Tuple[list[str], list[str]]:
    lits = _list(spec.get("allowed_audience_literals")) + _list(spec.get("allowed_audiences"))
    if not lits and not spec.get("allowed_audience_globs"):
        lits = ["sts.amazonaws.com"]
    globs = _list(spec.get("allowed_audience_globs"))
    return lits, globs


def intent_nfa(literals: Sequence[str], globs: Sequence[str], alphabet: Sequence[str]) -> NFA:
    pieces: list[NFA] = []
    if literals:
        pieces.append(union_literals(list(literals), alphabet))
    if globs:
        pieces.append(union_globs(list(globs), alphabet))
    return union(pieces, alphabet) if pieces else empty(alphabet)


def intent_alphabet_inputs(spec: Mapping[str, Any]) -> list[Any]:
    sl, sg = subject_intent_parts(spec)
    al, ag = audience_intent_parts(spec)
    return [("equals", sl), ("like", sg), ("equals", al), ("like", ag)]


def subject_intent_display(spec: Mapping[str, Any]) -> list[str]:
    l, g = subject_intent_parts(spec)
    return list(l) + list(g)


def audience_intent_display(spec: Mapping[str, Any]) -> list[str]:
    l, g = audience_intent_parts(spec)
    return list(l) + list(g)
