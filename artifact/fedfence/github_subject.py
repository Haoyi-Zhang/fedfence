"""Compatibility wrappers for the single authoritative GitHub subject semantics.

All parsing and automaton construction is delegated to fedfence.github.  This
module is kept only so older scripts import the same implementation rather than
maintaining a second, divergent grammar.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Sequence

from .github import SubjectAtom, github_default_subject_nfa, governance_key as governance_key

@dataclass(frozen=True)
class ParsedSubject:
    kind: str
    owner: str
    repository: str
    value: Optional[str] = None


def parse_subject_literal(subject: str) -> Optional[ParsedSubject]:
    from .github import parse_github_subject
    atom = parse_github_subject(subject)
    if atom is None:
        return None
    return ParsedSubject(atom.kind, atom.owner, atom.repository, atom.value or None)


def is_typed_subject_literal(subject: str) -> bool:
    return parse_subject_literal(subject) is not None


def default_github_subject_nfa(alphabet: Sequence[str]):
    return github_default_subject_nfa(alphabet)
