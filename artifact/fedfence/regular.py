"""Regular-language utilities for FedFence.

This module is intentionally small and dependency-free. It implements the
finite-automata core used in the paper: glob patterns are compiled to NFAs,
regular languages are closed under union and intersection, and containment is
checked by on-the-fly subset construction with concrete witnesses.
"""
from __future__ import annotations

from collections import deque, defaultdict
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Iterable, Optional, Sequence, Set, Tuple

# The language domain is Python ``str`` code points, U+0000..U+10FFFF.
# This is an abstract string model, not a provider identifier-validity claim.
# Raw NFA constructors operate over their explicit, finite alphabet; callers
# proving an open-domain judgment MUST first build a complete finite support.
CHARACTER_DOMAIN = "python-str-codepoints-v1"
CODEPOINT_LIMIT = 0x110000
# Readable *preferences* for the OTHER representative, never the entire domain.
DEFAULT_ALPHABET = tuple(sorted(set(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    "-_.:/@%+=,~"
)))
FRESH_REPRESENTATIVES = tuple("zq0_9y")
GLOB_META = {"*", "?"}
EPS = None  # epsilon-transition marker


def pattern_literals(*pattern_sets: object) -> Set[str]:
    """Collect actual singleton tests, retaining equality's literal ``*``/``?``.

    Strings are globs by default. Typed groups may be tuples or mappings with
    equals/literal or like/glob operators. Containers, including tuples and
    generators, are traversed rather than converted to their Python repr.
    Other predicates (e.g. constructor delimiters) must be supplied as literals.
    """
    from collections.abc import Iterable as IterableABC, Mapping
    literals: Set[str] = set()
    def visit(value: object, *, glob_mode: bool = True) -> None:
        if value is None:
            return
        if isinstance(value, str):
            literals.update(ch for ch in value if not glob_mode or ch not in GLOB_META)
        elif isinstance(value, Mapping):
            op = str(value.get("op", "like")).lower()
            if op not in {"equals", "literal", "like", "glob"}:
                raise ValueError("unsupported finite-support group operator")
            visit(value.get("values", []), glob_mode=op in {"like", "glob"})
        elif (isinstance(value, tuple) and len(value) == 2
              and isinstance(value[0], str)
              and value[0].lower() in {"equals", "literal", "like", "glob"}):
            visit(value[1], glob_mode=value[0].lower() in {"like", "glob"})
        elif isinstance(value, IterableABC) and not isinstance(value, (bytes, bytearray)):
            for item in value:
                visit(item, glob_mode=glob_mode)
        else:
            raise ValueError("finite-support inputs must contain string patterns")
    for patterns in pattern_sets:
        visit(patterns)
    return literals


def fresh_character(literals: Set[str], base: Sequence[str] = DEFAULT_ALPHABET) -> Optional[str]:
    """Choose one member of the entire domain outside ``literals``, if any.

    Exhausting preferences is NOT exhaustion of the domain. The disjoint ranges
    below cover every Python code point exactly once, prioritizing printable
    non-surrogates. None is sound only when all CODEPOINT_LIMIT singletons occur.
    """
    preferences = tuple(base)
    if any(not isinstance(ch, str) or len(ch) != 1 for ch in preferences):
        raise ValueError("alphabet preferences must be single code points")
    for ch in FRESH_REPRESENTATIVES + preferences:
        if ch not in literals and ch not in GLOB_META:
            return ch
    for lo, hi in ((0x21, 0xD800), (0xE000, CODEPOINT_LIMIT), (0, 0x21), (0xD800, 0xE000)):
        for cp in range(lo, hi):
            ch = chr(cp)
            if ch not in literals:
                return ch
    return None


def alphabet_from_patterns(*pattern_sets: object,
                           base: Sequence[str] = DEFAULT_ALPHABET) -> Tuple[str, ...]:
    """A complete support: every literal singleton and one OTHER representative.

    ``base`` is a preference list, not a closed character universe. Wildcards
    range over CHARACTER_DOMAIN. Equality literals, constructor boundaries and
    a nonempty remainder must all survive the quotient. Low-level NFAs accept
    representative words, not arbitrary out-of-support concrete strings.
    """
    literals = pattern_literals(*pattern_sets)
    fresh = fresh_character(literals, base)
    return tuple(sorted(literals | ({fresh} if fresh is not None else set())))


def validate_support(alphabet: Sequence[str], *pattern_sets: object) -> Tuple[bool, str]:
    """Check coverage, without calling the representative-selection algorithm.

    The cardinality argument for a remainder is independent of candidate pools:
    if fewer than CODEPOINT_LIMIT literal singletons exist, OTHER is nonempty.
    This validates a finite-support obligation, not the whole analyzer.
    """
    if isinstance(alphabet, (bytes, bytearray)):
        return False, "alphabet must contain code points"
    chars = tuple(alphabet)
    if any(not isinstance(ch, str) or len(ch) != 1 for ch in chars):
        return False, "alphabet entries must be single code points"
    support = set(chars)
    if len(support) != len(chars):
        return False, "duplicate alphabet entries"
    literals = pattern_literals(*pattern_sets)
    if not literals.issubset(support):
        return False, "alphabet omits a literal or constructor boundary"
    if len(literals) < CODEPOINT_LIMIT and not (support - literals):
        return False, "alphabet omits the nonempty OTHER character class"
    return True, "complete code-point support"


@dataclass
class NFA:
    start: int
    finals: Set[int]
    trans: Dict[int, Dict[Optional[str], Set[int]]] = field(
        default_factory=lambda: defaultdict(lambda: defaultdict(set))
    )
    states: Set[int] = field(default_factory=set)
    alphabet: Tuple[str, ...] = DEFAULT_ALPHABET

    def add_edge(self, src: int, sym: Optional[str], dst: int) -> None:
        self.states.add(src)
        self.states.add(dst)
        self.trans[src][sym].add(dst)

    def epsilon_closure(self, ss: Iterable[int]) -> FrozenSet[int]:
        stack = list(ss)
        out = set(stack)
        while stack:
            s = stack.pop()
            for t in self.trans.get(s, {}).get(EPS, set()):
                if t not in out:
                    out.add(t)
                    stack.append(t)
        return frozenset(out)

    def step(self, ss: FrozenSet[int], ch: str) -> FrozenSet[int]:
        nxt: Set[int] = set()
        for s in ss:
            nxt |= self.trans.get(s, {}).get(ch, set())
        return self.epsilon_closure(nxt)

    def accepts(self, word: str) -> bool:
        ss = self.epsilon_closure({self.start})
        for ch in word:
            ss = self.step(ss, ch)
            if not ss:
                return False
        return any(s in self.finals for s in ss)

    @property
    def size(self) -> Tuple[int, int]:
        edges = 0
        for d in self.trans.values():
            for targets in d.values():
                edges += len(targets)
        return (len(self.states), edges)


def empty(alphabet: Sequence[str] = DEFAULT_ALPHABET) -> NFA:
    n = NFA(start=0, finals=set(), alphabet=tuple(alphabet))
    n.states.add(0)
    return n


def epsilon(alphabet: Sequence[str] = DEFAULT_ALPHABET) -> NFA:
    n = NFA(start=0, finals={0}, alphabet=tuple(alphabet))
    n.states.add(0)
    return n


def literal(s: str, alphabet: Sequence[str] = DEFAULT_ALPHABET) -> NFA:
    n = NFA(start=0, finals=set(), alphabet=tuple(alphabet))
    n.states.add(0)
    cur = 0
    for ch in s:
        nxt = max(n.states) + 1
        n.add_edge(cur, ch, nxt)
        cur = nxt
    n.finals.add(cur)
    return n




def concat(nfas: Sequence[NFA], alphabet: Sequence[str] = DEFAULT_ALPHABET) -> NFA:
    """Concatenate NFAs by epsilon-linking finals of each component."""
    if not nfas:
        return epsilon(alphabet)
    out = NFA(start=0, finals=set(), alphabet=tuple(alphabet))
    out.states.add(0)
    offset = 1
    prev_finals = {out.start}
    for n in nfas:
        remap = {st: st + offset for st in n.states}
        for f in prev_finals:
            out.add_edge(f, EPS, remap[n.start])
        for src, d in n.trans.items():
            for sym, tgts in d.items():
                for dst in tgts:
                    out.add_edge(remap[src], sym, remap[dst])
        prev_finals = {remap[f] for f in n.finals}
        offset = max(out.states) + 1
    out.finals = set(prev_finals)
    return out


def charclass(chars: Iterable[str], alphabet: Sequence[str] = DEFAULT_ALPHABET) -> NFA:
    """Accept exactly one character from chars intersected with alphabet."""
    allowed = set(chars) & set(alphabet)
    n = NFA(start=0, finals={1}, alphabet=tuple(alphabet))
    n.states.update({0, 1})
    for ch in allowed:
        n.add_edge(0, ch, 1)
    return n


def star_chars(chars: Iterable[str], alphabet: Sequence[str] = DEFAULT_ALPHABET) -> NFA:
    """Accept any finite string over chars intersected with alphabet."""
    allowed = set(chars) & set(alphabet)
    n = NFA(start=0, finals={0}, alphabet=tuple(alphabet))
    n.states.add(0)
    for ch in allowed:
        n.add_edge(0, ch, 0)
    return n


def plus_chars(chars: Iterable[str], alphabet: Sequence[str] = DEFAULT_ALPHABET) -> NFA:
    """Accept any nonempty string over chars intersected with alphabet."""
    return concat([charclass(chars, alphabet), star_chars(chars, alphabet)], alphabet)


def sigma_star(alphabet: Sequence[str] = DEFAULT_ALPHABET) -> NFA:
    return star_chars(alphabet, alphabet)

def glob(pattern: str, alphabet: Sequence[str] = DEFAULT_ALPHABET) -> NFA:
    """Compile an IAM/GitHub-style glob to an NFA.

    '*' denotes any sequence over ``alphabet``, '?' denotes one character, and
    all other characters are literals. IAM escaping is intentionally not modeled;
    callers should normalize unsupported patterns before invoking the checker.
    """
    alph = tuple(alphabet)
    n = NFA(start=0, finals=set(), alphabet=alph)
    n.states.add(0)
    cur = 0
    for ch in pattern:
        if ch == "*":
            for a in alph:
                n.add_edge(cur, a, cur)
        elif ch == "?":
            nxt = max(n.states) + 1
            for a in alph:
                n.add_edge(cur, a, nxt)
            cur = nxt
        else:
            nxt = max(n.states) + 1
            n.add_edge(cur, ch, nxt)
            cur = nxt
    n.finals.add(cur)
    return n


def union(nfas: Sequence[NFA], alphabet: Sequence[str] = DEFAULT_ALPHABET) -> NFA:
    if not nfas:
        return empty(alphabet)
    out = NFA(start=0, finals=set(), alphabet=tuple(alphabet))
    out.states.add(0)
    offset = 1
    for n in nfas:
        remap = {s: s + offset for s in n.states}
        out.add_edge(out.start, EPS, remap[n.start])
        for s, d in n.trans.items():
            for sym, ts in d.items():
                for t in ts:
                    out.add_edge(remap[s], sym, remap[t])
        out.finals |= {remap[s] for s in n.finals}
        offset = max(out.states) + 1
    return out


def intersect(a: NFA, b: NFA, alphabet: Sequence[str] = DEFAULT_ALPHABET) -> NFA:
    alph = tuple(alphabet)
    start_pair = (a.epsilon_closure({a.start}), b.epsilon_closure({b.start}))
    id_of = {start_pair: 0}
    out = NFA(start=0, finals=set(), alphabet=alph)
    out.states.add(0)
    q = deque([start_pair])
    while q:
        pa, pb = q.popleft()
        sid = id_of[(pa, pb)]
        if any(s in a.finals for s in pa) and any(s in b.finals for s in pb):
            out.finals.add(sid)
        for ch in alph:
            na, nb = a.step(pa, ch), b.step(pb, ch)
            if not na or not nb:
                continue
            pair = (na, nb)
            if pair not in id_of:
                id_of[pair] = len(id_of)
                out.states.add(id_of[pair])
                q.append(pair)
            out.add_edge(sid, ch, id_of[pair])
    return out


def contains_witness(a: NFA, b: NFA, alphabet: Sequence[str] = DEFAULT_ALPHABET,
                     max_states: int = 200000) -> Optional[str]:
    """Return a shortest word in L(a) - L(b), or None if L(a) subset L(b)."""
    alph = tuple(alphabet)
    sa0 = a.epsilon_closure({a.start})
    sb0 = b.epsilon_closure({b.start})
    q = deque([(sa0, sb0, "")])
    seen = {(sa0, sb0)}
    while q:
        sa, sb, w = q.popleft()
        if any(s in a.finals for s in sa) and not any(s in b.finals for s in sb):
            return w
        if len(seen) > max_states:
            raise RuntimeError(f"containment search exceeded {max_states} determinized states")
        for ch in alph:
            na = a.step(sa, ch)
            if not na:
                continue
            nb = b.step(sb, ch) if sb else frozenset()
            key = (na, nb)
            if key not in seen:
                seen.add(key)
                q.append((na, nb, w + ch))
    return None


def union_globs(patterns: Sequence[str], alphabet: Sequence[str] = DEFAULT_ALPHABET) -> NFA:
    return union([glob(p, alphabet) for p in patterns], alphabet)


def union_literals(values: Sequence[str], alphabet: Sequence[str] = DEFAULT_ALPHABET) -> NFA:
    """Return the union of exact literal strings.

    This is separate from ``union_globs`` because IAM equality operators do not
    interpret '*' or '?' as metacharacters.
    """
    return union([literal(str(v), alphabet) for v in values], alphabet)


def intersection_typed_groups(pattern_groups: Sequence[Tuple[str, Sequence[str]]],
                              alphabet: Sequence[str] = DEFAULT_ALPHABET) -> NFA:
    """Intersect disjunctive groups while preserving equality vs glob semantics.

    Each group is ``(op, values)`` where ``op`` is ``equals`` or ``like``.  Values
    inside a group are disjunctive; groups themselves are conjunctive.
    """
    nonempty = [(op, list(vals)) for op, vals in pattern_groups if vals]
    if not nonempty:
        return empty(alphabet)
    def group_nfa(op: str, vals: Sequence[str]) -> NFA:
        return union_literals(vals, alphabet) if op == "equals" else union_globs(vals, alphabet)
    cur = group_nfa(nonempty[0][0], nonempty[0][1])
    for op, vals in nonempty[1:]:
        cur = intersect(cur, group_nfa(op, vals), alphabet)
    return cur


def intersection_globs(pattern_groups: Sequence[Sequence[str]],
                       alphabet: Sequence[str] = DEFAULT_ALPHABET) -> NFA:
    """Return the intersection of unions of glob groups.

    A group encodes disjunction (multiple values for one operator/key). Multiple
    groups encode conjunction (different operators constraining the same claim).
    Empty groups are ignored; if all groups are empty, Sigma* is not inferred by
    this helper because callers must make unconstrained claims explicit.
    """
    nonempty = [g for g in pattern_groups if g]
    if not nonempty:
        return empty(alphabet)
    cur = union_globs(nonempty[0], alphabet)
    for group in nonempty[1:]:
        cur = intersect(cur, union_globs(group, alphabet), alphabet)
    return cur


def language_difference_witness(allow: Sequence[str], intended: Sequence[str],
                                alphabet: Sequence[str] = DEFAULT_ALPHABET) -> Tuple[bool, Optional[str], Tuple[int, int], Tuple[int, int]]:
    """Check whether union(allow) is contained in union(intended)."""
    a = union_globs(allow, alphabet)
    b = union_globs(intended, alphabet)
    w = contains_witness(a, b, alphabet)
    return (w is None, w, a.size, b.size)


def nfa_difference_witness(allow: NFA, intended: NFA,
                           alphabet: Sequence[str] = DEFAULT_ALPHABET) -> Tuple[bool, Optional[str], Tuple[int, int], Tuple[int, int]]:
    """Check whether L(allow) is contained in L(intended)."""
    w = contains_witness(allow, intended, alphabet)
    return (w is None, w, allow.size, intended.size)


def intersection_language_difference_witness(a: NFA, b: NFA, intended: NFA,
                                             alphabet: Sequence[str] = DEFAULT_ALPHABET,
                                             max_states: int = 300000) -> Optional[str]:
    """Return a shortest word in L(a) ∩ L(b) - L(intended), or None.

    This is the constructive check for issuer ∩ policy ⊆ intent. It avoids
    materializing the intersection automaton before running containment.
    """
    alph = tuple(alphabet)
    sa0 = a.epsilon_closure({a.start})
    sb0 = b.epsilon_closure({b.start})
    si0 = intended.epsilon_closure({intended.start})
    q = deque([(sa0, sb0, si0, "")])
    seen = {(sa0, sb0, si0)}
    while q:
        sa, sb, si, w = q.popleft()
        if (any(s in a.finals for s in sa)
                and any(s in b.finals for s in sb)
                and not any(s in intended.finals for s in si)):
            return w
        if len(seen) > max_states:
            raise RuntimeError(f"intersection containment search exceeded {max_states} determinized states")
        for ch in alph:
            na = a.step(sa, ch)
            if not na:
                continue
            nb = b.step(sb, ch)
            if not nb:
                continue
            ni = intended.step(si, ch) if si else frozenset()
            key = (na, nb, ni)
            if key not in seen:
                seen.add(key)
                q.append((na, nb, ni, w + ch))
    return None


def issuer_policy_intent_witness(policy: NFA, issuer: NFA, intended: NFA,
                                 alphabet: Sequence[str] = DEFAULT_ALPHABET) -> Tuple[bool, Optional[str], Tuple[int, int], Tuple[int, int]]:
    """Check L(policy) ∩ L(issuer) ⊆ L(intended)."""
    w = intersection_language_difference_witness(policy, issuer, intended, alphabet)
    return (w is None, w, policy.size, intended.size)


def any_string_nfa(alphabet: Sequence[str] = DEFAULT_ALPHABET) -> NFA:
    """Language Sigma* over alphabet."""
    return glob("*", alphabet)


def constrained_witness(positive: Sequence[NFA], negative: Sequence[NFA],
                        alphabet: Sequence[str] = DEFAULT_ALPHABET,
                        max_states: int = 300000) -> Optional[str]:
    """Return a shortest word in all positive languages and no negative language.

    This is a generic Boolean-combination emptiness query used by effective
    Allow-minus-Deny policy semantics.  It performs on-the-fly subset construction
    over all participating NFAs and therefore avoids complement construction.
    """
    alph = tuple(alphabet)
    pos0 = tuple(n.epsilon_closure({n.start}) for n in positive)
    neg0 = tuple(n.epsilon_closure({n.start}) for n in negative)
    start = (pos0, neg0)
    q = deque([(start, "")])
    seen = {start}
    while q:
        (pos, neg), w = q.popleft()
        if (all(any(s in n.finals for s in ss) for n, ss in zip(positive, pos))
                and all(not any(s in n.finals for s in ss) for n, ss in zip(negative, neg))):
            return w
        if len(seen) > max_states:
            raise RuntimeError(f"constrained search exceeded {max_states} determinized states")
        for ch in alph:
            pos1 = tuple(n.step(ss, ch) for n, ss in zip(positive, pos))
            if any(not ss for ss in pos1):
                continue
            neg1 = tuple(n.step(ss, ch) if ss else frozenset() for n, ss in zip(negative, neg))
            state = (pos1, neg1)
            if state not in seen:
                seen.add(state)
                q.append((state, w + ch))
    return None
