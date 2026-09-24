"""Finite observation semantics; not a claim of complete provider behavior.

The state domain is restricted BEFORE taking images and inverse images.
Universal (must-safe) observations, unlike the image of intended states, remain
sound when intended and unintended states share a claim tuple.
"""
from __future__ import annotations
from itertools import combinations
from typing import Any, Mapping, Sequence


def inspect_projection(states: Sequence[Mapping[str, Any]], claims: Sequence[str]) -> dict:
    ids = [s.get("id") for s in states]
    if any(not isinstance(x, str) or not x for x in ids) or len(set(ids)) != len(ids):
        raise ValueError("state IDs must be unique nonempty strings")
    if len(set(claims)) != len(claims):
        raise ValueError("duplicate observation coordinate")
    groups: dict[tuple[str, ...], list[Mapping[str, Any]]] = {}
    for state in states:
        if type(state.get("mintable")) is not bool or type(state.get("intended")) is not bool:
            raise ValueError("mintable and intended require explicit booleans")
        if not state["mintable"]:
            continue
        values = state.get("claims")
        if not isinstance(values, dict) or any(not isinstance(values.get(k), str) for k in claims):
            raise ValueError("missing/non-scalar observation coordinate")
        key = tuple(values[k] for k in claims)
        groups.setdefault(key, []).append(state)
    mixed, must_safe, intended_images = [], [], []
    for key in sorted(groups):
        group = groups[key]
        yes = sorted(s["id"] for s in group if s["intended"])
        no = sorted(s["id"] for s in group if not s["intended"])
        row = {"observation": dict(zip(claims, key)), "intended": yes, "unintended": no}
        if yes:
            intended_images.append(row)
        if yes and not no:
            must_safe.append(row)
        if yes and no:
            mixed.append(row)
    return {"domain": "explicitly supplied mintable states only", "mintable_states": sum(s["mintable"] for s in states),
            "observation_classes": len(groups), "saturated": not mixed, "mixed_classes": mixed,
            "must_safe_observations": must_safe, "existential_intent_images": intended_images,
            "complete_provider_model": False}


def observation_bases(states: Sequence[Mapping[str, Any]], candidates: Sequence[str]) -> dict:
    if len(candidates) > 16 or len(set(candidates)) != len(candidates):
        raise ValueError("at most 16 distinct candidates (explicit exponential enumeration)")
    minimal = []
    for k in range(len(candidates) + 1):  # Empty basis is correct for constant predicates.
        for subset in combinations(candidates, k):
            chosen = set(subset)
            if any(set(b).issubset(chosen) for b in minimal):
                continue
            if inspect_projection(states, subset)["saturated"]:
                minimal.append(list(subset))
    size = min(map(len, minimal), default=None)
    return {"inclusion_minimal_bases": minimal,
            "minimum_cardinality": size,
            "minimum_cardinality_bases": [b for b in minimal if len(b) == size],
            "domain": "explicitly supplied mintable states only", "complete_provider_model": False}
