#!/usr/bin/env python3
from __future__ import annotations
import csv, json
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

ROOT = Path(__file__).resolve().parents[1]

@dataclass(frozen=True)
class State:
    repo: str
    repo_id: str
    ref: str
    env: str
    event: str
    workflow: str
    tier: str

STATES = tuple(
    State(repo, repo_id, ref, env, event, wf, tier)
    for repo, repo_id, tier in [("api", "R100", "prod"), ("web", "R200", "prod")]
    for ref in ["main", "feature"]
    for env, event, wf in [("prod", "environment", "deploy.yml"), ("", "pull_request", "test.yml")]
)

def p_default(s: State) -> tuple[str, ...]:
    if s.event == "environment":
        return (s.repo, "environment", s.env)
    return (s.repo, s.event)

def p_repo(s: State) -> tuple[str, ...]:
    return (s.repo,)

def p_repo_id(s: State) -> tuple[str, ...]:
    return (s.repo_id,)

def p_repo_ref_env(s: State) -> tuple[str, ...]:
    return (s.repo_id, s.ref, s.env, s.event)

def p_workflow_ref(s: State) -> tuple[str, ...]:
    return (s.repo_id, s.ref, s.workflow)

def p_custom_full(s: State) -> tuple[str, ...]:
    return (s.repo_id, s.ref, s.env, s.event, s.workflow, s.tier)

PROJECTIONS: dict[str, Callable[[State], tuple[str, ...]]] = {
    "default_subject": p_default,
    "repository_name": p_repo,
    "repository_id": p_repo_id,
    "repo_ref_environment": p_repo_ref_env,
    "workflow_ref": p_workflow_ref,
    "custom_full": p_custom_full,
}


def bitset(n: int) -> Iterable[int]:
    for x in range(1 << n):
        yield x


def indices(mask: int, n: int) -> list[int]:
    return [i for i in range(n) if (mask >> i) & 1]


def alpha(mask: int, obs: list[tuple[str, ...]]) -> frozenset[tuple[str, ...]]:
    return frozenset(obs[i] for i in indices(mask, len(obs)))


def gamma(obs_set: frozenset[tuple[str, ...]], obs: list[tuple[str, ...]]) -> int:
    out = 0
    for i, o in enumerate(obs):
        if o in obs_set:
            out |= 1 << i
    return out


def saturated(mask: int, classes: dict[tuple[str, ...], int]) -> bool:
    for cls_mask in classes.values():
        part = mask & cls_mask
        if part not in (0, cls_mask):
            return False
    return True


def main() -> int:
    n = len(STATES)
    rows = []
    total_galois = total_sat = 0
    failed: list[str] = []
    for name, proj in PROJECTIONS.items():
        obs = [proj(s) for s in STATES]
        obs_values = sorted(set(obs))
        classes: dict[tuple[str, ...], int] = {}
        for i, o in enumerate(obs):
            classes[o] = classes.get(o, 0) | (1 << i)
        galois_checks = 0
        sat_checks = 0
        for X in bitset(n):
            ax = alpha(X, obs)
            ga = gamma(ax, obs)
            is_sat = saturated(X, classes)
            if (X == ga) != is_sat:
                failed.append(f"kernel saturation failed for {name}, X={X}")
            sat_checks += 1
            for Y_mask in bitset(len(obs_values)):
                Y = frozenset(obs_values[j] for j in indices(Y_mask, len(obs_values)))
                lhs = alpha(X, obs).issubset(Y)
                rhs = (X & ~gamma(Y, obs)) == 0
                if lhs != rhs:
                    failed.append(f"galois failed for {name}, X={X}, Y={Y_mask}")
                    break
                galois_checks += 1
        total_galois += galois_checks
        total_sat += sat_checks
        rows.append({
            "projection": name,
            "states": n,
            "observations": len(obs_values),
            "equivalence_classes": len(classes),
            "galois_checks": galois_checks,
            "kernel_saturation_checks": sat_checks,
            "all_passed": not any(x.startswith(f"galois failed for {name}") or x.startswith(f"kernel saturation failed for {name}") for x in failed),
        })
    out = ROOT / "results"; out.mkdir(exist_ok=True)
    with (out / "projection_laws.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
    overall = {
        "projections": len(PROJECTIONS),
        "states": n,
        "galois_checks": total_galois,
        "kernel_saturation_checks": total_sat,
        "failures": len(failed),
        "passed": not failed,
    }
    (out / "projection_laws_overall.json").write_text(json.dumps(overall, indent=2, sort_keys=True) + "\n")
    print(json.dumps(overall, indent=2, sort_keys=True), flush=True)
    return 0 if not failed else 1

if __name__ == "__main__":
    raise SystemExit(main())
