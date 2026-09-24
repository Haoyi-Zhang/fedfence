"""Finite projection checks for federated CI/CD trust admission.

FedFence treats a CI/CD deployment as a concrete event and a cloud trust policy
as a predicate over claims exposed by an OIDC issuer.  This module gives a small,
executable instance of that projection calculus.  The finite model is not a
substitute for the paper proof; it is a regression artifact for the definability
and claim-basis theorems.
"""
from __future__ import annotations

from dataclasses import dataclass
from itertools import combinations, product
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple


@dataclass(frozen=True, order=True)
class WorkflowState:
    org: str
    repo: str
    event: str       # branch, tag, pull_request, environment
    ref: str         # branch or tag name; empty for pull_request
    environment: str # environment name, empty otherwise
    repo_class: str  # anonymous repository custom-property class


def github_default_subject(s: WorkflowState) -> str:
    if s.event == "branch":
        return f"repo:{s.org}/{s.repo}:ref:refs/heads/{s.ref}"
    if s.event == "tag":
        return f"repo:{s.org}/{s.repo}:ref:refs/tags/{s.ref}"
    if s.event == "pull_request":
        return f"repo:{s.org}/{s.repo}:pull_request"
    if s.event == "environment":
        return f"repo:{s.org}/{s.repo}:environment:{s.environment}"
    raise ValueError(s.event)


def github_refined_environment_subject(s: WorkflowState) -> str:
    """A custom subject template that retains the ref coordinate for environments."""
    if s.event == "environment":
        return f"repo:{s.org}/{s.repo}:environment:{s.environment}:ref:refs/heads/{s.ref}"
    return github_default_subject(s)


def sample_space() -> List[WorkflowState]:
    orgs = ["acme"]
    repos = [("api", "production"), ("web", "development")]
    branches = ["main", "release", "feature"]
    tags = ["v1", "test"]
    envs = ["prod", "stage"]
    out: List[WorkflowState] = []
    for org, (repo, repo_class) in product(orgs, repos):
        for b in branches:
            out.append(WorkflowState(org, repo, "branch", b, "", repo_class))
        for t in tags:
            out.append(WorkflowState(org, repo, "tag", t, "", repo_class))
        out.append(WorkflowState(org, repo, "pull_request", "", "", repo_class))
        for e, b in product(envs, branches):
            out.append(WorkflowState(org, repo, "environment", b, e, repo_class))
    return out


# Predicates used in the finite definability experiment.
def release_branch_api(s: WorkflowState) -> bool:
    return s.org == "acme" and s.repo == "api" and s.event == "branch" and s.ref == "main"


def prod_environment_api(s: WorkflowState) -> bool:
    return s.org == "acme" and s.repo == "api" and s.event == "environment" and s.environment == "prod"


def prod_environment_main_branch_api(s: WorkflowState) -> bool:
    return (s.org == "acme" and s.repo == "api" and s.event == "environment"
            and s.environment == "prod" and s.ref == "main")


def repository_api_only(s: WorkflowState) -> bool:
    return s.org == "acme" and s.repo == "api"


def deployable_repository_environment(s: WorkflowState) -> bool:
    return s.event == "environment" and s.environment == "prod" and s.repo_class == "production"


def not_pull_request(s: WorkflowState) -> bool:
    return s.event != "pull_request"


def prod_env_main_or_release(s: WorkflowState) -> bool:
    return (s.repo == "api" and s.event == "environment" and
            s.environment == "prod" and s.ref in {"main", "release"})


def production_tier(s: WorkflowState) -> bool:
    return s.repo_class == "production"


# Claim projections.  The repository_id coordinate abstracts an immutable
# provider identity; repo_class abstracts a repository custom property.
def claim_repo(s: WorkflowState) -> str:
    return f"{s.org}/{s.repo}"


def claim_repository_id(s: WorkflowState) -> str:
    return {"acme/api": "RID-api", "acme/web": "RID-web"}[f"{s.org}/{s.repo}"]


def claim_event(s: WorkflowState) -> str:
    return s.event


def claim_ref(s: WorkflowState) -> str:
    return s.ref


def claim_environment(s: WorkflowState) -> str:
    return s.environment


def claim_context(s: WorkflowState) -> str:
    if s.event == "environment":
        return f"environment:{s.environment}"
    if s.event == "pull_request":
        return "pull_request"
    if s.event == "branch":
        return f"ref:refs/heads/{s.ref}"
    if s.event == "tag":
        return f"ref:refs/tags/{s.ref}"
    return s.event


def claim_default_sub(s: WorkflowState) -> str:
    return github_default_subject(s)


def claim_refined_sub(s: WorkflowState) -> str:
    return github_refined_environment_subject(s)


def claim_repo_class(s: WorkflowState) -> str:
    return s.repo_class


CLAIM_PROJECTIONS: Dict[str, Callable[[WorkflowState], str]] = {
    "repo": claim_repo,
    "repository_id": claim_repository_id,
    "event": claim_event,
    "ref": claim_ref,
    "environment": claim_environment,
    "context": claim_context,
    "default_sub": claim_default_sub,
    "refined_sub": claim_refined_sub,
    "repo_class": claim_repo_class,
}

BASIS_PREDICATES: Dict[str, Callable[[WorkflowState], bool]] = {
    "release-branch": release_branch_api,
    "prod-environment": prod_environment_api,
    "prod-env-main": prod_environment_main_branch_api,
    "prod-env-main-or-release": prod_env_main_or_release,
    "repository-api-only": repository_api_only,
    "production-tier": production_tier,
    "deployable-prod-environment": deployable_repository_environment,
    "not-pull-request": not_pull_request,
}


def projection_from_fields(fields: Sequence[str]) -> Callable[[WorkflowState], Tuple[str, ...]]:
    fs = tuple(fields)
    funcs = tuple(CLAIM_PROJECTIONS[f] for f in fs)
    return lambda s: tuple(fn(s) for fn in funcs)


def claim_definability_counterexample(
    states: Iterable[WorkflowState],
    projection: Callable[[WorkflowState], object],
    predicate: Callable[[WorkflowState], bool],
) -> Optional[Tuple[WorkflowState, WorkflowState, object]]:
    """Return two states with same claim observation but different truth values."""
    by_claim: Dict[object, List[WorkflowState]] = {}
    for s in states:
        by_claim.setdefault(projection(s), []).append(s)
    for claim, xs in sorted(by_claim.items(), key=lambda kv: str(kv[0])):
        yes = [x for x in xs if predicate(x)]
        no = [x for x in xs if not predicate(x)]
        if yes and no:
            return yes[0], no[0], claim
    return None


def is_definable_by_claims(states: Sequence[WorkflowState], claim_names: Sequence[str], predicate: Callable[[WorkflowState], bool]) -> bool:
    return claim_definability_counterexample(states, projection_from_fields(claim_names), predicate) is None


def minimal_claim_bases(states: Sequence[WorkflowState], predicate: Callable[[WorkflowState], bool], candidates: Sequence[str]) -> List[Tuple[str, ...]]:
    """Return cardinality-minimal claim bases that define predicate on states."""
    cand = list(candidates)
    bases: List[Tuple[str, ...]] = []
    for k in range(1, len(cand) + 1):
        for subset in combinations(cand, k):
            if is_definable_by_claims(states, subset, predicate):
                bases.append(tuple(subset))
        if bases:
            return bases
    return bases
