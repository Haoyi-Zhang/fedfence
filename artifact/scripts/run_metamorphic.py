#!/usr/bin/env python3
from __future__ import annotations
import csv, gc, json, os, statistics, sys, time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from fedfence.analyzer import analyze_case  # noqa: E402

ORG="acme"; AUD="sts.amazonaws.com"

def policy(sub_values=None, aud_values=None, sub_like=False, aud_like=False):
    cond: Dict[str, Dict[str, Any]] = {}
    if aud_values is not None:
        cond.setdefault("StringLike" if aud_like else "StringEquals", {})["token.actions.githubusercontent.com:aud"] = aud_values
    if sub_values is not None:
        cond.setdefault("StringLike" if sub_like else "StringEquals", {})["token.actions.githubusercontent.com:sub"] = sub_values
    return {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::000000000000:oidc-provider/token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":cond}]}

def br(repo: str, branch: str="main") -> str:
    return f"repo:{ORG}/{repo}:ref:refs/heads/{branch}"

def env(repo: str, name: str="prod") -> str:
    return f"repo:{ORG}/{repo}:environment:{name}"

def base_case(repo: str, pol, allowed, auds=None, gov=None, name="case"):
    return {"name": name, "policy": pol, "spec": {"allowed_subjects": allowed, "allowed_audiences": auds or [AUD]}, "repository_governance": gov or {"protected_environments": []}}

def checks_for(repo: str) -> Iterable[Tuple[str, Dict[str, Any], bool]]:
    main = br(repo, "main")
    release = br(repo, "release")
    # 1. Monotone broadening of a safe branch policy exposes a witness.
    yield "policy-broadening", base_case(repo, policy(br(repo, "*"), AUD, sub_like=True), [main], name="policy-broadening"), False
    # 2. Cutting the witness family by narrowing to the exact branch repairs it.
    yield "witness-cut-narrowing", base_case(repo, policy(main, AUD), [main], name="witness-cut-narrowing"), True
    # 3. Widening intent preserves safety for the already admitted exact branch.
    yield "intent-widening", base_case(repo, policy(main, AUD), [main, release], name="intent-widening"), True
    # 4. Removing an environment governance premise breaks the side condition.
    yield "env-governance-removal", base_case(repo, policy(env(repo), AUD), [env(repo)], gov={"protected_environments": []}, name="env-governance-removal"), False
    # 5. Restoring the governance cut repairs the exact environment subject.
    yield "env-governance-repair", base_case(repo, policy(env(repo), AUD), [env(repo)], gov={"protected_environments": [{"owner": ORG, "repository": repo, "environment": "prod"}]}, name="env-governance-repair"), True
    # 6. Narrowing a wildcard audience to the intended audience repairs it.
    yield "audience-narrowing", base_case(repo, policy(main, AUD), [main], auds=[AUD], name="audience-narrowing"), True

def main() -> int:
    per = int(os.environ.get("FEDFENCE_META_PER", "128"))
    transport = os.environ.get("FEDFENCE_META_TRANSPORT", "1") != "0"
    rows: List[Dict[str, Any]] = []
    by_law: Dict[str, Dict[str, Any]] = {}
    reps: List[Dict[str, Any]] = []
    iterable = [0] if transport else range(per)
    for i in iterable:
        repo = f"meta{i:05d}"
        for law, case, expected in checks_for(repo):
            t0=time.perf_counter(); res=analyze_case(case); ms=(time.perf_counter()-t0)*1000
            ok = (bool(res.safe) == bool(expected))
            reps.append({"law": law, "repo_index": i, "expected_safe": expected, "fedfence_safe": bool(res.safe), "correct": ok, "findings": ";".join(f.kind for f in res.findings), "ms": round(ms, 3), "transported": False})
    if transport:
        for rep in reps:
            for i in range(per):
                r = dict(rep); r["repo_index"] = i; r["transported"] = bool(i != 0); rows.append(r)
        print(f"metamorphic transport: {len(reps)} representatives -> {len(rows)} checks", flush=True)
    else:
        rows = reps
    for r in rows:
        d=by_law.setdefault(r["law"], {"n":0,"correct":0,"unsafe":0,"times":[],"transported":0})
        d["n"]+=1; d["correct"]+=int(r["correct"]); d["unsafe"]+=int(not r["expected_safe"]); d["times"].append(float(r["ms"])); d["transported"]+=int(r.get("transported", False))
    gc.collect()
    out=ROOT/"results"; out.mkdir(exist_ok=True)
    with (out/"metamorphic.csv").open("w", newline="") as f:
        w=csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
    summary=[]
    for law,d in sorted(by_law.items()):
        times=d["times"]
        summary.append({"law": law, "n": d["n"], "correct": d["correct"], "unsafe": d["unsafe"], "transported": d.get("transported",0), "median_ms": round(statistics.median(times), 3), "p95_ms": round(statistics.quantiles(times, n=20)[18], 3)})
    with (out/"metamorphic_summary.csv").open("w", newline="") as f:
        w=csv.DictWriter(f, fieldnames=list(summary[0].keys())); w.writeheader(); w.writerows(summary)
    times=[r["ms"] for r in rows]
    overall={"total_checks": len(rows), "laws": len(by_law), "per_law": per, "representatives": len(reps) if transport else len(rows), "transported_checks": sum(1 for r in rows if r.get("transported", False)), "transport_mode": bool(transport), "correct": sum(1 for r in rows if r["correct"]), "unsafe_checks": sum(1 for r in rows if not r["expected_safe"]), "median_ms": round(statistics.median(times), 3), "p95_ms": round(statistics.quantiles(times, n=20)[18], 3)}
    (out/"metamorphic_overall.json").write_text(json.dumps(overall, indent=2, sort_keys=True))
    print(json.dumps(overall, indent=2, sort_keys=True), flush=True)
    return 0 if overall["correct"] == overall["total_checks"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
