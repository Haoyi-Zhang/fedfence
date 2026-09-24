#!/usr/bin/env python3
from __future__ import annotations
import csv
import gc
import json
import os
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from fedfence.analyzer import analyze_case  # noqa: E402


def make_case(n: int, unsafe: bool=False):
    subjects = [f"repo:acme/service{i}:ref:refs/heads/main" for i in range(n)]
    policy_subjects = list(subjects)
    if unsafe:
        policy_subjects.append("repo:acme/service0:ref:refs/heads/*")
    return {
        "name": f"synthetic_{n}_{'unsafe' if unsafe else 'safe'}",
        "policy": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Federated": "arn:aws:iam::000000000000:oidc-provider/token.actions.githubusercontent.com"},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"},
                    "StringLike": {"token.actions.githubusercontent.com:sub": policy_subjects}
                }
            }]
        },
        "repository_governance": {"protected_branches": ["main"], "protected_environments": []},
        "spec": {"allowed_audiences": ["sts.amazonaws.com"], "allowed_subjects": subjects}
    }


def main() -> int:
    out_dir = ROOT / "results"
    out_dir.mkdir(exist_ok=True)
    rows = []
    # Keep the benchmark lightweight: the largest case has 257 subject patterns.
    # Each configuration is repeated three times to smooth local scheduling noise while keeping artifact evaluation lightweight.
    max_n = int(os.environ.get("FEDFENCE_BENCH_MAX", "64"))
    for n in [x for x in [1, 2, 4, 8, 16, 32, 64, 128, 256] if x <= max_n]:
        for unsafe in [False, True]:
            samples = []
            last = None
            for _ in range(int(os.environ.get("FEDFENCE_BENCH_REPS", "1"))):
                case = make_case(n, unsafe)
                t0 = time.perf_counter()
                res = analyze_case(case)
                dt = (time.perf_counter() - t0) * 1000.0
                samples.append(dt); last = res
                del case, res
                gc.collect()
            print(f"  bench progress: n={n} unsafe={unsafe}", flush=True)
            rows.append({
                "patterns": n + (1 if unsafe else 0),
                "intended_patterns": n,
                "unsafe_injected": unsafe,
                "median_ms": round(statistics.median(samples), 3),
                "min_ms": round(min(samples), 3),
                "max_ms": round(max(samples), 3),
                "safe": last.safe,
                "findings": len(last.findings),
                "allow_subject_states": last.allow_subject_states,
                "intended_subject_states": last.intended_subject_states,
            })
    with (out_dir / "benchmark.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)
    last = rows[-1]
    print(json.dumps({"rows": len(rows), "max_patterns": last["patterns"], "max_median_ms": last["median_ms"]}, indent=2))
    print(f"Wrote {out_dir/'benchmark.csv'}", flush=True)
    rows.clear(); gc.collect()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
