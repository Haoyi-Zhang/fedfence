"""Measure local analysis latency for the frozen public change pilot.

This is a small execution-cost check, not a scalability or production-throughput
claim. Source parsing is excluded because the corpus stores reviewed normalized
snapshots; the timing includes analyzer and certificate replay for before/after.
"""
from __future__ import annotations

from pathlib import Path
from datetime import datetime, timezone
import json
import platform
import statistics
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from fse_workflow.io import load_json, save_json  # noqa: E402
from fse_workflow.public_changes import analyze_change  # noqa: E402


def percentile(values: list[float], q: float) -> float:
    ordered = sorted(values)
    if not ordered:
        raise ValueError("empty values")
    rank = (len(ordered) - 1) * q
    low = int(rank)
    high = min(low + 1, len(ordered) - 1)
    frac = rank - low
    return ordered[low] * (1 - frac) + ordered[high] * frac


def main() -> int:
    corpus = load_json(ROOT / "study" / "public_change_corpus.json")
    rows = corpus["changes"]
    repeats = 7
    warmups = 1
    results = []
    for row in rows:
        for _ in range(warmups):
            analyze_change(row)
        samples = []
        for _ in range(repeats):
            start = time.perf_counter_ns()
            result = analyze_change(row)
            elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000
            if not result["source_alignment"]:
                raise RuntimeError(f"source alignment failed for {row['id']}")
            samples.append(elapsed_ms)
        results.append({
            "id": row["id"],
            "repeats": repeats,
            "median_ms": round(statistics.median(samples), 4),
            "p95_ms": round(percentile(samples, 0.95), 4),
            "min_ms": round(min(samples), 4),
            "max_ms": round(max(samples), 4),
        })
    all_samples = []
    # A second corpus-wide loop reports the cost of reviewing the full frozen pilot.
    for _ in range(warmups):
        for row in rows:
            analyze_change(row)
    for _ in range(repeats):
        start = time.perf_counter_ns()
        for row in rows:
            analyze_change(row)
        all_samples.append((time.perf_counter_ns() - start) / 1_000_000)
    out = {
        "schema": "fedfence-public-change-latency-v2",
        "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
        "python": sys.version,
        "platform": platform.platform(),
        "scope": "normalized public-change packets; analyzer plus certificate replay; source collection and IaC evaluation excluded",
        "repeats": repeats,
        "rows": results,
        "all_changes": {
            "median_ms": round(statistics.median(all_samples), 4),
            "p95_ms": round(percentile(all_samples, 0.95), 4),
            "min_ms": round(min(all_samples), 4),
            "max_ms": round(max(all_samples), 4),
        },
        "claim_boundary": "local execution-cost check only; not production tail latency or end-to-end CI time",
    }
    save_json(ROOT / "fse/results/public_change_latency.json", out)
    print(json.dumps(out["all_changes"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
