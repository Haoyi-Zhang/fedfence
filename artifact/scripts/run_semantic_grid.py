#!/usr/bin/env python3
from __future__ import annotations
import csv, json, os, statistics, sys, time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from fedfence.analyzer import analyze_case  # noqa: E402
from scripts.run_iac_scale import TEMPLATES, make_template, _TEMPLATE_PROFILE, REGISTERED_TEMPLATES, HARDENING_TEMPLATES  # noqa: E402

def one(template: str, i: int):
    repo = f"g{i:x}"
    case, expected = make_template(template, repo)
    t0 = time.perf_counter(); res = analyze_case(case); ms = (time.perf_counter() - t0) * 1000
    return {"template": template, "atom": i, "expected_safe": expected, "fedfence_safe": bool(res.safe), "correct": bool(res.safe) == bool(expected), "findings": len(res.findings), "ms": round(ms, 3), "transported": False}

def transported_grid(per: int):
    # The service atom occurs only in literal owner/repository positions.  The
    # paper proves certificate transport under delimiter-preserving injective
    # renaming, so one representative per template can be replayed and then
    # transported over the remaining atoms.  Set FEDFENCE_GRID_TRANSPORT=0 to
    # force direct analysis of every atom.
    reps = {t: one(t, 0) for t in TEMPLATES}
    rows = []
    for t in TEMPLATES:
        rep = reps[t]
        for i in range(per):
            r = dict(rep)
            r["atom"] = i
            r["transported"] = bool(i != 0)
            rows.append(r)
    return rows

def main() -> int:
    per = int(os.environ.get("FEDFENCE_GRID_PER", "128"))
    workers = int(os.environ.get("FEDFENCE_GRID_WORKERS", "4"))
    transport = os.environ.get("FEDFENCE_GRID_TRANSPORT", "0") != "0"
    tasks = [(t, i) for t in TEMPLATES for i in range(per)]
    rows = []
    if transport:
        rows = transported_grid(per)
        print(f"  semantic-grid transport: {len(TEMPLATES)} representatives -> {len(rows)} cases", flush=True)
    elif workers > 1:
        with ProcessPoolExecutor(max_workers=workers) as ex:
            futs = [ex.submit(one, t, i) for t, i in tasks]
            for k, fut in enumerate(as_completed(futs), 1):
                rows.append(fut.result())
                if k % 256 == 0 or k == len(futs):
                    print(f"  semantic-grid progress: {k}/{len(futs)}", flush=True)
    else:
        for k, (t, i) in enumerate(tasks, 1):
            rows.append(one(t, i))
            if k % 256 == 0 or k == len(tasks):
                print(f"  semantic-grid progress: {k}/{len(tasks)}", flush=True)
    out = ROOT / "results"; out.mkdir(exist_ok=True)
    rows.sort(key=lambda r: (r["template"], r["atom"]))
    with (out / "semantic_grid.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
    by_template = {t: {"n": 0, "correct": 0, "times": [], "unsafe": 0, "transported": 0} for t in TEMPLATES}
    for r in rows:
        d = by_template[r["template"]]
        d["n"] += 1; d["correct"] += int(r["correct"]); d["unsafe"] += int(not r["expected_safe"]); d["times"].append(float(r["ms"])); d["transported"] += int(r.get("transported", False))
    summary = []
    for t, d in by_template.items():
        times = d["times"]
        summary.append({"template": t, "n": d["n"], "unsafe": d["unsafe"], "correct": d["correct"], "transported": d["transported"], "median_ms": round(statistics.median(times), 3), "p95_ms": round(statistics.quantiles(times, n=20)[18], 3) if len(times)>=20 else round(max(times), 3)})
    with (out / "semantic_grid_summary.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(summary[0].keys())); w.writeheader(); w.writerows(summary)
    all_times = [float(r["ms"]) for r in rows]
    overall = {"profile": _TEMPLATE_PROFILE, "registered_templates": len(REGISTERED_TEMPLATES), "hardening_templates": len(HARDENING_TEMPLATES), "total_cases": len(rows), "templates": len(TEMPLATES), "per_template": per, "representatives": len(TEMPLATES) if transport else len(rows), "transported_cases": sum(1 for r in rows if r.get("transported", False)), "correct": sum(1 for r in rows if r["correct"]), "unsafe_cases": sum(1 for r in rows if not r["expected_safe"]), "median_ms": round(statistics.median(all_times), 3), "p95_ms": round(statistics.quantiles(all_times, n=20)[18], 3), "transport_mode": bool(transport)}
    (out / "semantic_grid_overall.json").write_text(json.dumps(overall, indent=2, sort_keys=True))
    print(json.dumps(overall, indent=2, sort_keys=True))
    return 0 if overall["correct"] == overall["total_cases"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
