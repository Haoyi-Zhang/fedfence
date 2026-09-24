#!/usr/bin/env python3
from __future__ import annotations
import csv, json, sys, time
from pathlib import Path
from urllib.parse import urlparse
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from fedfence.analyzer import analyze_case, load_case  # noqa: E402

FIELDS = ["example", "expected_safe", "fedfence_safe", "correct", "findings", "source", "source_url", "source_host", "ms"]


def contains_wildcard_case(case):
    for st in case.get("policy", {}).get("Statement", []):
        for group in (st.get("Condition", {}) or {}).values():
            if isinstance(group, dict):
                for v in group.values():
                    vals = v if isinstance(v, list) else [v]
                    if any("*" in str(x) or "?" in str(x) for x in vals):
                        return True
    return False


def has_subject_and_audience(case):
    stmts = case.get("policy", {}).get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    ok_any = False
    for st in stmts:
        seen_sub = seen_aud = False
        for group in (st.get("Condition", {}) or {}).values():
            if isinstance(group, dict):
                for k in group:
                    seen_sub |= str(k).endswith(":sub") or str(k) == "sub"
                    seen_aud |= str(k).endswith(":aud") or str(k) == "aud"
        ok_any = ok_any or (seen_sub and seen_aud)
    return ok_any


def exact_env_linter(case):
    return has_subject_and_audience(case) and not contains_wildcard_case(case)


def update_baseline(acc, name, expected_safe, pred_safe):
    b = acc.setdefault(name, {"tp":0,"tn":0,"fp":0,"fn":0})
    if expected_safe and pred_safe:
        b["tn"] += 1
    elif expected_safe and not pred_safe:
        b["fp"] += 1
    elif not expected_safe and not pred_safe:
        b["tp"] += 1
    else:
        b["fn"] += 1


def main() -> int:
    rows = []
    out = ROOT / "results"; out.mkdir(exist_ok=True)
    baseline = {}
    for path in sorted((ROOT / "public_examples").glob("*.json")):
        case = load_case(path)
        t0 = time.perf_counter(); res = analyze_case(case); ms = (time.perf_counter() - t0) * 1000
        expected = bool(case.get("expected_safe"))
        url = str(case.get("source_url", ""))
        fed_safe = bool(res.safe)
        update_baseline(baseline, "FedFence", expected, fed_safe)
        update_baseline(baseline, "Presence", expected, has_subject_and_audience(case))
        update_baseline(baseline, "Wildcard", expected, (not contains_wildcard_case(case) and has_subject_and_audience(case)))
        update_baseline(baseline, "ExactEnv", expected, exact_env_linter(case))
        rows.append({
            "example": case.get("name", path.stem),
            "expected_safe": expected,
            "fedfence_safe": fed_safe,
            "correct": fed_safe == expected,
            "findings": ";".join(f.kind for f in res.findings),
            "source": case.get("public_source", ""),
            "source_url": url,
            "source_host": urlparse(url).netloc,
            "ms": round(ms, 3),
        })
        (out / f"{path.stem}.public_result.json").write_text(json.dumps({
            "safe": res.safe,
            "findings": [f.__dict__ for f in res.findings],
            "source": case.get("public_source", ""),
            "source_url": url,
        }, indent=2, sort_keys=True) + "\n")
    with (out / "public_examples.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS); w.writeheader(); w.writerows(rows)
    base_rows=[]
    for name,b in baseline.items():
        tp,tn,fp,fn=b["tp"],b["tn"],b["fp"],b["fn"]
        base_rows.append({"analyzer":name,"tp_unsafe":tp,"tn_safe":tn,"false_alarm":fp,"miss":fn,
                          "unsafe_recall":round(tp/(tp+fn),4) if tp+fn else 1.0,
                          "unsafe_precision":round(tp/(tp+fp),4) if tp+fp else 1.0,
                          "safe_acceptance":round(tn/(tn+fp),4) if tn+fp else 1.0})
    with (out / "public_baselines.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(base_rows[0].keys())); w.writeheader(); w.writerows(base_rows)
    overall = {
        "examples": len(rows),
        "correct": sum(1 for r in rows if r["correct"]),
        "unsafe": sum(1 for r in rows if not r["expected_safe"]),
        "hosts": sorted({r["source_host"] for r in rows}),
        "baselines": len(base_rows),
    }
    (out / "public_examples_overall.json").write_text(json.dumps(overall, indent=2, sort_keys=True) + "\n")
    print(json.dumps(overall, indent=2, sort_keys=True), flush=True)
    return 0 if overall["correct"] == overall["examples"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
