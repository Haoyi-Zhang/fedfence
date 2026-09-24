#!/usr/bin/env python3
from __future__ import annotations
import csv, hashlib, json, os, sys, time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from fedfence.analyzer import analyze_case, load_case  # noqa: E402


def canon(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def sha256(obj: Any) -> str:
    return hashlib.sha256(canon(obj)).hexdigest()


def load_manifest(path: Path) -> dict[str, Any]:
    obj = json.loads(path.read_text())
    if not isinstance(obj, dict) or not isinstance(obj.get("entries"), list):
        raise ValueError("manifest must be an object with an entries array")
    return obj


def load_entry_case(entry: dict[str, Any]) -> tuple[dict[str, Any], str]:
    if "case" in entry:
        case = entry["case"]
        if not isinstance(case, dict):
            raise ValueError(f"embedded case for {entry.get('id')} is not an object")
        return case, "embedded"
    rel = entry.get("case_path")
    if not isinstance(rel, str):
        raise ValueError(f"entry {entry.get('id')} has neither case nor case_path")
    path = (ROOT / rel).resolve()
    if ROOT not in path.parents and path != ROOT:
        raise ValueError(f"case_path escapes artifact root: {rel}")
    return load_case(path), str(path.relative_to(ROOT))


def main() -> int:
    manifest_path = Path(os.environ.get("FEDFENCE_DEPLOYMENT_MANIFEST", ROOT / "deployment_manifest" / "example_manifest.json"))
    manifest = load_manifest(manifest_path)
    out = ROOT / "results"
    out.mkdir(exist_ok=True)
    rows: list[dict[str, Any]] = []
    failures: list[str] = []
    for idx, entry in enumerate(manifest["entries"], start=1):
        if not isinstance(entry, dict):
            raise ValueError(f"manifest entry {idx} is not an object")
        case, case_source = load_entry_case(entry)
        t0 = time.perf_counter()
        result = analyze_case(case)
        ms = (time.perf_counter() - t0) * 1000.0
        expected = case.get("expected_safe")
        correct = (expected is None) or (bool(expected) == bool(result.safe))
        if not correct:
            failures.append(str(entry.get("id", f"row-{idx}")))
        rows.append({
            "id": entry.get("id", f"row-{idx}"),
            "source_type": entry.get("source_type", "role-review-object"),
            "source_ref": entry.get("source_ref", ""),
            "source_hash": entry.get("source_hash", ""),
            "case_source": case_source,
            "case_hash": sha256(case),
            "expected_safe": "" if expected is None else bool(expected),
            "fedfence_safe": bool(result.safe),
            "correct": correct,
            "findings": ";".join(f.kind for f in result.findings),
            "ms": round(ms, 3),
        })
    fields = ["id", "source_type", "source_ref", "source_hash", "case_source", "case_hash", "expected_safe", "fedfence_safe", "correct", "findings", "ms"]
    with (out / "deployment_manifest.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader(); w.writerows(rows)
    overall = {
        "manifest": str(manifest_path.relative_to(ROOT)) if manifest_path.is_relative_to(ROOT) else str(manifest_path),
        "schema": manifest.get("schema", ""),
        "rows": len(rows),
        "safe": sum(1 for r in rows if r["fedfence_safe"] is True),
        "unsafe_or_outside_core": sum(1 for r in rows if r["fedfence_safe"] is False),
        "expected_labeled_rows": sum(1 for r in rows if r["expected_safe"] != ""),
        "correct": sum(1 for r in rows if r["correct"] is True),
        "active_network_access": False,
        "cloud_credentials_required": False,
        "uses_same_proof_path_as_registered_cases": True,
        "passed": not failures,
        "failures": failures,
    }
    (out / "deployment_manifest_overall.json").write_text(json.dumps(overall, indent=2, sort_keys=True) + "\n")
    print(json.dumps(overall, indent=2, sort_keys=True))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
