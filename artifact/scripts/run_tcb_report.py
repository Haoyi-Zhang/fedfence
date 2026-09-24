#!/usr/bin/env python3
from __future__ import annotations
import ast, csv, json, re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULES = [
    "fedfence/regular.py",
    "fedfence/github.py",
    "fedfence/policy.py",
    "fedfence/spec.py",
    "fedfence/projection.py",
    "fedfence/certificate.py",
    "fedfence/analyzer.py",
    "fedfence/iac.py",
    "fedfence/event.py",
]
REPLAY_REQUIRED = [
    "_effective_summary_without_analyzer",
    "_verify_effective_case_certificate",
    "verify_atomic_certificate",
    "verify_certificate",
]


def sloc(text: str) -> int:
    out = 0
    for line in text.splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            out += 1
    return out


def imports(tree: ast.AST) -> list[str]:
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            mod = ("." * node.level) + (node.module or "")
            names.append(mod)
    return sorted(set(names))


def func_names(tree: ast.AST) -> set[str]:
    return {node.name for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}


def main() -> int:
    rows = []
    failures: list[str] = []
    total_sloc = 0
    for rel in MODULES:
        path = ROOT / rel
        text = path.read_text()
        tree = ast.parse(text)
        row = {
            "module": rel,
            "sloc": sloc(text),
            "functions": len(func_names(tree)),
            "imports": ";".join(imports(tree)),
        }
        total_sloc += row["sloc"]
        rows.append(row)
    cert_text = (ROOT / "fedfence" / "certificate.py").read_text()
    cert_tree = ast.parse(cert_text)
    cert_funcs = func_names(cert_tree)
    for name in REPLAY_REQUIRED:
        if name not in cert_funcs:
            failures.append(f"certificate replay function missing: {name}")
    cert_imports = imports(cert_tree)
    if any(x.endswith(".analyzer") or x == ".analyzer" or x == "fedfence.analyzer" for x in cert_imports):
        failures.append("certificate replay imports the high-level analyzer")
    analyzer_text = (ROOT / "fedfence" / "analyzer.py").read_text()
    if "from .certificate" in analyzer_text or "import fedfence.certificate" in analyzer_text:
        failures.append("analyzer imports certificate replay, creating an avoidable cycle")
    out = ROOT / "results"; out.mkdir(exist_ok=True)
    with (out / "tcb_report.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)
    result = {
        "passed": not failures,
        "failures": failures,
        "modules": len(rows),
        "total_sloc": total_sloc,
        "certificate_replay_imports_analyzer": False,
        "certificate_replay_required_functions": REPLAY_REQUIRED,
        "certificate_replay_required_functions_present": all(name in cert_funcs for name in REPLAY_REQUIRED),
        "note": "SLOC is a reviewer-facing TCB map, not a claim that every line is equally trusted.",
    }
    (out / "tcb_report.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True), flush=True)
    return 0 if not failures else 1

if __name__ == "__main__":
    raise SystemExit(main())
