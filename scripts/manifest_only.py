"""Record current package inputs, without executing scientific project code."""
from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path

ARTIFACT = Path(__file__).resolve().parents[1]
PACKAGE = ARTIFACT.parent
PAPER = PACKAGE / "paper"
CURRENT_SCRIPTS = (
    "reproduce.py", "build_public_study_result.py", "run_repair_audit.py",
    "audit_source_frontier.py", "audit_basis_witness.py", "run_timing.py",
    "audit_consistency.py", "manifest_only.py",
)


def collect_inventory() -> dict:
    required = [PAPER / "main.tex", PAPER / "references.bib",
                ARTIFACT / "UNAVAILABLE_EVIDENCE.json",
                ARTIFACT / "study" / "corrections.json",
                ARTIFACT / "study" / "source_frontier_sample.json"]
    scripts = [ARTIFACT / "scripts" / name for name in CURRENT_SCRIPTS]
    missing = [str(path.relative_to(PACKAGE)) for path in required + scripts
               if not path.is_file()]
    if missing:
        raise ValueError("Missing required current input: " + ", ".join(missing))
    pdf = next((p for p in (PAPER / "FedFence.pdf", PACKAGE / "FedFence.pdf")
                if p.is_file()), None)
    if pdf is None:
        raise ValueError("No current FedFence.pdf was found in paper/ or the package root")
    with pdf.open("rb") as stream:
        if not stream.read(5).startswith(b"%PDF-"):
            raise ValueError("The selected manuscript does not have a PDF header")
    for script in scripts:
        ast.parse(script.read_text(encoding="utf-8-sig"), filename=str(script))
    unavailable = json.loads((ARTIFACT / "UNAVAILABLE_EVIDENCE.json").read_text(encoding="utf-8-sig"))
    result_files = []
    for path in sorted((ARTIFACT / "results").glob("*.json")):
        if path.name == "manifest.json":
            continue
        json.loads(path.read_text(encoding="utf-8-sig"))
        result_files.append({"path": str(path.relative_to(PACKAGE)),
                             "bytes": path.stat().st_size})
    return {
        "schema": "fedfence.current-package-inventory.v1",
        "mode": "inventory-only",
        "manuscript": {"source": "paper/main.tex", "bibliography": "paper/references.bib",
                       "pdf": str(pdf.relative_to(PACKAGE)), "pdf_bytes": pdf.stat().st_size},
        "current_scripts_parsed": list(CURRENT_SCRIPTS),
        "result_files": result_files,
        "unavailable_evidence": unavailable,
        "experiments_executed_by_this_command": False,
        "scientific_results_verified_by_this_command": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-only", action="store_true",
                        help="Validate inputs and syntax without writing any files")
    args = parser.parse_args()
    try:
        inventory = collect_inventory()
    except (OSError, ValueError, SyntaxError) as exc:
        parser.exit(1, f"Package input check failed: {exc}\n")
    if not args.check_only:
        destination = ARTIFACT / "results" / "manifest.json"
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(inventory, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(json.dumps({"input_check": "passed", "manifest_written": not args.check_only,
                      "experiments_executed": False, "result_files": len(inventory["result_files"])}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
