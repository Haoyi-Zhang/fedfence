from __future__ import annotations

import argparse
from pathlib import Path

from .analyzer import analyze_case, load_case, result_to_json


def main() -> int:
    ap = argparse.ArgumentParser(description="FedFence OIDC federation policy checker")
    ap.add_argument("case", type=Path, help="JSON/YAML case file")
    ap.add_argument("--json", action="store_true", help="print machine-readable JSON")
    args = ap.parse_args()

    result = analyze_case(load_case(args.case))
    if args.json:
        print(result_to_json(result))
    else:
        verdict = "SAFE" if result.safe else "UNSAFE"
        print(f"{args.case.name}: {verdict}")
        for f in result.findings:
            loc = f" [statement {f.statement}]" if f.statement is not None else ""
            print(f"- {f.severity.upper()} {f.kind}{loc}: {f.message}")
            if f.witness:
                print(f"  witness: {f.witness}")
    return 0 if result.safe else 1

if __name__ == "__main__":
    raise SystemExit(main())
