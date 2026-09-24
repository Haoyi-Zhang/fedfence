#!/usr/bin/env python3
from __future__ import annotations
import copy, csv, json, os, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from fedfence.certificate import certificate_for_case, verify_certificate  # noqa: E402


def load_case(path: Path) -> dict:
    return json.loads(path.read_text())


def tamperers(cert: dict) -> list[tuple[str, dict]]:
    out: list[tuple[str, dict]] = []
    c = copy.deepcopy(cert); c["verdict"] = "safe" if cert.get("verdict") == "unsafe" else "unsafe"; out.append(("flip-verdict", c))
    c = copy.deepcopy(cert); c.setdefault("replay_summary", {})["safe"] = not bool(c.get("replay_summary", {}).get("safe", False)); out.append(("flip-summary-safe", c))
    c = copy.deepcopy(cert); c.setdefault("policy_profile", {}).setdefault("allows", []).append({"index":999,"effect":"Allow"}); out.append(("add-fake-allow-profile", c))
    if cert.get("replay_summary", {}).get("blocking_kinds"):
        c = copy.deepcopy(cert); c.setdefault("replay_summary", {})["blocking_kinds"] = []; out.append(("drop-blocking-kinds", c))
    if cert.get("replay_summary", {}).get("witnesses"):
        c = copy.deepcopy(cert); c.setdefault("replay_summary", {})["witnesses"] = ["tampered-witness"]; out.append(("replace-witnesses", c))
    c = copy.deepcopy(cert); c.pop("case", None); out.append(("remove-embedded-case", c))
    c = copy.deepcopy(cert); c["certificate_components"] = []; out.append(("drop-component-list", c))
    return out


def main() -> int:
    case_paths = sorted((ROOT / "cases").glob("*.json"))
    limit = int(os.environ.get("FEDFENCE_CERT_LIMIT", os.environ.get("FEDFENCE_CASE_LIMIT", "0")))
    if limit > 0:
        case_paths = case_paths[:limit]
    rows = []
    unexpected_accepts = []
    for path in case_paths:
        case = load_case(path)
        cert = certificate_for_case(case)
        ok, notes = verify_certificate(cert)
        if not ok:
            raise RuntimeError(f"base certificate does not verify for {path.name}: {notes}")
        for family, bad in tamperers(cert):
            ok_bad, note_bad = verify_certificate(bad)
            rejected = not bool(ok_bad)
            rows.append({"case": path.stem, "tamper": family, "rejected": rejected, "verifier_note": ";".join(note_bad) if isinstance(note_bad, list) else str(note_bad)})
            if not rejected:
                unexpected_accepts.append({"case": path.stem, "tamper": family})
    out = ROOT / "results"; out.mkdir(exist_ok=True)
    with (out / "certificate_tamper.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
    overall = {"certificates": len(case_paths), "tamper_trials": len(rows), "rejected": sum(1 for r in rows if r["rejected"]), "unexpected_accepts": unexpected_accepts}
    (out / "certificate_tamper_overall.json").write_text(json.dumps(overall, indent=2, sort_keys=True) + "\n")
    print(json.dumps(overall, indent=2, sort_keys=True), flush=True)
    return 0 if not unexpected_accepts else 1


if __name__ == "__main__":
    raise SystemExit(main())
