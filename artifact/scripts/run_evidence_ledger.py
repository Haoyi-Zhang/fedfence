#!/usr/bin/env python3
from __future__ import annotations
import argparse, csv, hashlib, json, re, subprocess
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SUBMISSION = ROOT.parent
PAPER = SUBMISSION / "paper"
RESULTS = ROOT / "results"

EXPECTED_TITLE_HASH = "a4617e06687cecf91bfc7853e16b982444e09c44886802d0c716470440b43425"
EXPECTED_ABSTRACT_HASH = "ffb368fcbcf0fab2977ff24baa06ab31493b10c4b57627c8182627cda046d3ca"
EXPECTED = {
    "curated_cases": 37,
    "public_examples": 20,
    "selected_claim_cases": 7,
    "projection_law_checks": 204288,
    "certificate_tamper_trials": 234,
    "certificate_tamper_rejected": 234,
    "adversarial_instances": 2240,
    "semantic_grid_obligations": 4480,
    "iac_roles": 3360,
    "differential_fuzz_checks": 2000,
    "metamorphic_checks": 768,
}


def norm(x: str) -> str:
    return re.sub(r"\s+", " ", x.strip())


def sha(x: str) -> str:
    return hashlib.sha256(x.encode()).hexdigest()


def json_file(name: str) -> dict[str, Any]:
    return json.loads((RESULTS / name).read_text())


def csv_count(name: str) -> int:
    with (RESULTS / name).open(newline="") as f:
        return sum(1 for _ in csv.DictReader(f))


def require_file(name: str, failures: list[str]) -> bool:
    ok = (RESULTS / name).exists()
    if not ok:
        failures.append(f"missing results/{name}")
    return ok


def pdf_info(path: Path) -> dict[str, Any]:
    out: dict[str, Any] = {}
    try:
        info = subprocess.check_output(["pdfinfo", str(path)], text=True, stderr=subprocess.STDOUT)
        m = re.search(r"Pages:\s+(\d+)", info)
        out["pages"] = int(m.group(1)) if m else None
        m = re.search(r"Page size:\s+([^\n]+)", info)
        out["page_size"] = m.group(1).strip() if m else ""
        fonts = subprocess.check_output(["pdffonts", str(path)], text=True, stderr=subprocess.STDOUT)
        out["has_type3"] = "Type 3" in fonts
        out["has_truetype"] = "TrueType" in fonts or "CID TrueType" in fonts
    except Exception as e:
        out["error"] = str(e)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", choices=["quick", "paper"], default="paper")
    args = ap.parse_args()
    failures: list[str] = []
    ledger: dict[str, Any] = {"profile": args.profile, "expected": EXPECTED, "observed": {}, "optional": {}}

    registered_case_files = sorted((ROOT / "cases").glob("*.json"))
    hardening_case_files = sorted((ROOT / "hardening_cases").glob("*.json"))
    ledger["optional"]["registered_case_files"] = len(registered_case_files)
    ledger["optional"]["hardening_case_files"] = len(hardening_case_files)
    if len(registered_case_files) != EXPECTED["curated_cases"]:
        failures.append(f"registered cases directory has {len(registered_case_files)} JSON files; expected {EXPECTED['curated_cases']}")
    if len(hardening_case_files) and not (RESULTS / "hardening_case_summary.csv").exists():
        failures.append("optional hardening cases exist but results/hardening_case_summary.csv is missing")

    tex = (PAPER / "main.tex").read_text()
    title = norm(re.search(r"\\title\{([^}]*)\}", tex, re.S).group(1))
    abstract = norm(re.search(r"\\begin\{abstract\}(.*?)\\end\{abstract\}", tex, re.S).group(1))
    ledger["title_hash"] = sha(title)
    ledger["abstract_hash"] = sha(abstract)
    if ledger["title_hash"] != EXPECTED_TITLE_HASH:
        failures.append("title hash differs from registered baseline")
    if ledger["abstract_hash"] != EXPECTED_ABSTRACT_HASH:
        failures.append("abstract hash differs from registered baseline")

    pdf = pdf_info(PAPER / "fedfence_sp2027.pdf")
    ledger["pdf"] = pdf
    if pdf.get("pages") != 18:
        failures.append(f"compiled PDF page count is not 18: {pdf.get('pages')}")
    if "612 x 792" not in str(pdf.get("page_size", "")):
        failures.append(f"compiled PDF is not US letter: {pdf.get('page_size')}")
    if pdf.get("has_type3") or pdf.get("has_truetype"):
        failures.append("compiled PDF contains Type 3 or TrueType fonts")

    quick_files = [
        "case_summary.csv", "public_examples_overall.json", "claim_projection_overall.json",
        "label_audit_overall.json", "baseline_suite_overall.json",
        "certificate_summary.csv", "certificate_tamper_overall.json", "replay_oracle_overall.json",
        "public_source_metadata_overall.json", "external_evidence_overall.json", "provider_drift_overall.json", "deployment_manifest_overall.json",
        "governance_export_audit.json", "iac_frontier_overall.json",
        "submission_audit.json", "tcb_report.json", "code_metrics.json", "max_narrowing_sanity.json",
    ]
    paper_files = quick_files + [
        "projection_laws_overall.json", "adversarial_matrix_overall.json", "semantic_grid_overall.json",
        "iac_overall.json", "differential_fuzz_overall.json", "metamorphic_overall.json",
        "minimal_basis_overall.json", "definability.csv", "benchmark.csv",
    ]
    needed = paper_files if args.profile == "paper" else quick_files
    for name in needed:
        require_file(name, failures)

    obs = ledger["observed"]
    if (RESULTS / "case_summary.csv").exists():
        obs["curated_cases"] = csv_count("case_summary.csv")
    if (RESULTS / "hardening_case_summary.csv").exists():
        ledger["optional"]["hardening_case_results"] = csv_count("hardening_case_summary.csv")
    if (RESULTS / "public_examples_overall.json").exists():
        obs["public_examples"] = json_file("public_examples_overall.json").get("examples")
    if (RESULTS / "label_audit_overall.json").exists():
        ind = json_file("label_audit_overall.json")
        ledger["optional"]["label_audit"] = ind
        if not ind.get("passed") or ind.get("uses_fedfence_imports"):
            failures.append("standalone label audit did not pass or imports FedFence")
    if (RESULTS / "baseline_suite_overall.json").exists():
        bs = json_file("baseline_suite_overall.json")
        ledger["optional"]["baseline_suite"] = bs
        if bs.get("best_baseline_correct", 0) >= bs.get("fedfence_correct", 0):
            failures.append("strongest baseline matches or exceeds FedFence on registered/public suite")
    if (RESULTS / "claim_projection_overall.json").exists():
        obs["selected_claim_cases"] = json_file("claim_projection_overall.json").get("cases")
    if (RESULTS / "projection_laws_overall.json").exists():
        pl = json_file("projection_laws_overall.json")
        obs["projection_law_checks"] = int(pl.get("galois_checks", 0)) + int(pl.get("kernel_saturation_checks", 0))
    if (RESULTS / "certificate_tamper_overall.json").exists():
        ct = json_file("certificate_tamper_overall.json")
        obs["certificate_tamper_trials"] = ct.get("tamper_trials")
        obs["certificate_tamper_rejected"] = ct.get("rejected")
    if (RESULTS / "adversarial_matrix_overall.json").exists():
        obs["adversarial_instances"] = json_file("adversarial_matrix_overall.json").get("total_cases")
    if (RESULTS / "semantic_grid_overall.json").exists():
        sg = json_file("semantic_grid_overall.json")
        obs["semantic_grid_obligations"] = sg.get("total_cases")
        ledger["optional"]["semantic_grid_profile"] = sg.get("profile", "registered")
        if args.profile == "paper" and sg.get("templates") != 35:
            failures.append(f"semantic-grid registered profile should use 35 templates, observed {sg.get('templates')}")
    if (RESULTS / "iac_overall.json").exists():
        iac = json_file("iac_overall.json")
        obs["iac_roles"] = iac.get("total_roles")
        ledger["optional"]["iac_profile"] = iac.get("profile", "registered")
        if args.profile == "paper" and iac.get("templates") != 35:
            failures.append(f"IaC registered profile should use 35 templates, observed {iac.get('templates')}")
    if (RESULTS / "differential_fuzz_overall.json").exists():
        obs["differential_fuzz_checks"] = json_file("differential_fuzz_overall.json").get("checks")
    if (RESULTS / "metamorphic_overall.json").exists():
        obs["metamorphic_checks"] = json_file("metamorphic_overall.json").get("total_checks")
    for k, v in EXPECTED.items():
        if k in obs and obs[k] != v:
            failures.append(f"evidence count mismatch for {k}: observed {obs[k]}, expected {v}")
        elif args.profile == "paper" and k not in obs:
            failures.append(f"evidence count {k} could not be observed in paper profile")


    if (RESULTS / "replay_oracle_overall.json").exists():
        ro = json_file("replay_oracle_overall.json")
        ledger["optional"]["replay_oracle_rows"] = ro.get("rows")
        ledger["optional"]["replay_oracle_groups"] = ro.get("groups", {})
        if ro.get("verified") != ro.get("rows"):
            failures.append("replay oracle did not verify every row")
        if ro.get("matches_expected_labels") != ro.get("expected_labeled_rows"):
            failures.append("replay oracle disagrees with at least one expected label")
    if (RESULTS / "external_evidence_overall.json").exists():
        ee = json_file("external_evidence_overall.json")
        ledger["optional"]["optional_public_issue_challenge"] = ee.get("optional_public_issue_challenge")
        if ee.get("optional_public_issue_challenge") and ee.get("optional_correct") != ee.get("optional_public_issue_challenge"):
            failures.append("optional public issue challenge examples did not all match expected labels")


    if (RESULTS / "provider_drift_overall.json").exists():
        pd = json_file("provider_drift_overall.json")
        ledger["optional"]["provider_drift_cases"] = pd
        if not pd.get("passed") or pd.get("correct") != pd.get("cases"):
            failures.append("provider-drift cases did not all match expected labels")

    if (RESULTS / "iac_frontier_overall.json").exists():
        frontier = json_file("iac_frontier_overall.json")
        ledger["optional"]["iac_frontier"] = frontier
        if not frontier.get("passed"):
            failures.append("IaC frontier corpus did not pass")

    if (RESULTS / "deployment_manifest_overall.json").exists():
        dm = json_file("deployment_manifest_overall.json")
        ledger["optional"]["deployment_manifest"] = dm
        if not dm.get("passed") or not dm.get("uses_same_proof_path_as_registered_cases"):
            failures.append("deployment manifest proof path did not pass")
    if (RESULTS / "governance_export_audit.json").exists():
        ge = json_file("governance_export_audit.json")
        ledger["optional"]["governance_export_audit"] = ge
        if not ge.get("passed") or ge.get("verified") != ge.get("premises"):
            failures.append("governance export audit did not verify every premise")

    sub_audit = json_file("submission_audit.json") if (RESULTS / "submission_audit.json").exists() else {}
    if sub_audit and not sub_audit.get("passed"):
        failures.append("submission audit did not pass")
    tcb = json_file("tcb_report.json") if (RESULTS / "tcb_report.json").exists() else {}
    if tcb and not tcb.get("passed"):
        failures.append("TCB report did not pass")
    cm = json_file("code_metrics.json") if (RESULTS / "code_metrics.json").exists() else {}
    if cm and not cm.get("passed"):
        failures.append("code metrics manifest checks did not pass")
    if cm:
        ledger["optional"]["code_metrics"] = cm.get("totals", {})

    if (RESULTS / "max_narrowing_sanity.json").exists():
        mn = json_file("max_narrowing_sanity.json")
        ledger["optional"]["max_narrowing_sanity"] = mn
        if not mn.get("passed") or not mn.get("wrong_formula_counterexample_found"):
            failures.append("max-narrowing sanity audit did not pass or did not record wrong-formula counterexample")
        if mn.get("checked_candidate_narrowings") != 248832:
            failures.append(f"max-narrowing candidate count mismatch: {mn.get('checked_candidate_narrowings')}")

    ledger["passed"] = not failures
    ledger["failures"] = failures
    (RESULTS / "evidence_ledger.json").write_text(json.dumps(ledger, indent=2, sort_keys=True) + "\n")
    print(json.dumps(ledger, indent=2, sort_keys=True), flush=True)
    return 0 if not failures else 1

if __name__ == "__main__":
    raise SystemExit(main())
