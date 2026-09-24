#!/usr/bin/env python3
from __future__ import annotations
import json, os, re, subprocess, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
PAPER = ROOT / "paper" / "fedfence_sp2027.pdf"
TEX = ROOT / "paper" / "main.tex"

BAD_FILES = {".aux", ".log", ".out", ".toc", ".fls", ".fdb_latexmk", ".synctex.gz", ".pyc"}
BAD_DIRS = {"__pycache__", ".git", ".hg", ".svn", ".mypy_cache", ".pytest_cache", ".mplconfig"}
PATH_PREFIXES = ["/" + "home" + "/", "/" + "Users" + "/", "/" + "mnt" + "/" + "data" + "/"]
IDENTITY_PATTERNS = [re.compile(re.escape(prefix) + r"[^\s}]+") for prefix in PATH_PREFIXES]
IDENTITY_PATTERNS.append(re.compile(r"[A-Za-z0-9._%+-]+" + "@" + r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}"))


def fail(msg: str, failures: list[str]) -> None:
    failures.append(msg)


def run(cmd: list[str]) -> str:
    return subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)


def _check_pdf_fonts(path: Path, failures: list[str], label: str) -> None:
    fonts = run(["pdffonts", str(path)])
    if "Type 3" in fonts:
        fail(f"{label} contains Type 3 fonts", failures)
    for line in fonts.splitlines()[2:]:
        cols = line.split()
        if len(cols) >= 6 and cols[4].lower() != "yes":
            fail(f"{label} font is not embedded: {line}", failures)
        if "TrueType" in line or "CID TrueType" in line:
            fail(f"{label} contains TrueType font; use Type 1 only: {line}", failures)


def _column_baselines(path: Path, page_no: int) -> dict[str, float]:
    """Return the deepest occupied text baseline per column from pdftotext -bbox.

    This is a formatting sanity check, not a content proof. It catches accidental
    short boundary pages after late polishing while preserving the IEEE margins.
    """
    html = run(["pdftotext", "-bbox", str(path), "-"])
    pages = re.findall(r"<page[^>]*width=\"([0-9.]+)\"[^>]*height=\"([0-9.]+)\"[^>]*>(.*?)</page>", html, flags=re.S)
    if page_no < 1 or page_no > len(pages):
        return {"left": 0.0, "right": 0.0}
    width, _height, body = pages[page_no - 1]
    split = float(width) / 2.0
    left: list[float] = []
    right: list[float] = []
    for m in re.finditer(r"<word[^>]*xMin=\"([0-9.]+)\"[^>]*yMax=\"([0-9.]+)\"", body):
        x = float(m.group(1)); y = float(m.group(2))
        (left if x < split else right).append(y)
    return {"left": max(left) if left else 0.0, "right": max(right) if right else 0.0}


def check_boundary_fill(failures: list[str]) -> None:
    # IEEEtran leaves a normal bottom margin around y=720 on US letter pages.
    # We do not compress margins; we just reject boundary pages that stop an
    # obvious line or more above the template text block.
    threshold = 719.0
    for page_no, label in [(13, "main-text boundary"), (18, "final appendix")]:
        baselines = _column_baselines(PAPER, page_no)
        for col, y in baselines.items():
            if y < threshold:
                fail(f"{label} page {page_no} {col} column appears underfilled: last baseline y={y:.1f}", failures)


def check_pdf(failures: list[str]) -> None:
    info = run(["pdfinfo", str(PAPER)])
    pages = re.search(r"Pages:\s+(\d+)", info)
    size = re.search(r"Page size:\s+(.+)", info)
    if not pages or int(pages.group(1)) != 18:
        fail(f"PDF page count is not 18: {pages.group(1) if pages else 'unknown'}", failures)
    if not size or "612 x 792" not in size.group(1):
        fail(f"PDF is not US letter: {size.group(1) if size else 'unknown'}", failures)
    _check_pdf_fonts(PAPER, failures, "PDF")
    for fig in [ROOT / "paper" / "figures" / "benchmark.pdf", ROOT / "paper" / "figures" / "iac_cdf.pdf"]:
        if not fig.exists():
            fail(f"missing vector figure: {fig.relative_to(ROOT)}", failures)
        else:
            _check_pdf_fonts(fig, failures, str(fig.relative_to(ROOT)))
    check_boundary_fill(failures)


def check_tex(failures: list[str]) -> None:
    tex = TEX.read_text()
    if "\\documentclass[conference,compsoc]{IEEEtran}" not in tex:
        fail("paper does not use the required IEEEtran compsoc conference class", failures)
    if re.search(r"\\author\{\s*(Anonymous|Anonymized|Authors?)", tex, flags=re.I):
        fail("title page contains an anonymous/fake author block; S&P requires no author names", failures)
    body = tex.split("\\begin{thebibliography}")[0]
    if "\\texttt" in body:
        fail("body contains \\texttt", failures)
    if re.search(r"\\vspace\s*\{\s*-", tex) or "\\usepackage{geometry}" in tex or "\\baselinestretch" in tex:
        fail("paper appears to use format-scrunching commands", failures)
    main = tex.split("\\begin{thebibliography}")[0]
    sections = len(re.findall(r"(?m)^\\section\{", main))
    subsections = len(re.findall(r"(?m)^\\subsection\{", main))
    subsubs = len(re.findall(r"(?m)^\\subsubsection\{", main))
    if sections > 9 or subsections > 12 or subsubs != 0:
        fail(f"main-paper structure is report-like: sections={sections}, subsections={subsections}, subsubsections={subsubs}", failures)
    appendix = tex.split("\\appendices", 1)[1] if "\\appendices" in tex else ""
    app_sections = len(re.findall(r"(?m)^\\section\{", appendix))
    app_subsections = len(re.findall(r"(?m)^\\subsection\{", appendix))
    if app_sections > 4 or app_subsections != 0:
        fail(f"appendix structure is too fragmented: sections={app_sections}, subsections={app_subsections}", failures)
    if "\\usepackage{newtx" in tex or "newtxtext" in tex or "newtxmath" in tex:
        fail("paper modifies the IEEE template text/math font with newtx", failures)
    bib = tex.split("\\begin{thebibliography}")[-1]
    if "\\footnotesize" in bib or "\\scriptsize" in bib:
        fail("bibliography uses manual font-size compression", failures)
    markers = ("TO" + "DO", "FIX" + "ME")
    if any(marker in tex for marker in markers):
        fail("paper contains unfinished-task markers", failures)
    bibitems = set(re.findall(r"\\bibitem\{([^}]+)\}", tex))
    cites = set()
    for c in re.findall(r"\\cite\{([^}]+)\}", tex):
        cites.update(x.strip() for x in c.split(",") if x.strip())
    if not (55 <= len(bibitems) <= 70):
        fail(f"reference count {len(bibitems)} is outside the target 55--70 range", failures)
    unused = sorted(bibitems - cites)
    undefined = sorted(cites - bibitems)
    if unused:
        fail(f"unused bibliography entries: {unused[:8]}", failures)
    if undefined:
        fail(f"undefined citations: {undefined[:8]}", failures)
    for line in bib.splitlines():
        if "[Online]. Available:" in line and "accessed Jun. 12, 2026" not in line:
            fail(f"online reference lacks fixed access date: {line[:120]}", failures)


def check_tree(failures: list[str]) -> None:
    for p in ROOT.rglob("*"):
        rel = p.relative_to(ROOT)
        if any(part in BAD_DIRS for part in rel.parts):
            fail(f"forbidden temporary/VCS directory present: {rel}", failures)
        if p.is_file():
            if p.suffix in BAD_FILES or p.name.endswith("~") or p.name.startswith(".#"):
                fail(f"temporary/build file present: {rel}", failures)
            if p.stat().st_size > 4_000_000:
                fail(f"unexpectedly large file present: {rel}", failures)
            if p.suffix.lower() in {".tex", ".md", ".py", ".json", ".csv", ".yml", ".yaml", ".txt"}:
                text = p.read_text(errors="ignore")
                if any(rx.search(text) for rx in IDENTITY_PATTERNS):
                    fail(f"possible identity/local-path leak in {rel}", failures)


def main() -> int:
    failures: list[str] = []
    check_pdf(failures)
    check_tex(failures)
    check_tree(failures)
    out = ROOT / "artifact" / "results" / "submission_audit.json"
    out.parent.mkdir(exist_ok=True)
    result = {"passed": not failures, "failures": failures}
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    if failures:
        print(json.dumps(result, indent=2, sort_keys=True))
        return 1
    print("submission audit passed")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
