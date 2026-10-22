#!/usr/bin/env python3
"""Record an actual forced native paper build; status queries never rewrite evidence."""
from datetime import datetime, timezone
from pathlib import Path
import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys

PAPER = Path(globals().get("MANUSCRIPT_DIR", Path(__file__).resolve().parents[2] / "paper"))
SUPPORT = Path(__file__).resolve().parent
RECORD = SUPPORT / "build_environment.json"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def version(name):
    return subprocess.check_output([name, "--version"], text=True,
                                   errors="replace", timeout=5).splitlines()[0]


def recorded_inputs():
    paths = set()
    for line in (PAPER / "main.fls").read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("INPUT "):
            path = Path(line[6:].strip('"'))
            paths.add((PAPER / path).resolve())
    classes = {p for p in paths if p.name == "acmart.cls" and p.is_file()}
    if len(classes) != 1:
        raise ValueError("The fresh TeX recorder must identify exactly one consumed acmart.cls")
    selected = next(iter(classes))
    sources = {p.relative_to(PAPER).as_posix(): sha(p) for p in paths
               if p.is_relative_to(PAPER) and p.is_file()
               and p.suffix in {".tex", ".cls", ".sty", ".pdf", ".bst"}}
    for name in ("references.bib", ".latexmkrc", "Makefile"):
        sources[name] = sha(PAPER / name)
    return selected, sources


def build(pdf, latexmk):
    started = datetime.now(timezone.utc).isoformat()
    figure_command = [sys.executable, "-B", "figures/draw_local_costs.py"]
    # The direct native entrypoint must enforce the same selected-data check as make.
    subprocess.run(figure_command, cwd=PAPER, check=True, timeout=10)
    command = [latexmk, "-gg", "-pdf", "-recorder", "-interaction=nonstopmode",
               "-halt-on-error", "-latexoption=-no-shell-escape", "main.tex"]
    # -gg forces native execution even when a supplied PDF is already up to date.
    # A failed build leaves the earlier environment record unchanged.
    log = SUPPORT / "native_build.log"
    with log.open("w", encoding="utf-8") as stream:
        subprocess.run(command, cwd=PAPER, check=True, stdout=stream,
                       stderr=subprocess.STDOUT, timeout=150,
                       env={**os.environ, "LC_ALL": "C", "LANG": "C"})
    selected, sources = recorded_inputs()
    class_data = selected.read_bytes()
    found = re.search(r"\\ProvidesClass\{acmart\}\s*\[([^]]+)\]",
                      class_data.decode(errors="replace"))
    if not found:
        raise ValueError("Cannot identify the class consumed by the completed build")
    bibliography = next((shutil.which(n) for n in ("bibtex", "bibtex.original", "bibtex8")
                         if shutil.which(n)), None)
    if bibliography is None:
        raise ValueError("No native bibliography executable found")
    record = dict(
        schema="fedfence-native-paper-build-v1",
        build_started_utc=started, build_completed_utc=datetime.now(timezone.utc).isoformat(),
        scope="Native typesetting of selected retained results; no scientific drivers or measurements run.",
        figure_command=["<PYTHON>", *figure_command[1:]],
        selected_scaling_csv_sha256=sha(PAPER.parent / "artifact/tosem/results/local_scaling.csv"),
        selected_scaling_json_sha256=sha(PAPER.parent / "artifact/tosem/results/local_scaling.json"),
        build_command=[Path(command[0]).name, *command[1:]], build_exit_code=0,
        bibliography_engine=version(bibliography), latex_engine=version("pdflatex"),
        acmart_declaration=found.group(1), acmart_sha256=sha(selected),
        class_source=("local-vendor" if selected.is_relative_to(PAPER / "vendor")
                      else "installed-system-package"),
        pinned_optional_release="2.20",
        compiled_with_current_release="v2.20" in found.group(1),
        release_label_scope="2.20 is the optional pinned bootstrap, not a latest-release query.",
        python=sys.version, platform=platform.platform(),
        font_files_distributed=False, production_TAPS_certified=False,
        paper_inputs_sha256=sources, recorder_sha256=sha(PAPER / "main.fls"),
        build_log="native_build.log", build_log_sha256=sha(log))
    shutil.copyfile(PAPER / "main.pdf", pdf)
    record["pdf_sha256"] = sha(pdf)
    # Complete only after native execution and input/PDF inspection succeeded.
    temporary = RECORD.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, RECORD)
    return record


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", action="store_true", help="force latexmk and record only a successful native build")
    parser.add_argument("--latexmk", default="latexmk", help="native latexmk executable")
    parser.add_argument("--pdf", type=Path, default=Path("FedFence_TOSEM.pdf"))
    args = parser.parse_args(argv)
    pdf = (PAPER / args.pdf).resolve()
    if pdf != (PAPER / "FedFence_TOSEM.pdf").resolve():
        raise ValueError("Only the registered sibling-paper PDF may be built or queried")
    if args.build:
        record = build(pdf, args.latexmk)
    else:
        record = json.loads(RECORD.read_text(encoding="utf-8"))
        record["status_pdf_matches_record"] = pdf.is_file() and record.get("pdf_sha256") == sha(pdf)
        record["status_operation"] = "Read-only; no build or record update performed"
    print(json.dumps(record, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
