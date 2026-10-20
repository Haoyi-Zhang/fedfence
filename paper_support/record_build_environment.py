#!/usr/bin/env python3
"""Record the class actually selected by TeX, not merely a desired version."""
from pathlib import Path
import argparse, hashlib, json, platform, re, shutil, subprocess, sys
PAPER=Path(globals().get("MANUSCRIPT_DIR", Path(__file__).resolve().parents[2] / "paper"))
SUPPORT=Path(__file__).resolve().parent
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--pdf',type=Path);args=ap.parse_args()
    path=Path(subprocess.check_output(['kpsewhich','acmart.cls'],text=True,cwd=PAPER).strip())
    if not path.is_absolute():path=PAPER/path
    data=path.read_bytes(); text=data.decode(errors='replace')
    found=re.search(r'\\ProvidesClass\{acmart\}\s*\[([^]]+)\]',text)
    version=found.group(1) if found else 'unparsed'
    bibtex=next((shutil.which(name) for name in ('bibtex','bibtex.original','bibtex8') if shutil.which(name)), None)
    record=dict(bibliography_engine=(subprocess.check_output([bibtex,'--version'],text=True).splitlines()[0] if bibtex else 'missing'),acmart_declaration=version,acmart_sha256=hashlib.sha256(data).hexdigest(),
        class_source='verified-local-vendor' if str(path).startswith(str(PAPER/'vendor')) else 'installed-system-package',
        official_current_release='2.20',compiled_with_current_release='v2.20' in version,
        latex_engine=subprocess.check_output(['pdflatex','--version'],text=True).splitlines()[0],
        python=sys.version,platform=platform.platform(),font_files_distributed=False,
        production_TAPS_certified=False)
    if args.pdf:
        pdf=args.pdf if args.pdf.is_absolute() else PAPER/args.pdf
        record['pdf_sha256']=hashlib.sha256(pdf.read_bytes()).hexdigest()
    SUPPORT.mkdir(parents=True,exist_ok=True)
    (SUPPORT/'build_environment.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record))
if __name__=='__main__':main()
