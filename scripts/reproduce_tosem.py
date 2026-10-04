#!/usr/bin/env python3
"""Reproduce the current TOSEM evidence locally. No network or cloud calls."""
from __future__ import annotations
import argparse, json, os, platform, re, shutil, subprocess, sys, time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from fse_workflow.io import save_json
from fse_workflow.gate import implementation_digest

def main(argv=None):
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--paper',action='store_true',help='also compile the sibling paper and audit it')
    args=ap.parse_args(argv)
    out=ROOT/'tosem/results'; logs=ROOT/'logs';out.mkdir(parents=True,exist_ok=True);logs.mkdir(exist_ok=True)
    commands=[('unit-tests',[sys.executable,'scripts/run_fse_tests.py']),
              ('core-self-check',[sys.executable,'artifact/scripts/self_check.py']),
              ('projection-audit',[sys.executable,'scripts/run_finite_audit.py']),
              ('relational-audit',[sys.executable,'scripts/run_relational_audit.py']),
              ('two-sided-validation',[sys.executable,'scripts/run_tosem_validation.py']),
              ('character-domain',[sys.executable,'scripts/run_character_domain_audit.py']),
              ('final-boundaries',[sys.executable,'scripts/run_final_validation.py']),
              ('seeded-faults',[sys.executable,'scripts/run_seeded_faults.py']),
              ('repair-audit',[sys.executable,'scripts/run_repair_audit.py']),
              ('source-studies',[sys.executable,'scripts/run_tosem_studies.py'])]
    if sys.flags.optimize:
        raise RuntimeError('reproduction requires assertions enabled; do not run with -O')
    rows=[]; env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1','PYTHONOPTIMIZE':'0'}
    for name,cmd in commands:
        started=time.perf_counter(); log=logs/(name+'.log')
        with log.open('w') as stream:
            r=subprocess.run(cmd,cwd=ROOT,env=env,stdout=stream,stderr=subprocess.STDOUT,check=False)
        row=dict(name=name,command=cmd,exit_code=r.returncode,seconds=time.perf_counter()-started,log=str(log.relative_to(ROOT)))
        rows.append(row);print(json.dumps(row),flush=True)
        if r.returncode:
            save_json(out/'reproduction.json',dict(passed=False,steps=rows));return r.returncode
    shutil.copyfile(ROOT/'fse/results/unit_tests.json',out/'unit_tests.json')
    shutil.copyfile(ROOT/'fse/results/finite_semantics_audit.json',out/'finite_semantics_audit.json')
    shutil.copyfile(ROOT/'results/repair_audit.json',out/'repair_audit.json')
    text=(logs/'core-self-check.log').read_text()
    match=re.search(r'self-check passed \((\d+) bounded and symbolic comparisons\)',text)
    if not match:raise RuntimeError('self-check completed without its expected evidence summary')
    save_json(out/'core_self_check.json',dict(passed=True,comparisons=int(match[1]),scope='bounded words over ab: plus symbolic regression examples; not provider equivalence'))
    save_json(out/'reproduction.json',dict(passed=True,steps=rows,implementation_sha256=implementation_digest(),python=sys.version,platform=platform.platform(),network_access=False,cloud_accounts_used=False))
    subprocess.run([sys.executable,'scripts/generate_tosem_tables.py'],cwd=ROOT,check=True,env=env)
    if args.paper:
        subprocess.run(['make','-C',str(ROOT.parent/'paper')],cwd=ROOT,check=True,env=env)
        subprocess.run([sys.executable,'scripts/audit_tosem.py'],cwd=ROOT,check=True,env=env)
    return 0
if __name__=='__main__':raise SystemExit(main())
