"""Run an explicitly supplied tool command on local files, preserving raw evidence.

Example: python scripts/run_external_tool.py --input role.cfn.json --output run.json -- checkov -f role.cfn.json --framework cloudformation -o json
No command is launched automatically by the reproduction pipeline. Inspect the
command before running: cloud/SaaS commands may require authorization and may
send configuration to an external service. This wrapper never invokes a shell.
"""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from fse_workflow.io import save_json
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--input',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
p.add_argument('--timeout',type=float,default=120);p.add_argument('command',nargs=argparse.REMAINDER)
a=p.parse_args();cmd=a.command[1:] if a.command[:1]==['--'] else a.command
if not cmd: p.error('an explicit command is required')
record={'command':cmd,'input_sha256':hashlib.sha256(a.input.read_bytes()).hexdigest(),
        'status':'not_run','predicted_label':None,'accuracy':None}
exe=shutil.which(cmd[0])
if not exe:
    record['reason']='executable unavailable'
else:
    t=time.perf_counter()
    try:
        r=subprocess.run(cmd,capture_output=True,text=True,timeout=a.timeout)
        record.update(status='completed',exit_code=r.returncode,stdout=r.stdout,stderr=r.stderr,
                      elapsed_seconds=time.perf_counter()-t)
    except subprocess.TimeoutExpired:
        record.update(status='timeout',elapsed_seconds=time.perf_counter()-t)
save_json(a.output,record)
print(record['status'])
raise SystemExit(0 if record['status']=='completed' else 2)
