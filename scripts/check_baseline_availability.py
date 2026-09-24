"""Discovery only. No fabricated execution or accuracy if an executable is absent."""
import shutil
import subprocess
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT))
from fse_workflow.io import save_json
rows=[]
for tool, argv in [('checkov',['checkov','--version']),('tfsec',['tfsec','--version']),('trivy',['trivy','--version']),('opa',['opa','version']),('aws',['aws','--version'])]:
    exe=shutil.which(tool)
    row={'tool':tool,'executable':exe,'benchmark_status':'not_run','version_status':'unavailable','version':None}
    if exe:
        try:
            p=subprocess.run(argv,capture_output=True,text=True,timeout=10)
            row.update(version_status='queried',version=(p.stdout+p.stderr).strip(),version_exit=p.returncode)
        except Exception as exc:
            row.update(version_status='query_failed',error=type(exc).__name__)
    rows.append(row)
save_json(ROOT/'fse/results/external_tool_availability.json',{'tools':rows,'actual_comparative_benchmark_runs':0,
          'note':'version discovery is not a benchmark; tool absence does not count as a missed vulnerability'})
print(rows)
