from __future__ import annotations
import json,os,pathlib,subprocess,sys,time
ROOT=pathlib.Path(__file__).resolve().parents[1]; RESULTS=ROOT/'results'; RESULTS.mkdir(exist_ok=True)
steps=[]
def run(name,cmd,required=True):
 t=time.perf_counter(); p=subprocess.run(cmd,cwd=ROOT,text=True,capture_output=True)
 rec={'name':name,'command':cmd,'returncode':p.returncode,'elapsed_s':time.perf_counter()-t,'stdout_tail':p.stdout[-4000:],'stderr_tail':p.stderr[-4000:],'required':required}
 steps.append(rec)
 if required and p.returncode: raise SystemExit(f'{name} failed: {p.stderr[-1200:]}')
 return p.returncode
# Actual tests in the supplied package plus correction regressions.
run('unittest',[sys.executable,'-m','unittest','discover','-s','tests','-p','test*.py'])
# Retain real executable checks when their scripts are present; no absent baseline/log is synthesized.
for name in ['run_cases.py','run_walkthroughs.py','run_finite_semantic_audit.py','run_semantic_audit.py','run_self_checks.py','run_static_quality_audit.py']:
 p=ROOT/'scripts'/name
 if p.exists(): run(name,[sys.executable,str(p.relative_to(ROOT))])
for name in ['build_public_study_result.py','run_repair_audit.py','audit_source_frontier.py','audit_basis_witness.py','run_timing.py','audit_consistency.py','manifest_only.py']:
 run(name,[sys.executable,'scripts/'+name])
# Parse every current JSON result/data object; missing historical files remain declared unavailable.
bad=[]; count=0
for p in ROOT.rglob('*.json'):
 try: json.loads(p.read_text()); count+=1
 except Exception as e: bad.append({'path':str(p.relative_to(ROOT)),'error':str(e)})
if bad: raise SystemExit('invalid JSON: '+json.dumps(bad[:5]))
summary={'schema':'fedfence.reproduction.v1','status':'pass','steps':steps,'json_files_parsed':count,'unavailable_evidence':json.loads((ROOT/'UNAVAILABLE_EVIDENCE.json').read_text())}
(RESULTS/'reproduction.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n')
print(json.dumps({'status':'pass','steps':len(steps),'json_files_parsed':count},sort_keys=True))
