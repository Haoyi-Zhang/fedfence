from __future__ import annotations
import json, os, pathlib, platform, statistics, subprocess, sys, time
ROOT=pathlib.Path(__file__).resolve().parents[1]
CMD=[sys.executable,str(ROOT/'scripts/run_repair_audit.py')]
s=[]
for _ in range(7):
 t=time.perf_counter_ns(); subprocess.run(CMD,cwd=ROOT,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True); s.append((time.perf_counter_ns()-t)/1_000_000)
ss=sorted(s)
def linear_percentile(values,p):
 if len(values)==1:return values[0]
 x=(len(values)-1)*p; lo=int(x); hi=min(lo+1,len(values)-1); return values[lo]+(values[hi]-values[lo])*(x-lo)
out={'schema':'fedfence.timing.v1','measurement':'fresh full-batch subprocess timing of scripts/run_repair_audit.py',
     'samples_ms':s,'repetitions':7,'median_ms':statistics.median(s),'p95_ms':linear_percentile(ss,.95),
     'aggregation':{'median':'statistics.median','p95':'linear interpolation at (n-1)*0.95 on sorted samples'},
     'environment':{'python':sys.version.split()[0],'implementation':platform.python_implementation(),'platform':platform.platform(),'machine':platform.machine(),'cpu_count':os.cpu_count()},
     'frozen_result_validation_is_timing':False,'command':' '.join(CMD)}
p=ROOT/'results/timing.json'; p.parent.mkdir(exist_ok=True); p.write_text(json.dumps(out,indent=2,sort_keys=True)+'\n'); print(json.dumps(out,sort_keys=True))
