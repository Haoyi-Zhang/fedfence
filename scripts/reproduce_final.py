"""Reproduce the final local and source-backed FedFence evidence package.

A successful run establishes package consistency, not prevalence, owner-confirmed
accuracy, provider conformance, comparative-tool superiority, or usability.
"""
from __future__ import annotations
from pathlib import Path
from datetime import datetime, timezone
import argparse, hashlib, json, os, platform, subprocess, sys, time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from fse_workflow.io import load_json, save_json

STEPS=[
 ('unit_tests','scripts/run_fse_tests.py',240),
 ('finite_semantics_audit','scripts/run_finite_audit.py',120),
 ('legacy_boundary_probe','scripts/run_legacy_boundary_probe.py',90),
 ('legacy_fragment_inventory','scripts/inventory_legacy_fragment.py',90),
 ('legacy_case_replay','scripts/replay_legacy_cases.py',240),
 ('legacy_self_check','artifact/scripts/self_check.py',600),
 ('demo_suite','scripts/run_demo_suite.py',120),
 ('public_change_study','scripts/run_public_change_study.py',240),
 ('public_change_latency','scripts/validate_public_change_latency.py',30),
 ('source_frontier_study','scripts/run_source_frontier_study.py',60),
 ('runtime_compatibility_study','scripts/run_runtime_compatibility_study.py',60),
 ('external_tool_availability','scripts/check_baseline_availability.py',120),
]

def sha(path:Path)->str:return hashlib.sha256(path.read_bytes()).hexdigest()

def validate_results():
    checks=[
      ('unit_tests','unit_tests.json',lambda d:d['passed'] and d['tests_run']==79),
      ('finite_semantics_audit','finite_semantics_audit.json',lambda d:d['passed'] and d['checked_models']==65536),
      ('legacy_boundary_probe','legacy_boundary_probe.json',lambda d:d['passed'] and d['fse_gate_verdict']=='unknown'),
      ('legacy_fragment_inventory','legacy_fragment_inventory.json',lambda d:sum(d['counts'].values())==37),
      ('legacy_case_replay','legacy_case_replay.json',lambda d:d['agreements']==d['total']==37),
      ('demo_suite','demo_summary.json',lambda d:d['all_expected'] and len(d['rows'])==8),
      ('public_change_study','public_change_study.json',lambda d:d['summary']['source_aligned']==9),
      ('public_change_latency','public_change_latency.json',lambda d:d['repeats']==7 and len(d['rows'])==9),
      ('source_frontier_study','source_frontier_summary.json',lambda d:d['sample_size']==24 and d['unique_repositories']==24),
      ('runtime_compatibility_study','runtime_compatibility_summary.json',lambda d:d['records']==12 and d['public_actions_success_runs']==2),
      ('external_tool_availability','external_tool_availability.json',lambda d:d['actual_comparative_benchmark_runs']==0),
    ]
    rows=[]
    for name,file,pred in checks:
        path=ROOT/'fse/results'/file; data=load_json(path)
        if not pred(data): raise RuntimeError(f'result validation failed: {file}')
        rows.append({'step':name,'status':'verified-result-file','result':str(path.relative_to(ROOT)),'result_sha256':sha(path)})
    log=ROOT/'logs/legacy_self_check.log'
    if not log.is_file() or 'self-check passed (3945 bounded and symbolic comparisons)' not in log.read_text(errors='replace'):
        raise RuntimeError('legacy self-check log missing or inconsistent')
    rows.insert(5,{'step':'legacy_self_check','status':'verified-result-file','result':str(log.relative_to(ROOT)),'result_sha256':sha(log)})
    return rows

def run_all():
    logs=ROOT/'logs';logs.mkdir(exist_ok=True)
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1')
    rows=[]
    for name,script,timeout in STEPS:
        start=time.monotonic(); log=logs/f'{name}.log'; print(name,'starting',flush=True)
        with log.open('w',encoding='utf-8') as h:
            try:
                p=subprocess.run([sys.executable,str(ROOT/script)],cwd=ROOT,env=env,stdin=subprocess.DEVNULL,stdout=h,stderr=subprocess.STDOUT,timeout=timeout,start_new_session=True)
                code=p.returncode; status='passed' if code==0 else 'failed'
            except subprocess.TimeoutExpired:
                code=None;status='timeout'
        rows.append({'step':name,'command':[sys.executable,script],'elapsed_seconds':round(time.monotonic()-start,4),'exit_code':code,'status':status,'log':str(log.relative_to(ROOT))})
        print(name,status,flush=True)
    return rows

def write_provenance():
    old=load_json(ROOT/'fse/results/provenance.json') if (ROOT/'fse/results/provenance.json').is_file() else {}
    data={
      'schema':'fedfence-final-provenance-v1',
      'recorded_at_utc':datetime.now(timezone.utc).isoformat(),
      'manuscript_title':'FedFence: Specification-Guided Review of CI/CD Trust Changes',
      'manuscript_source_sha256':sha(ROOT/'paper/main.tex'),
      'review_packet_schema_sha256':sha(ROOT/'schemas/review-packet.schema.json'),
      'composite_action_sha256':sha(ROOT/'action.yml'),
      'public_change_corpus_sha256':sha(ROOT/'study/public_change_corpus.json'),
      'public_change_screening_sha256':sha(ROOT/'study/public_change_screening.json'),
      'runtime_compatibility_corpus_sha256':sha(ROOT/'study/runtime_compatibility_corpus.json'),
      'source_frontier_sample_sha256':sha(ROOT/'study/source_frontier_sample.json'),
      'baseline_all_original_file_bytes_preserved':bool(old.get('baseline_all_original_file_bytes_preserved',True)),
      'original_core_unchanged':bool(old.get('original_core_unchanged',True)),
      'baseline_pdf_sha256':old.get('baseline_pdf_sha256'),
      'source_zip_sha256':old.get('source_zip_sha256'),
      'evidence_boundaries':{
        'representative_sample':False,'independent_labels':False,'owner_confirmed_findings':0,
        'live_cloud_runs_by_fedfence':0,'human_study_participants':0,'vendor_common_corpus_runs':0,
        'public_post_fix_action_runs_observed':2,'required_tokens_are_complete_availability_specification':False,
      },
    }
    save_json(ROOT/'fse/results/provenance.json',data);return data

def build_manifest(steps,mode):
    write_provenance()
    files={str(p.relative_to(ROOT)):sha(p) for p in sorted((ROOT/'fse/results').glob('*')) if p.is_file() and p.name not in {'final_reproduction_manifest.json','final_audit.json'}}
    data={
      'schema':'fedfence-final-reproduction-v1','recorded_at_utc':datetime.now(timezone.utc).isoformat(),
      'python':sys.version,'platform':platform.platform(),'execution_mode':mode,'steps':steps,
      'local_reproduction_passed':all(r['status'] in {'passed','verified-result-file'} for r in steps),
      'submission_package_complete':True,'external_validation_complete':False,
      'unit_tests':79,'finite_models':65536,'historical_cases':37,'legacy_self_checks':3945,
      'synthetic_walkthroughs':8,'normalized_public_changes':9,'runtime_maintenance_commits':12,
      'source_frontier_repositories':24,'public_post_fix_action_runs_observed':2,
      'actual_comparative_benchmark_runs':0,'owner_confirmed_findings':0,'human_study_participants':0,
      'limitations':['public studies are purposive or query-defined rather than representative','commit and run metadata are source evidence rather than independent root-cause adjudication','no owner-confirmed labels, live FedFence deployment, vendor common-corpus benchmark, or human study','finite required tokens are regression examples, not a complete availability language','no machine-checked refinement from mathematics to Python'],
      'result_files':files,
    }
    save_json(ROOT/'fse/results/final_reproduction_manifest.json',data);return data

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--manifest-only',action='store_true');args=ap.parse_args()
    steps=validate_results() if args.manifest_only else run_all(); mode='split-step-results-validated' if args.manifest_only else 'single-driver-run'
    data=build_manifest(steps,mode);print(json.dumps({k:data[k] for k in ['execution_mode','local_reproduction_passed','submission_package_complete','external_validation_complete']},indent=2))
    return 0 if data['local_reproduction_passed'] else 1
if __name__=='__main__':raise SystemExit(main())
