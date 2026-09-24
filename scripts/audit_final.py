"""Audit final artifact/manuscript consistency and PDF preflight."""
from __future__ import annotations
from pathlib import Path
import hashlib,json,re,subprocess,sys
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from fse_workflow.io import load_json,save_json

def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def main():
  failures=[]
  def ck(v,msg):
    if not v:failures.append(msg)
  def res(name):return load_json(ROOT/'fse/results'/name)
  unit=res('unit_tests.json');ck(unit['passed'] and unit['tests_run']==79 and not unit['failures'] and not unit['errors'] and not unit['skipped'],'unit tests')
  finite=res('finite_semantics_audit.json');ck(finite['passed'] and finite['checked_models']==65536,'finite audit')
  replay=res('legacy_case_replay.json');ck(replay['agreements']==replay['total']==37,'historical replay')
  demo=res('demo_summary.json');ck(demo['all_expected'] and len(demo['rows'])==8,'walkthroughs')
  public=res('public_change_study.json')['summary'];ck(public['source_aligned']==9 and public['public_commits']==9,'public changes')
  frontier=res('source_frontier_summary.json');ck(frontier['sample_size']==24 and frontier['literal_or_constant_foldable']==7 and frontier['requires_instantiation_or_host_evaluation']==17,'source frontier')
  runtime=res('runtime_compatibility_summary.json');ck(runtime['records']==12 and runtime['runtime_breakage_or_denial_reports']==11 and runtime['public_actions_success_runs']==2,'runtime corpus')
  tools=res('external_tool_availability.json');ck(tools['actual_comparative_benchmark_runs']==0,'tool-run accounting')
  visual=res('pdf_visual_qa.json')
  ck((ROOT/'action.yml').is_file() and (ROOT/'schemas/review-packet.schema.json').is_file(),'packaged action/schema')
  # Parse every final-layer JSON file and compile the final-layer Python sources.
  json_files=[p for base in ['schemas','study','fse/results','examples'] for p in (ROOT/base).rglob('*.json')]
  try:
    for path in json_files: json.loads(path.read_text())
    json_ok=True
  except Exception:
    json_ok=False
  ck(json_ok,'JSON parse sanity')
  compiled=subprocess.run([sys.executable,'-m','compileall','-q','fse_workflow','tests','scripts'],cwd=ROOT).returncode==0
  ck(compiled,'Python compile sanity')
  try:
    import yaml
    for path in [ROOT/'action.yml',ROOT/'examples/github-actions-fedfence.yml']:
      yaml.load(path.read_text(),Loader=yaml.BaseLoader)
    yaml_ok=True
  except Exception:
    yaml_ok=False
  ck(yaml_ok,'YAML parse sanity')
  tex=(ROOT/'paper/main.tex').read_text();bib=(ROOT/'paper/references.bib').read_text()
  bibkeys=set(re.findall(r'@\w+\{([^,]+),',bib));cites={k.strip() for g in re.findall(r'\\cite\{([^}]+)\}',tex) for k in g.split(',')}
  ck(cites<=bibkeys,'undefined citations');ck('acmsmall,screen,review,anonymous' in tex,'template');ck('79 tests' in tex and '24-repository' in tex and 'twelve' in tex.lower(),'stale manuscript counts')
  build=(ROOT/'logs/paper_build_final.log').read_text(errors='replace') if (ROOT/'logs/paper_build_final.log').is_file() else ''
  ck('Overfull \\hbox' not in build and 'Overfull \\vbox' not in build,'overfull box')
  pdf=ROOT/'paper/FedFence_FSE_final_submission_candidate.pdf';ck(pdf.is_file(),'final PDF missing')
  pages=0;markers={};pdfsha=None
  if pdf.is_file():
    info=subprocess.check_output(['pdfinfo',str(pdf)],text=True);pages=int(re.search(r'Pages:\s*(\d+)',info).group(1));ck(1<=pages<=18,'page limit')
    author=re.search(r'^Author:\s*(.*?)$',info,re.M);ck(not author or not author.group(1).strip(),'PDF author metadata')
    text=subprocess.check_output(['pdftotext',str(pdf),'-'],text=True);markers={m:text.count(m) for m in ['鈥','鈭','脳','�']};ck(not any(markers.values()),'mojibake');ck('79 tests' in text and 'Source frontier' in text and 'Runtime compatibility evidence' in text,'compiled PDF stale')
    fonts=subprocess.check_output(['pdffonts',str(pdf)],text=True);ck('Type 3' not in fonts,'Type 3 fonts');pdfsha=sha(pdf)
    ck(visual['pdf_sha256']==pdfsha and visual['pages_inspected']==pages and not visual['issues'],'visual QA record')
    ck({r['engine'] for r in visual['renderers']}=={'pdfium','pdftoppm'} and all(r['pages_rendered']==pages for r in visual['renderers']),'visual QA renderers')
  out={'schema':'fedfence-final-audit-v1','local_audit_passed':not failures,'submission_package_complete':not failures,'external_validation_complete':False,'failures':failures,'pdf_pages':pages,'pdf_sha256':pdfsha,'reference_entries':len(bibkeys),'cited_entries':len(cites),'unused_reference_keys':sorted(bibkeys-cites),'mojibake_probe':markers,'pdf_visual_qa':{'pages_inspected':visual['pages_inspected'],'renderers':[r['engine'] for r in visual['renderers']],'issues':visual['issues']},'package_sanity':{'json_files_parsed':len(json_files),'python_compile':compiled,'yaml_parse':yaml_ok},'unit_tests':unit['tests_run'],'public_changes':9,'runtime_maintenance_commits':12,'source_frontier_repositories':24,'interpretation':'complete submission candidate and internally consistent artifact; not representative field validation, owner-confirmed accuracy, or a human usability study'}
  save_json(ROOT/'fse/results/final_audit.json',out);print(json.dumps(out,indent=2,ensure_ascii=False));return 1 if failures else 0
if __name__=='__main__':raise SystemExit(main())
