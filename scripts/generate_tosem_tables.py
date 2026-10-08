#!/usr/bin/env python3
"""Validate/render all selected evidence before writing paper macros and tables."""
from pathlib import Path
import argparse, ast, csv, json, math, re, statistics
from audit_current_science import (load as strict_load, require, sha,
                                   validate_table_record, validate_differential_rows)
ROOT=Path(__file__).resolve().parents[1]


def validate_scaling(folder, scaling):
    """Check the supplied measurements, not run or replace a timing campaign."""
    require(scaling['passed'] is True and scaling['recorded_runs'] == 54 and
            scaling['warmup_runs'] == 18 and scaling['repetitions'] == 3 and
            scaling['sizes'] == [1, 2, 4, 8, 16, 32] and
            sha(folder/'local_scaling.csv') == scaling['csv_sha256'], 'retained scaling CSV binding')
    with (folder/'local_scaling.csv').open(newline='', encoding='utf-8') as stream:
        rows = list(csv.DictReader(stream))
    tasks = ('review-pass', 'review-positive-loss', 'receipt-replay')
    keys = {(n, task) for n in scaling['sizes'] for task in tasks}
    require(len(rows) == 54 and len(scaling['summary']) == 18 and
            {(r['required_tokens'], r['task']) for r in scaling['summary']} == keys and
            all(math.isfinite(float(r['seconds'])) and float(r['seconds']) > 0 and
                r['verdict'] == r['expected'] for r in rows), 'retained scaling rows/cells')
    for cell in scaling['summary']:
        group = [r for r in rows if int(r['required_tokens']) == cell['required_tokens'] and r['task'] == cell['task']]
        values = [float(r['seconds']) for r in group]
        require(len(values) == cell['repetitions'] == 3 and
                {int(r['repetition']) for r in group} == {0, 1, 2} and
                cell['median_seconds'] == statistics.median(values) and
                cell['min_seconds'] == min(values) and cell['max_seconds'] == max(values),
                'retained scaling summary')


def generate(root=ROOT,receipt_path=None,evidence_root=None):
    ROOT=Path(root).resolve(); RES=ROOT/'tosem/results'; outputs={}
    CURRENT=None; current_receipt=None; current_audit=None
    if receipt_path is not None:
        from audit_current_science import audit
        path=(ROOT/receipt_path).resolve(strict=True)
        if not path.is_relative_to(ROOT): raise ValueError('receipt outside artifact')
        storage=ROOT if evidence_root is None else (ROOT/evidence_root).resolve(strict=True)
        current_receipt=strict_load(path)
        current_audit=audit(ROOT,current_receipt,storage)
        CURRENT=storage/current_receipt['result_directory']
        native=run_metadata(ROOT,current_receipt,path,storage,current_audit)
    elif evidence_root is not None:
        raise ValueError('evidence-root requires an explicit current-receipt')
    def load(name, fallback=None, historical=False):
        p=(CURRENT if CURRENT is not None and not historical else RES)/name
        if not p.exists() and fallback and CURRENT is None:p=ROOT/fallback
        value=strict_load(p)
        validate_table_record(p.stem, value)
        if p.stem in ('strict_literal_differential', 'strict_glob_differential'):
            validate_differential_rows(p.parent, p.stem, value)
        return value
    def tex(s):
        return str(s).replace('\\',r'\textbackslash{}').replace('_',r'\_').replace('&',r'\&').replace('%',r'\%').replace('#',r'\#')
    u=load('unit_tests.json','fse/results/unit_tests.json');f=load('two_sided_exhaustive.json');s=load('strict_literal_differential.json');r=load('relational_audit.json');p=load('public_study.json');fr=load('source_frontier.json');m=load('maintenance_metadata.json');proj=load('finite_semantics_audit.json','fse/results/finite_semantics_audit.json')
    discovered=sum(sum(isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name.startswith('test_')
                       for n in ast.walk(ast.parse(path.read_text(encoding='utf-8'))))
                   for path in (ROOT/'tests').glob('test_*.py'))
    if u['tests_run'] != discovered:
        raise ValueError('unit-test record is stale for the current sources; regenerate evidence before paper tables')
    macros={'TestCount':u['tests_run'],'FiniteCount':f['checked'],'FinitePass':f['verdicts']['pass'],'FiniteFail':f['verdicts']['fail'],'FiniteUnknown':f['verdicts']['unknown'],'FiniteReplay':f['replay_samples'],'StrictCount':s['checked'],'StrictPass':s['verdicts']['pass'],'StrictFail':s['verdicts']['fail'],'ProjectionCount':proj['checked_models'],'PublicCommits':p['summary']['commits'],'PublicRoles':p['summary']['role_contracts'],'PublicConfigurations':p['summary']['evaluations'],'PublicPass':p['summary']['verdicts']['pass'],'PublicFail':p['summary']['verdicts']['fail'],'PublicUnknown':p['summary']['verdicts']['unknown'],'SourceCount':fr['summary']['records'],'SourceFull':fr['summary']['full_source_files'],'SourceExtractions':fr['summary']['executed_extractions'],'MaintenanceCount':m['summary']['records'],'ReportedBreakages':m['summary']['reports_annotated_breakage'],'RecordedSuccesses':m['summary']['records_with_success_run_id']}
    matcher=load('matcher_differential.json');issuer=load('issuer_membership_differential.json');gs=load('strict_glob_differential.json');scaling=load('local_scaling.json',historical=True)
    validate_scaling(RES, scaling)
    macros.update(MatcherCount=matcher['checked'],IssuerCount=issuer['checked'],GlobStrictCount=gs['checked'],GlobStrictPass=gs['verdicts'].get('pass',0),GlobStrictFail=gs['verdicts'].get('fail',0),ScalingRuns=scaling['recorded_runs'])
    domain=load('character_domain_audit.json')
    macros.update(DomainPredicateChecks=domain['partition']['primitive_signature_comparisons'],
                  DomainPartitions=domain['partition']['partitions'],
                  DomainMatcherCount=domain['matcher']['checked'],
                  DomainConstructorCount=domain['constructor']['checked'])
    core=RES/'core_self_check.json'
    if CURRENT is not None:macros['CoreComparisons']=current_audit['core_comparisons']
    elif core.exists():macros['CoreComparisons']=load('core_self_check.json')['comparisons']
    require(all(type(v) is int and v >= 0 for v in macros.values()), 'nonnegative integral table counts')
    outputs['results.tex'] = '% Automatically generated; do not edit counts by hand.\n'+''.join('\\newcommand{\\'+k+'}{'+f'{v:,}'+'}\n' for k,v in macros.items())
    rows=[]
    labels={'two_sided_realizability':'Two-sided realizability','governance_restriction':'Governance restriction','intent_monotonicity':'Intent monotonicity','observation_refinement':'Observation refinement'}
    for k,v in r['checks'].items(): rows.append(f'{labels[k]} & {v:,} & No counterexample \\\\')
    outputs['relational_rows.tex'] = '\n'.join(rows)+'\n'
    rows=[]
    for k,v in fr['summary']['annotation_counts'].items():rows.append(tex(k.replace('_',' '))+f' & {v} \\\\')
    outputs['frontier_rows.tex'] = '\n'.join(rows)+'\n'
    outputs['tables.tex'] = '\\newcommand{\\RelationalRows}{%\n'+outputs['relational_rows.tex']+'}\n'+'\\newcommand{\\FrontierRows}{%\n'+outputs['frontier_rows.tex']+'}\n'
    provenance=dict(source='artifact/'+(CURRENT.relative_to(ROOT).as_posix() if CURRENT is not None else 'tosem/results'),macros=macros,quantitative_tables_from_results=True,
                    retained_measurements='Scaling tables/plot use the selected supplied tosem/results snapshot, separate from explicitly selected native evidence; no before/current timing-gain claim.')
    if CURRENT is not None:
        provenance['current_science_receipt']='artifact/'+path.relative_to(ROOT).as_posix()
        provenance['current_science_receipt_sha256']=sha(path)
        provenance['native_run']=native
        provenance['unit_test_count_source']=dict(tests_run=u['tests_run'],python=current_audit['python'],platform=current_audit['platform'],scope='Retained native nine-stage output, passively audited against current sources.')
    outputs['generation.json'] = json.dumps(provenance,indent=2)+'\n'
    
    
    # All plotted points and table values come from the recorded local measurements.
    summary=scaling['summary']; rows=[]
    for n in scaling['sizes']:
        values=[next(r['median_seconds'] for r in summary if r['required_tokens']==n and r['task']==task) for task in ('review-pass','review-positive-loss','receipt-replay')]
        rows.append(str(n)+' & '+' & '.join(f'{v:.3f}' for v in values)+r' \\')
    outputs['scaling_rows.tex'] = '\n'.join(rows)+'\n'
    outputs['tables.tex'] += '\\newcommand{\\ScalingRows}{%\n'+outputs['scaling_rows.tex']+'}\n'
    for task,name in [('review-pass','pass'),('review-positive-loss','loss'),('receipt-replay','replay')]:
        points=['n median lower upper']
        for r in summary:
            if r['task']==task:
                points.append(f"{r['required_tokens']} {r['median_seconds']:.9f} {r['median_seconds']-r['min_seconds']:.9f} {r['max_seconds']-r['median_seconds']:.9f}")
        outputs[f'scaling-{name}.dat'] = '\n'.join(points)+'\n'
    outputs['plot_provenance.json'] = json.dumps(dict(source='artifact/tosem/results/local_scaling.csv',csv_sha256=scaling['csv_sha256'],points_per_series=len(scaling['sizes']),series=3,range='observed min/max, not confidence intervals'),indent=2)+'\n'
    return outputs

def run_metadata(root, receipt, path, storage, audited):
    """Use actual recorded fields; no invented ids for an unlabelled local run."""
    from audit_current_science import bounded_path, load, require, sha
    driver=load(bounded_path(storage,receipt['execution']))
    require(driver['python']==audited['python'] and driver['platform']==audited['platform']
            and len(driver['steps'])==9,'audited driver metadata')
    result=dict(execution=receipt['execution'],python=driver['python'],
                platform=driver['platform'],stages=len(driver['steps']),
                elapsed_seconds=driver['elapsed_seconds'])
    if 'run' in receipt:
        run=receipt['run']
        require(isinstance(run,dict) and type(run.get('run_id')) is int and run['run_id']>0
                and isinstance(run.get('head'),str) and re.fullmatch(r'[0-9a-f]{40}',run['head']),
                'legacy recorded run identity')
        result.update(run)
    elif 'fresh_preparation' in receipt:
        item=receipt['fresh_preparation']; manifest=bounded_path(storage,item['path'])
        require(sha(manifest)==item['sha256'],'original fresh preparation bytes')
        prepared=load(manifest)
        require(prepared['schema']=='fedfence-fresh-preparation-v1' and
                all(prepared[k]==receipt[k] for k in ('source_files','study_inputs','implementation_sha256')),
                'fresh preparation scientific binding')
        result['fresh_preparation_sha256']=item['sha256']
        ci_path=path.parent/'ci-identity.json'
        if ci_path.exists():
            ci=load(bounded_path(root,ci_path.relative_to(root).as_posix()))
            require(isinstance(ci.get('GITHUB_SHA'),str) and re.fullmatch(r'[0-9a-f]{40}',ci['GITHUB_SHA'])
                    and all(isinstance(ci.get(k),str) and re.fullmatch(r'[1-9][0-9]*',ci[k])
                            for k in ('GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT'))
                    and isinstance(ci.get('GITHUB_REF'),str) and ci['GITHUB_REF'].startswith('refs/'),
                    'recorded CI identity shape')
            result.update(run_id=int(ci['GITHUB_RUN_ID']),head=ci['GITHUB_SHA'],
                          run_attempt=int(ci['GITHUB_RUN_ATTEMPT']),ref=ci['GITHUB_REF'])
            result['ci_identity_path']=ci_path.relative_to(root).as_posix()
            result['ci_identity_sha256']=sha(ci_path)
        else:
            result['identity_authority']='No CI identity supplied; audited local driver fields only.'
    else:
        raise ValueError('native receipt has neither recorded run nor fresh preparation')
    result['identity_limit']='Recorded metadata, not remote authentication by this generator.'
    return result


def main(argv=None):
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--current-receipt',type=Path)
    ap.add_argument('--evidence-root',type=Path)
    ap.add_argument('--out',type=Path,default=ROOT.parent/'paper/generated')
    ap.add_argument('--check',action='store_true',help='validate/render only; write nothing')
    args=ap.parse_args(argv)
    outputs=generate(ROOT,args.current_receipt,args.evidence_root)
    if not args.check:
        args.out.mkdir(parents=True,exist_ok=True)
        for name,text in outputs.items():
            (args.out/name).write_text(text,encoding='utf-8')
    print(json.dumps(dict(validated_outputs=len(outputs),written=not args.check)))
    return 0


if __name__=='__main__':
    raise SystemExit(main())
