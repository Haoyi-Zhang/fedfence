#!/usr/bin/env python3
"""Generate the paper's quantitative macros and tables from current results."""
from pathlib import Path
import json, sys
ROOT=Path(__file__).resolve().parents[1]; OUT=ROOT.parent/'paper/generated';OUT.mkdir(parents=True,exist_ok=True)
RES=ROOT/'tosem/results'
def load(name, fallback=None):
    p=RES/name
    if not p.exists() and fallback:p=ROOT/fallback
    return json.loads(p.read_text())
def tex(s):
    return str(s).replace('\\',r'\textbackslash{}').replace('_',r'\_').replace('&',r'\&').replace('%',r'\%').replace('#',r'\#')
u=load('unit_tests.json','fse/results/unit_tests.json');f=load('two_sided_exhaustive.json');s=load('strict_literal_differential.json');r=load('relational_audit.json');p=load('public_study.json');fr=load('source_frontier.json');m=load('maintenance_metadata.json');proj=load('finite_semantics_audit.json','fse/results/finite_semantics_audit.json')
macros={'TestCount':u['tests_run'],'FiniteCount':f['checked'],'FinitePass':f['verdicts']['pass'],'FiniteFail':f['verdicts']['fail'],'FiniteUnknown':f['verdicts']['unknown'],'FiniteReplay':f['replay_samples'],'StrictCount':s['checked'],'StrictPass':s['verdicts']['pass'],'StrictFail':s['verdicts']['fail'],'ProjectionCount':proj['checked_models'],'PublicCommits':p['summary']['commits'],'PublicRoles':p['summary']['role_contracts'],'PublicConfigurations':p['summary']['evaluations'],'PublicPass':p['summary']['verdicts']['pass'],'PublicFail':p['summary']['verdicts']['fail'],'PublicUnknown':p['summary']['verdicts']['unknown'],'SourceCount':fr['summary']['records'],'SourceFull':fr['summary']['full_source_files'],'SourceExtractions':fr['summary']['executed_extractions'],'MaintenanceCount':m['summary']['records'],'ReportedBreakages':m['summary']['reports_annotated_breakage'],'RecordedSuccesses':m['summary']['records_with_success_run_id']}
matcher=load('matcher_differential.json');issuer=load('issuer_membership_differential.json');gs=load('strict_glob_differential.json');scaling=load('local_scaling.json')
macros.update(MatcherCount=matcher['checked'],IssuerCount=issuer['checked'],GlobStrictCount=gs['checked'],GlobStrictPass=gs['verdicts'].get('pass',0),GlobStrictFail=gs['verdicts'].get('fail',0),ScalingRuns=scaling['recorded_runs'])
domain=load('character_domain_audit.json')
macros.update(DomainPredicateChecks=domain['partition']['primitive_signature_comparisons'],
              DomainPartitions=domain['partition']['partitions'],
              DomainMatcherCount=domain['matcher']['checked'],
              DomainConstructorCount=domain['constructor']['checked'])
core=RES/'core_self_check.json'
if core.exists():macros['CoreComparisons']=load('core_self_check.json')['comparisons']
(OUT/'results.tex').write_text('% Automatically generated; do not edit counts by hand.\n'+''.join('\\newcommand{\\'+k+'}{'+f'{v:,}'+'}\n' for k,v in macros.items()))
rows=[]
labels={'two_sided_realizability':'Two-sided realizability','governance_restriction':'Governance restriction','intent_monotonicity':'Intent monotonicity','observation_refinement':'Observation refinement'}
for k,v in r['checks'].items(): rows.append(f'{labels[k]} & {v:,} & No counterexample \\\\')
(OUT/'relational_rows.tex').write_text('\n'.join(rows)+'\n')
rows=[]
for k,v in fr['summary']['annotation_counts'].items():rows.append(tex(k.replace('_',' '))+f' & {v} \\\\')
(OUT/'frontier_rows.tex').write_text('\n'.join(rows)+'\n')
(OUT/'tables.tex').write_text('\\newcommand{\\RelationalRows}{%\n'+(OUT/'relational_rows.tex').read_text()+'}\n'+'\\newcommand{\\FrontierRows}{%\n'+(OUT/'frontier_rows.tex').read_text()+'}\n')
(OUT/'generation.json').write_text(json.dumps(dict(source='artifact/tosem/results',macros=macros,quantitative_tables_from_results=True),indent=2)+'\n')
print('Generated',len(macros),'quantitative macros from current results.')

# All plotted points and table values come from the recorded local measurements.
summary=scaling['summary']; rows=[]
for n in scaling['sizes']:
    values=[next(r['median_seconds'] for r in summary if r['required_tokens']==n and r['task']==task) for task in ('review-pass','review-positive-loss','receipt-replay')]
    rows.append(str(n)+' & '+' & '.join(f'{v:.3f}' for v in values)+r' \\')
(OUT/'scaling_rows.tex').write_text('\n'.join(rows)+'\n')
with (OUT/'tables.tex').open('a') as stream:
    stream.write('\\newcommand{\\ScalingRows}{%\n'+(OUT/'scaling_rows.tex').read_text()+'}\n')
for task,name in [('review-pass','pass'),('review-positive-loss','loss'),('receipt-replay','replay')]:
    points=['n median lower upper']
    for r in summary:
        if r['task']==task:
            points.append(f"{r['required_tokens']} {r['median_seconds']:.9f} {r['median_seconds']-r['min_seconds']:.9f} {r['max_seconds']-r['median_seconds']:.9f}")
    (OUT/f'scaling-{name}.dat').write_text('\n'.join(points)+'\n')
(OUT/'plot_provenance.json').write_text(json.dumps(dict(source='artifact/tosem/results/local_scaling.csv',csv_sha256=scaling['csv_sha256'],points_per_series=len(scaling['sizes']),series=3,range='observed min/max, not confidence intervals'),indent=2)+'\n')
