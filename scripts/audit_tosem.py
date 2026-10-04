#!/usr/bin/env python3
"""Cross-check the current TOSEM evidence, manuscript and reproducibility entry points.

Uses only the Python standard library and Poppler command-line utilities.
This is a consistency audit, not a proof of universal correctness or acceptance.
"""
from __future__ import annotations
import ast
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import statistics

ROOT = Path(__file__).resolve().parents[1]
PAPER = ROOT.parent / 'paper'
RESULTS = ROOT / 'tosem/results'
sys.path.insert(0, str(ROOT))
from fse_workflow.gate import implementation_digest
from fse_workflow.io import save_json


def main() -> int:
    checks: list[dict] = []
    def check(name: str, condition: bool, detail: object = '') -> None:
        checks.append({'name': name, 'passed': bool(condition), 'detail': detail})
    def load(name: str):
        return json.loads((RESULTS / name).read_text(encoding='utf-8'))

    unit = load('unit_tests.json')
    discovered = sum(sum(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                         and node.name.startswith('test_') for node in ast.walk(ast.parse(f.read_text())))
                     for f in (ROOT / 'tests').glob('test_*.py'))
    check('unit-test-discovery-and-record', unit['tests_run'] == discovered and discovered >= 112
          and unit['passed'] and all(unit[k] == 0 for k in ('errors', 'failures', 'skipped')),
          {'recorded': unit['tests_run'], 'test_methods_in_source': discovered})
    repro = load('reproduction.json')
    expected_steps = {'unit-tests', 'core-self-check', 'projection-audit', 'relational-audit',
                      'two-sided-validation', 'character-domain', 'final-boundaries', 'seeded-faults', 'repair-audit', 'source-studies'}
    check('all-ten-reproduction-steps', repro['passed'] and
          {r['name'] for r in repro['steps']} == expected_steps and
          all(r['exit_code'] == 0 and (ROOT / r['log']).is_file() for r in repro['steps']))
    validation = load('validation_summary.json')
    implementation = implementation_digest()
    check('current-implementation-matches-records', implementation == repro['implementation_sha256']
          == validation['environment']['implementation_sha256'], implementation)
    check('offline-recorded-scope', all(x is False for x in (
          repro['network_access'], repro['cloud_accounts_used'], validation['network_access'],
          validation['cloud_accounts_used'])))
    domain = load('character_domain_audit.json')
    check('character-domain-current-implementation', domain['passed'] and
          domain['implementation_sha256'] == implementation and
          domain['character_domain'] == 'python-str-codepoints-v1' and
          domain['network_access'] is False and domain['cloud_accounts_used'] is False)
    partition = domain['partition']
    check('full-codepoint-predicate-signatures', partition['passed'] and
          partition['partitions'] == len(partition['rows']) == 3 and
          partition['codepoints_per_partition'] == 0x110000 and
          partition['primitive_signature_comparisons'] == 3*0x110000 and all(
              r['passed'] and r['checked_codepoints'] == 0x110000 and
              r['support_size'] == r['literal_classes'] + 1 for r in partition['rows']))
    dm = domain['matcher']
    check('quotient-matcher-concrete-oracle', dm['passed'] and
          dm['checked'] == dm['operators']*dm['patterns']*dm['words'] == 57498 and
          dm['matching'] + dm['nonmatching'] == dm['checked'])
    dc = domain['constructor']
    check('quotient-constructor-boundaries', dc['passed'] and
          dc['checked'] == dc['positions']*dc['characters'] == 60)
    di = domain['integration']
    check('domain-full-review-controls', di['passed'] and di['regular_cases'] == 4 and
          di['strict_packets'] == 3 and all(r['expected_safe'] == r['actual_safe'] and r['replay_ok']
          for r in di['rows']) and all(r['expected'] == r['verdict'] and r['receipt_replay_ok']
          for r in di['strict_rows']) and {r['verdict'] for r in di['strict_rows']} == {'pass','fail','unknown'})
    dr = domain['rejection']
    check('independent-support-rejection-challenges', dr['passed'] and dr['challenges'] == 2 and
          all(r['control_passed'] and r['detected'] for r in dr['rows']))
    core = load('core_self_check.json')
    check('core-self-check', core['passed'] and core['comparisons'] == 3945)
    projection = load('finite_semantics_audit.json')
    check('projection-domain', projection['passed'] and projection['checked_models'] == 65536
          and projection['universe_states'] == 4 and projection['observation_values'] == 2
          and bool(projection['incorrect_existential_lifting_counterexample']))
    finite = load('two_sided_exhaustive.json')
    samples = load('two_sided_samples.json')
    check('two-sided-domain-and-partition', finite['passed'] and finite['checked'] == 65536
          == finite['relation_combinations'] * finite['validity_settings']
          == sum(finite['verdicts'].values()) and finite['replay_samples'] == len(samples) == 256)
    check('two-sided-summary-matches-raw-result', validation['finite'] == finite)
    strict = load('strict_literal_differential.json')
    with (RESULTS / 'strict_literal_differential.csv').open(newline='') as f:
        raw = list(csv.DictReader(f))
    check('strict-differential-rows', strict['passed'] and strict['checked'] == len(raw) == 56
          and all(r['verdict'] == r['expected'] and r['replay_ok'].lower() == 'true' for r in raw)
          and dict(Counter(r['verdict'] for r in raw)) == strict['verdicts'])
    check('strict-summary-matches-raw-result', validation['strict'] == strict)
    relation = load('relational_audit.json')
    check('relational-audit', relation['passed'] and relation['checks'] == {
          'two_sided_realizability': 16384, 'governance_restriction': 20736,
          'intent_monotonicity': 20736, 'observation_refinement': 16384})
    meta = load('dependency_metamorphic.json')
    check('dependency-transformations', meta['passed'] and meta['checked'] == len(meta['rows']) == 6
          and meta == validation['metamorphic'])
    faults = load('seeded_faults.json')
    check('seeded-fault-controls-and-detection', faults['passed'] and faults['detected']
          == faults['hand_selected_faults'] == len(faults['rows']) == 8 and all(
          r['baseline_passed'] and r['assertion_detected_fault'] and not r['syntax_or_import_error']
          for r in faults['rows']))
    public = load('public_study.json')
    pub = public['summary']
    check('public-noninterchangeable-denominators', pub['commits'] == 9 and pub['role_contracts'] == 10
          and pub['ordinary_role_phases'] == 20 and pub['additional_variable_branch'] == 1
          and pub['evaluations'] == len(public['rows']) == 21
          and pub['safety_or_full_study_replay_checks'] == 21 and pub['verified_patch_digests'] == 9
          and pub['verdicts'] == {'pass': 10, 'fail': 10, 'unknown': 1}
          and pub['entry_points'] == {'regular-language-study-adapter': 14,
                                    'finite-explicit-issuer-study-adapter': 7})
    check('public-claim-boundaries', all(pub[k] is False for k in (
          'source_authenticity_verified', 'owner_confirmed', 'independent_accuracy_measure', 'cloud_validation')))
    fr = load('source_frontier.json')
    check('source-excerpts-not-extraction', fr['summary']['records'] == len(fr['rows']) == 24
          and fr['summary']['verified_excerpts'] == 24 and fr['summary']['full_source_files'] == 0
          and fr['summary']['executed_extractions'] == 0
          and all(r['excerpt_verified'] and not r['full_source_available']
                  and r['extraction_result'] == 'not-executed' for r in fr['rows']))
    maint = load('maintenance_metadata.json')
    check('maintenance-recorded-not-reproduced', maint['summary']['records'] == len(maint['rows']) == 12
          and maint['summary']['verified_record_digests'] == 12
          and maint['summary']['reports_annotated_breakage'] == 11
          and maint['summary']['records_with_success_run_id'] == 2
          and maint['summary']['live_workflows_run'] == 0
          and not maint['summary']['independent_root_cause_adjudication'])
    summary = load('studies_summary.json')
    check('study-summary-provenance', summary == {'public': pub, 'frontier': fr['summary'],
                                                'maintenance': maint['summary']})
    repair = load('repair_audit.json')
    check('repaired-issuer-and-branch-audit', repair['status'] == 'pass'
          and repair['issuer_contract'] == {'checks': 7, 'status': 'pass'})
    boundaries = load('final_validation_summary.json')
    check('new-boundary-results-match-current-code', boundaries['passed'] and
          boundaries['implementation_sha256'] == implementation and
          boundaries['network_access'] is False and boundaries['cloud_accounts_used'] is False)
    matcher = load('matcher_differential.json')
    check('matcher-domain-and-three-way-agreement', matcher['passed'] and
          matcher['checked'] == matcher['patterns']*matcher['values'] == 242580 and
          matcher['matching_pairs'] + matcher['nonmatching_pairs'] == matcher['checked'] and
          boundaries['results']['matcher'] == matcher)
    issuer = load('issuer_membership_differential.json')
    check('issuer-refinement-domain-and-agreement', issuer['passed'] and issuer['checked'] == 2304 ==
          len(issuer['subjects'])*len(issuer['audiences'])*len(issuer['subject_refinements'])*len(issuer['audience_refinements'])
          and issuer['accepted'] + issuer['rejected'] == issuer['checked'] and boundaries['results']['issuer'] == issuer)
    globs = load('strict_glob_differential.json')
    with (RESULTS/'strict_glob_differential.csv').open(newline='') as f:
        grow = list(csv.DictReader(f))
    check('bounded-glob-complete-packets', globs['passed'] and globs['checked'] == len(grow) == 192
          and all(r['expected'] == r['verdict'] and r['replay_ok'] == 'True' for r in grow)
          and dict(Counter(r['verdict'] for r in grow)) == globs['verdicts']
          and boundaries['results']['strict_glob'] == globs)
    from fse_workflow.io import digest
    check('bounded-glob-packet-digests', all(digest(json.loads((RESULTS/r['packet_file']).read_text())) ==
          r['packet_sha256'] for r in grow) and
          hashlib.sha256((RESULTS/'strict_glob_differential.csv').read_bytes()).hexdigest() == globs['csv_sha256'])
    scaling = load('local_scaling.json')
    with (RESULTS/'local_scaling.csv').open(newline='') as f:
        timing = list(csv.DictReader(f))
    check('local-cost-runs-and-source-digest', scaling['passed'] and len(timing) == scaling['recorded_runs'] == 54
          and all(r['expected'] == r['verdict'] and float(r['seconds']) > 0 for r in timing)
          and hashlib.sha256((RESULTS/'local_scaling.csv').read_bytes()).hexdigest() == scaling['csv_sha256']
          and boundaries['results']['scaling'] == scaling)
    def timing_agrees(row):
        values=[float(r['seconds']) for r in timing if int(r['required_tokens'])==row['required_tokens'] and r['task']==row['task']]
        return len(values)==row['repetitions']==3 and statistics.median(values)==row['median_seconds'] and min(values)==row['min_seconds'] and max(values)==row['max_seconds']
    check('local-cost-statistics-recomputed', len(scaling['summary']) == 18 and all(timing_agrees(r) for r in scaling['summary']))
    provenance=json.loads((PAPER/'generated/plot_provenance.json').read_text())
    check('plot-provenance-is-measured-data', provenance['csv_sha256'] == scaling['csv_sha256'] and provenance['series']==3 and provenance['points_per_series']==6)
    plot_values_agree = True
    for task, name in [('review-pass','pass'), ('review-positive-loss','loss'), ('receipt-replay','replay')]:
        with (PAPER/f'generated/scaling-{name}.dat').open() as stream:
            points = list(csv.DictReader(stream, delimiter=' '))
        rows = [r for r in scaling['summary'] if r['task'] == task]
        plot_values_agree &= len(points) == len(rows) == 6
        for point, row in zip(points, rows):
            plot_values_agree &= (int(point['n']) == row['required_tokens'] and
                abs(float(point['median']) - row['median_seconds']) <= 5.1e-10 and
                abs(float(point['lower']) - (row['median_seconds'] - row['min_seconds'])) <= 5.1e-10 and
                abs(float(point['upper']) - (row['max_seconds'] - row['median_seconds'])) <= 5.1e-10)
    check('plot-points-and-whiskers-match-measurements', plot_values_agree)
    generation = json.loads((PAPER / 'generated/generation.json').read_text())
    quantitative = (PAPER / 'generated/results.tex').read_text()
    check('generated-macros-exact', all('\\newcommand{\\' + k + '}{' + f'{v:,}' + '}'
                                     in quantitative for k, v in generation['macros'].items()))
    check('generated-macro-source-values', generation['macros']['TestCount'] == unit['tests_run']
          and generation['macros']['FiniteCount'] == finite['checked']
          and generation['macros']['StrictCount'] == strict['checked']
          and generation['macros']['PublicConfigurations'] == pub['evaluations']
          and generation['macros']['SourceExtractions'] == 0
          and generation['macros']['MatcherCount'] == matcher['checked']
          and generation['macros']['IssuerCount'] == issuer['checked']
          and generation['macros']['GlobStrictCount'] == globs['checked']
          and generation['macros']['ScalingRuns'] == scaling['recorded_runs'])
    main = (PAPER / 'main.tex').read_text()
    active_tex = [PAPER / 'main.tex', *sorted((PAPER / 'sections').glob('*.tex')),
                  *sorted((PAPER / 'figures').glob('*.tex'))]
    text = '\n'.join(p.read_text() for p in active_tex)
    labels = re.findall(r'\\label\{([^}]+)\}', text)
    check('unique-active-latex-labels', len(labels) == len(set(labels)))
    refs = re.findall(r'@\w+\{([^,]+),', (PAPER / 'references.bib').read_text())
    cited = set(k.strip() for group in re.findall(r'\\cite\w*(?:\[[^\]]*\])?\{([^}]+)\}', text)
                for k in group.split(','))
    check('all-reference-keys-unique-and-used', len(refs) == len(set(refs)) == 63
          and cited == set(refs), {'entries': len(refs), 'cited_keys': len(cited),
                                  'unused': sorted(set(refs)-cited), 'undefined': sorted(cited-set(refs))})
    ledger = json.loads((PAPER/'docs/REFERENCE_AUDIT.json').read_text())
    with (PAPER/'docs/REFERENCE_AUDIT.csv').open(newline='') as stream:
        ledger_csv = list(csv.DictReader(stream))
    check('reference-ledger-keys-and-categories', ledger['entries'] == len(ledger['rows']) == len(ledger_csv) == len(refs)
          and {r['key'] for r in ledger['rows']} == {r['key'] for r in ledger_csv} == set(refs)
          and dict(Counter(r['category'] for r in ledger['rows'])) == ledger['categories'])
    figures = text.count('\\begin{figure}')
    tables = text.count('\\begin{table}')
    check('figure-accessibility-descriptions', figures == text.count('\\Description{') == 9)
    check('table-count', tables == 13)
    check('official-journal-review-template', '\\documentclass[manuscript,screen,review]{acmart}' in main
          and '\\acmJournal{TOSEM}' in main and 'sigconf' not in main and 'anonymous' not in main)
    check('supplied-author-order', re.findall(r'\\author\{([^}]+)\}', main) == [
          'Haoyi Zhang', 'Huaijin Ran', 'Kisub Kim', 'Xunzhu Tang', "Tegawend\\'e F. Bissyand\\'e"])
    make = (ROOT / 'Makefile').read_text()
    check('current-reproduction-entry-point', 'scripts/reproduce_tosem.py --paper' in make
          and '../paper' in make and (ROOT / 'scripts/reproduce_tosem.py').is_file())
    pdf = PAPER / 'FedFence_TOSEM.pdf'
    check('pdf-exists', pdf.is_file())
    for tool in ('pdfinfo', 'pdftotext', 'pdffonts'):
        check('tool-' + tool, bool(shutil.which(tool)))
    pages = None
    ref_start = None
    if pdf.exists() and all(shutil.which(t) for t in ('pdfinfo','pdftotext','pdffonts')):
        info = subprocess.check_output(['pdfinfo', str(pdf)], text=True)
        pages = int(re.search(r'^Pages:\s+(\d+)', info, re.M).group(1))
        extracted = subprocess.check_output(['pdftotext', '-layout', str(pdf), '-'], text=True)
        texts = extracted.split('\f')
        ref_start = next((i+1 for i,s in enumerate(texts) if re.search(r'^\s*(?:\d+\s+)?References\s*$', s, re.M)), None)
        check('page-count-within-conservative-fast-impact-text-bound', 30 <= pages <= 45,
              {'total_pages': pages, 'references_start_page': ref_start,
               'note': '45 is the fast-impact text threshold, not an asserted universal TOSEM limit'})
        check('pdf-text-present', all(t in extracted for t in ['FedFence', '65,536', str(unit['tests_run']), '242,580', 'References']))
        fonts = subprocess.check_output(['pdffonts', str(pdf)], text=True)
        fontrows = [line.split() for line in fonts.splitlines()[2:] if line.strip()]
        check('all-pdf-fonts-embedded', bool(fontrows) and all(row[-5] == 'yes' for row in fontrows))
    build = json.loads((PAPER/'generated/build_environment.json').read_text())
    check('recorded-build-binds-delivered-pdf', pdf.exists() and build.get('pdf_sha256') == hashlib.sha256(pdf.read_bytes()).hexdigest()
          and bool(build.get('acmart_sha256')) and bool(build.get('acmart_declaration'))
          and build['font_files_distributed'] is False and build['production_TAPS_certified'] is False,
          {'actual_class': build['acmart_declaration'], 'compiled_with_current_release': build['compiled_with_current_release']})
    log = PAPER / 'main.log'
    # The final archive may omit transient TeX files. When rebuilding, check them.
    if log.exists():
        logtext = log.read_text(errors='replace')
        check('latex-no-overfull-or-undefined', 'Overfull \\hbox' not in logtext
              and 'Overfull \\vbox' not in logtext and 'There were undefined references' not in logtext
              and 'Citation `' not in logtext and 'Fatal error occurred' not in logtext
              and 'multiply defined' not in logtext)
    document = {'schema': 'fedfence-tosem-final-consistency-audit-v1',
                'passed': all(r['passed'] for r in checks), 'checks': checks,
                'implementation_sha256': implementation,
                'paper': {'pages': pages, 'references_start_page': ref_start,
                          'references': len(refs), 'figures': figures, 'tables': tables,
                          'sha256': hashlib.sha256(pdf.read_bytes()).hexdigest() if pdf.exists() else None},
                'limitations': ['Not an acceptance prediction or universal correctness proof.',
                    'Local source digests do not authenticate remote sources or reviewer identities.',
                    'No live cloud account, independent user study, or population benchmark.']}
    save_json(RESULTS / 'final_audit.json', document)
    (ROOT / 'docs').mkdir(exist_ok=True)
    report = '# TOSEM consistency audit\n\n' + ('PASS' if document['passed'] else 'FAIL')
    report += f" — {sum(r['passed'] for r in checks)}/{len(checks)} checks.\n\n"
    report += f"Implementation SHA-256: `{implementation}`.\n\n"
    report += f"Paper: {pages} pages; {len(refs)} references; {figures} figures; {tables} tables.\n\n"
    report += '| Check | Result | Detail |\n|---|---|---|\n'
    for row in checks:
        report += '| '+row['name']+' | '+('PASS' if row['passed'] else 'FAIL')+' | '+str(row['detail']).replace('|','\\|')+' |\n'
    report += '\n## Interpretation\n\n'+'\n'.join('- '+s for s in document['limitations'])+'\n'
    (ROOT / 'docs/AUDIT_REPORT.md').write_text(report)
    print(json.dumps({'passed': document['passed'], 'checks': len(checks), 'paper': document['paper']}))
    for row in checks:
        if not row['passed']: print('FAILED:', row)
    return 0 if document['passed'] else 1

if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as exc:
        print('Audit could not complete:', exc, file=sys.stderr)
        raise SystemExit(2)
