"""Check actually produced phase-one records. Not the separate ten-stage/PDF audit."""
from pathlib import Path
import argparse
import csv
import json
import re

STEPS = ['unit-tests', 'core-self-check', 'projection-audit', 'relational-audit',
         'two-sided-validation', 'character-domain', 'final-boundaries',
         'seeded-faults', 'repair-audit', 'source-studies']


def require(ok, detail):
    if not ok:
        raise ValueError(detail)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    root = args.out/'execution/P113/artifact'
    def load(name):
        return json.loads((root/'tosem/results'/name).read_text(encoding='utf-8'))
    repro = load('reproduction.json')
    require(repro['passed'] and [s['name'] for s in repro['steps']] == STEPS and
            all(s['exit_code'] == 0 and s['log'] == 'logs/'+s['name']+'.log' and
                (root/s['log']).is_file() for s in repro['steps']), 'all ten genuine stage records/logs')
    unit = load('unit_tests.json')
    require(unit['passed'] and unit['tests_run'] == 204 and
            all(unit[k] == 0 for k in ('failures', 'errors', 'skipped')), 'all ordinary204')
    faults = load('seeded_faults.json')
    require(faults['passed'] and faults['hand_selected_faults'] == faults['detected'] == len(faults['rows']) == 8
            and all(r['baseline_passed'] and r['assertion_detected_fault'] and
                    not r['syntax_or_import_error'] and
                    (root/'logs/seeded_faults'/(r['name']+'.log')).is_file()
                    for r in faults['rows']), 'all eight local semantic controls/logs')
    validation = load('validation_summary.json')
    boundary = load('final_validation_summary.json')
    domain = load('character_domain_audit.json')
    require(repro['implementation_sha256'] == validation['environment']['implementation_sha256']
            == boundary['implementation_sha256'] == domain['implementation_sha256'], 'fresh implementation bindings')
    require(all(r['network_access'] is False and r['cloud_accounts_used'] is False
                for r in (repro, validation, boundary, domain)), 'owned offline scope')
    scaling = load('local_scaling.json')
    with (root/'tosem/results/local_scaling.csv').open(newline='') as stream:
        rows = list(csv.DictReader(stream))
    require(scaling['passed'] and scaling['recorded_runs'] == len(rows) == 54,
            'original scaling observations retained')
    for name, count in [('consumer12.log', 12), ('scalar7.log', 7), ('assembler8.log', 8)]:
        text = (args.out/name).read_text(encoding='utf-8')
        require(re.search(r'Ran '+str(count)+r' tests in [\d.]+s\s+OK\s*$', text)
                and len(re.findall(r'^test_.* \.\.\. ok$', text, re.M)) == count, 'actual separate suite: '+name)
    generated = args.out/'execution/P113/paper/generated'
    require((generated/'character_domain_rows.tex').is_file() and
            json.loads((generated/'generation.json').read_text())['macros']['TestCount'] == 204,
            'actual sibling paper data generated')
    result = dict(ten_science_stages_complete=True, ordinary_methods=204,
                  semantic_fault_controls=8, separate_methods=dict(consumer=12, scalar=7, assembler=8),
                  implementation_sha256=repro['implementation_sha256'],
                  paper_build_performed=False, final_tosem_audit_performed=False,
                  scope='Intermediate source/record check; full statistical/paper/PDF audit remains required.')
    with (args.out/'science-phase-summary.json').open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
