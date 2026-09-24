#!/usr/bin/env python3
from __future__ import annotations
import ast, json, py_compile, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]

def main() -> int:
    failures=[]
    for path in sorted((ROOT/'fedfence').glob('*.py')) + sorted((ROOT/'scripts').glob('*.py')):
        try:
            py_compile.compile(str(path), doraise=True)
            ast.parse(path.read_text())
        except Exception as e:
            failures.append(f'{path.relative_to(ROOT)}: {e}')
    gh = (ROOT/'fedfence'/'github.py').read_text()
    wrapper = (ROOT/'fedfence'/'github_subject.py').read_text()
    if (ROOT/'fedfence'/'subject.py').exists():
        failures.append('stale independent subject.py implementation is present')
    if 'def parse_github_subject' not in gh or 'from .github import' not in wrapper:
        failures.append('GitHub subject semantics is not a single authoritative implementation plus wrapper')
    cert = (ROOT/'fedfence'/'certificate.py').read_text()
    if 'from .analyzer import' in cert or 'import analyze_case' in cert:
        failures.append('certificate verifier imports the high-level analyzer')
    if '_effective_summary_without_analyzer' not in cert:
        failures.append('missing independent effective certificate replay path')
    policy = (ROOT/'fedfence'/'policy.py').read_text()
    iac = (ROOT/'fedfence'/'iac.py').read_text()
    if 'repository_id' not in policy or 'repository_custom_properties.' not in policy:
        failures.append('selected GitHub claim keys are not present in the raw policy normalizer')
    if 'FedFenceStates' not in iac:
        failures.append('IaC extractor does not transport selected-claim event states')
    analyzer = (ROOT/'fedfence'/'analyzer.py').read_text()
    required = ['_find_subject_bad', '_find_audience_bad', 'DenyRect', 'allow_overapprox_core', 'deny_exact_core']
    for r in required:
        if r not in analyzer:
            failures.append(f'missing analyzer construct {r}')
    scan_roots = [ROOT/'fedfence', ROOT/'scripts', ROOT/'public_examples', ROOT/'external_evidence', ROOT/'governance_exports', ROOT/'deployment_manifest']
    scan_files = []
    for sr in scan_roots:
        if sr.exists():
            scan_files.extend(q for q in sr.rglob('*') if q.is_file() and q.name != 'run_code_audit.py' and q.suffix in {'.py','.md','.json','.sh','.txt','.csv'})
    scan_files.extend(p for p in [ROOT/'README.md', ROOT/'ARTIFACT.md', ROOT/'EVIDENCE.md', ROOT/'STATUS.md', ROOT/'REPRODUCE.md', ROOT/'SECURITY_SCOPE.md', ROOT/'DISCLOSURE.md'] if p.exists())
    for bad in ['requests.', 'urllib.request', 'subprocess.check_call(["curl"', 'ANTHROPIC' + '_AUTH' + '_TOKEN']:
        for path in sorted(set(scan_files)):
            text = path.read_text(errors='ignore')
            if bad in text:
                failures.append(f'forbidden network/secret token marker {bad!r} in {path.relative_to(ROOT)}')
                break
    out=ROOT/'results'; out.mkdir(exist_ok=True)
    result={'passed': not failures, 'failures': failures, 'python_files': len(list((ROOT/'fedfence').glob('*.py'))) + len(list((ROOT/'scripts').glob('*.py')))}
    (out/'code_audit.json').write_text(json.dumps(result, indent=2, sort_keys=True)+'\n')
    if failures:
        print(json.dumps(result, indent=2, sort_keys=True)); return 1
    print(json.dumps(result, indent=2, sort_keys=True)); return 0
if __name__ == '__main__':
    raise SystemExit(main())
