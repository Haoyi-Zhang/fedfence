#!/usr/bin/env python3
from __future__ import annotations
import csv, json, statistics, sys, tempfile
from pathlib import Path
from typing import Any, Dict
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT/'scripts'))
from fedfence.iac import extract_file
from fedfence.analyzer import analyze_case
from run_iac_scale import make_template, meta

TEMPLATES=[
 'safe_exact_branch','safe_protected_environment','repo_suffix_wildcard','pull_request_exact',
 'unprotected_environment','selected_claim_ref_env_repoid_safe','selected_claim_custom_property_without_ref_unsafe'
]
FORMATS=['terraform-hcl','cloudformation-yaml']
PER=4

def hcl_quote(s: str) -> str:
    return json.dumps(s)

def hcl_file(name: str, case: Dict[str, Any], expected: bool, template: str) -> str:
    tags=meta(case,expected,template)
    tag_lines='\n'.join(f'    {k} = {hcl_quote(v)}' for k,v in sorted(tags.items()))
    return f'''resource "aws_iam_role" "{name}" {{
  name = "{name}"
  assume_role_policy = {hcl_quote(json.dumps(case['policy'], sort_keys=True))}
  tags = {{
{tag_lines}
  }}
}}
'''

def yaml_scalar(v: str) -> str:
    return json.dumps(v)

def yaml_file(name: str, case: Dict[str, Any], expected: bool, template: str) -> str:
    tags=meta(case,expected,template)
    meta_lines='\n'.join(f'      {k}: {yaml_scalar(v)}' for k,v in sorted(tags.items()))
    policy=json.dumps(case['policy'], sort_keys=True)
    # Use JSON embedded in YAML; PyYAML parses it to the same mapping.
    return f'''AWSTemplateFormatVersion: "2010-09-09"
Resources:
  {name.replace('_','')}:
    Type: AWS::IAM::Role
    Metadata:
{meta_lines}
    Properties:
      AssumeRolePolicyDocument: {policy}
'''

def materialize(fmt: str, tmp: Path, name: str, case: Dict[str, Any], expected: bool, template: str) -> Path:
    if fmt=='terraform-hcl':
        p=tmp/f'{name}.tf'; p.write_text(hcl_file(name,case,expected,template)); return p
    p=tmp/f'{name}.yaml'; p.write_text(yaml_file(name,case,expected,template)); return p

def main()->int:
    out=ROOT/'results'; out.mkdir(exist_ok=True)
    rows=[]
    with tempfile.TemporaryDirectory() as td:
        tmp=Path(td)
        idx=0
        for fmt in FORMATS:
            for template in TEMPLATES:
                for i in range(PER):
                    case, expected = make_template(template, f'frontier{i:02d}')
                    name=f'{template}_{fmt.replace("-","_")}_{i:02d}'
                    path=materialize(fmt,tmp,name,case,expected,template)
                    roles=extract_file(path)
                    if len(roles)!=1:
                        raise RuntimeError(f'expected one role from {path}, got {len(roles)}')
                    role=roles[0]
                    res=analyze_case(role.case)
                    rows.append({'format':role.format,'template':template,'expected_safe':bool(expected),
                                 'fedfence_safe':bool(res.safe),'correct':bool(expected)==bool(res.safe),
                                 'findings':len(res.findings)})
                    idx+=1
    with (out/'iac_frontier_rows.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
    overall={'rows':len(rows),'formats':FORMATS,'templates':len(TEMPLATES),'per_template_format':PER,
             'correct':sum(1 for r in rows if r['correct']),'passed':all(r['correct'] for r in rows),
             'purpose':'optional parser-frontier corpus for Terraform HCL and CloudFormation YAML review packets'}
    (out/'iac_frontier_overall.json').write_text(json.dumps(overall,indent=2,sort_keys=True)+'\n')
    print(json.dumps(overall,indent=2,sort_keys=True))
    return 0 if overall['passed'] else 1
if __name__=='__main__':
    raise SystemExit(main())
