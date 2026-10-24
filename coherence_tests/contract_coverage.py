"""Passive evidence qualification and direct-set comparison for retained cases.

No provider, workflow or upstream program is executed. Empty lower obligations
are valid mathematics but are never counted as nonvacuous two-sided evidence.
"""
from collections import Counter
from pathlib import Path
import argparse
import hashlib
import json
import re

ROOT=Path(__file__).resolve().parents[1]


def tuples(items):
    return {(item['sub'],item['aud']) for item in items}


def qualification(public, corrections):
    rows=[];disagreements=[]
    roles={role['role']:role for role in corrections['sports_store']['roles']}
    micro=corrections['microticket']
    for row in public['rows']:
        finite=row['entry_point']=='finite-explicit-issuer-study-adapter'
        result=row['result'];direct=None
        if not finite:
            checks=result['required_token_checks']
            required=checks['required']
            if type(required) is not int or required<0 or required!=len(checks['checks']):
                raise ValueError('Malformed lower-obligation inventory')
        else:
            if row['role'] in roles:
                contract=roles[row['role']]
            elif row['role']==micro['role']:
                contract=micro
            else:raise ValueError('Unmapped finite role')
            admitted={tuple(pair) for pair in result['admitted']}
            issuer={tuple(pair) for pair in result['issuer_domain']}
            allowed=tuples(contract['intent']);needed=tuples(contract['required'])
            if not needed<=allowed or not needed<=issuer or not admitted<=issuer:
                raise ValueError('Invalid finite intent or source domain')
            required=len(needed)
            # Ordinary direct two-sided set reasoning, without framework helpers.
            direct='pass' if admitted<=allowed and needed<=admitted else 'fail'
            if direct!=result['verdict']:
                disagreements.append([row['id'],row['role'],row['configuration']])
        rows.append({'id':row['id'],'role':row['role'],'configuration':row['configuration'],
                     'entry_point':row['entry_point'],'model_verdict':result['verdict'],
                     'required_occurrences':required,
                     'lower_evidence':'nonempty-reconstructed' if required else 'vacuous',
                     'direct_two_sided_verdict':direct,
                     'owner_confirmed':False,'deployment_claim_supported':False})
    if len({(x['id'],x['role'],x['configuration']) for x in rows})!=len(rows):
        raise ValueError('Duplicate configuration')
    groups=[]
    for profile in sorted({x['entry_point'] for x in rows}):
        selected=[x for x in rows if x['entry_point']==profile]
        groups.append({'profile':profile,'configurations':len(selected),
                       'nonempty_lower_configurations':sum(x['required_occurrences']>0 for x in selected),
                       'required_occurrences':sum(x['required_occurrences'] for x in selected),
                       'verdicts':dict(Counter(x['model_verdict'] for x in selected))})
    return {'configurations':len(rows),'groups':groups,'rows':rows,
            'finite_direct_set_comparisons':sum(x['direct_two_sided_verdict'] is not None for x in rows),
            'finite_direct_set_disagreements':disagreements,
            'nonempty_owner_confirmed_public_deployment_contracts':0,
            'meaning':'model verdicts unchanged; empty lower sets do not demonstrate release preservation'}


def block_end(text,start):
    """Bounded quoted-string/comment-aware brace scan; not a Terraform evaluator."""
    depth=0;quoted=False;escape=False;comment=False
    for index in range(start,len(text)):
        ch=text[index]
        if comment:
            if ch=='\n':comment=False
            continue
        if quoted:
            if escape:escape=False
            elif ch=='\\':escape=True
            elif ch=='"':quoted=False
            continue
        if ch=='#':comment=True
        elif ch=='"':quoted=True
        elif ch=='{':depth+=1
        elif ch=='}':
            depth-=1
            if depth==0:return index+1
    raise ValueError('Unclosed resource block')


def clean_source(text):
    chars=list(text);quoted=False;escape=False;comment=False;i=0
    while i<len(text):
        ch=text[i]
        if comment:
            if ch=='\n':comment=False
            else:chars[i]=' '
        elif quoted:
            if escape:escape=False
            elif ch=='\\':escape=True
            elif ch=='"':quoted=False
        elif ch=='"':quoted=True
        elif ch=='#' or text[i:i+2]=='//':
            comment=True;chars[i]=' '
        elif text[i:i+2] in ('/*','<<'):
            raise ValueError('Unsupported source lexical form')
        i+=1
    if quoted:raise ValueError('Unclosed quoted string')
    return ''.join(chars)


def source_tokens(text):
    return re.findall(r'"(?:[^"\\]|\\.)*"|[A-Za-z_][A-Za-z_0-9]*|[^\s]',text)


def group_body(tokens,opening):
    """Admit one complete, balanced group, without evaluating expressions."""
    closing={'{':'}','[':']','(':')'}
    if not tokens or tokens[0]!=opening:raise ValueError('Expected literal source group')
    stack=[]
    for index,token in enumerate(tokens):
        if token in closing:stack.append(closing[token])
        elif token in closing.values():
            if not stack or stack.pop()!=token:raise ValueError('Unbalanced source group')
            if not stack:
                if index!=len(tokens)-1:raise ValueError('Trailing source expression')
                return tokens[1:-1]
    raise ValueError('Unclosed source group')


def direct_fields(tokens):
    """Read direct map assignments only; nested maps never become siblings."""
    body=group_body(tokens,'{');fields={};index=0
    closing={'{':'}','[':']','(':')'}
    def key(token):
        if token.startswith('"'):return json.loads(token)
        if re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*',token):return token
        raise ValueError('Unsupported source map key')
    while index<len(body):
        if body[index]==',':index+=1;continue
        name=key(body[index])
        if index+1>=len(body) or body[index+1]!='=':raise ValueError('Expected map assignment')
        if name in fields:raise ValueError('Duplicate source field')
        start=index+2;index=start;stack=[]
        while index<len(body):
            token=body[index]
            if not stack and index>start:
                if token==',':break
                if index+1<len(body) and body[index+1]=='=':break
            if token in closing:stack.append(closing[token])
            elif token in closing.values():
                if not stack or stack.pop()!=token:raise ValueError('Unbalanced source value')
            index+=1
        if stack or index==start:raise ValueError('Incomplete source value')
        fields[name]=body[start:index]
    return fields


def literal_subjects(text,role):
    text=clean_source(text)
    matches=list(re.finditer(r'resource\s+"aws_iam_role"\s+"'+re.escape(role)+r'"\s*(\{)',text))
    if len(matches)!=1:raise ValueError('Missing or duplicate role')
    start=matches[0].start();end=block_end(text,matches[0].start(1));body=text[start:end]
    fields=direct_fields(source_tokens(text[matches[0].start(1):end]))
    policy=fields.get('assume_role_policy',[])
    if policy[:2]!=['jsonencode','('] or policy[-1:]!=[')']:
        raise ValueError('Literal jsonencode trust policy required')
    policy_fields=direct_fields(policy[2:-1])
    statement=direct_fields(group_body(policy_fields.get('Statement',[]),'['))
    if statement.get('Effect')!=['"Allow"'] or statement.get('Action')!=['"sts:AssumeRoleWithWebIdentity"']:
        raise ValueError('Single Allow web-identity statement required')
    condition=direct_fields(statement.get('Condition',[]))
    if set(condition)!={'StringEquals'}:
        raise ValueError('Only literal StringEquals conditions admitted')
    equals=direct_fields(condition['StringEquals'])
    value=equals.get('token.actions.githubusercontent.com:sub')
    if value is None:raise ValueError('Missing trust-condition subject')
    parsed=json.loads(''.join(value));subjects=parsed if isinstance(parsed,list) else [parsed]
    if not subjects or any(type(x) is not str or '$' in x or '*' in x or '?' in x for x in subjects):
        raise ValueError('Subject is not a resolved exact literal')
    return {'role':role,'start_line':text.count('\n',0,start)+1,
            'end_line':text.count('\n',0,end)+1,'subjects':subjects,
            'strict_gate_or_cloud_authorization_established':False}


def source_projection(text,corrections):
    projected=[]
    for role in corrections['sports_store']['roles']:
        row=literal_subjects(text,role['role'])
        if row['subjects']!=[x['sub'] for x in role['after_allow']]:
            raise ValueError('Complete-file literal projection differs from reconstructed after role')
        projected.append(row)
    return {'repository':corrections['sports_store']['repository'],
            'commit':corrections['sports_store']['commit'],'path':'iam.tf',
            'complete_source_bytes':len(text.encode('utf-8')),
            'source_content_identity':hashlib.sha256(text.encode('utf-8')).hexdigest(),
            'literal_role_projections':projected,
            'source_redistributed':False,'frontier_24_excerpts_denominator_unchanged':True,
            'scope':'literal subject projection from one complete file; not module, workflow, governance or owner-intent verification'}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--source-file',type=Path)
    parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    if args.output.exists():parser.error('fresh output directory required')
    corrections=json.loads((ROOT/'study/corrections.json').read_text())
    result=qualification(json.loads((ROOT/'tosem/results/public_study.json').read_text()),corrections)
    if result['finite_direct_set_disagreements']:raise ValueError('Direct set mismatch')
    projection=None
    if args.source_file:
        projection=source_projection(args.source_file.read_text(encoding='utf-8'),corrections)
    args.output.mkdir(parents=True)
    (args.output/'coverage.json').write_text(json.dumps(result,indent=2)+'\n')
    if projection is not None:
        (args.output/'literal-source.json').write_text(json.dumps(projection,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k!='rows'},indent=2))


if __name__=='__main__':main()
