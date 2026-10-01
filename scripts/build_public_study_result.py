from __future__ import annotations
import json,pathlib,re,sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
COR=json.loads((ROOT/'study/corrections.json').read_text())
SS=COR['sports_store']['repository']; MT=COR['microticket']['repository']
def repo_of(x):
 if not isinstance(x,dict):return None
 return x.get('repository') or x.get('repository_full_name') or x.get('repo')
def commit_of(x):
 if not isinstance(x,dict):return None
 return x.get('commit') or x.get('commit_sha') or x.get('sha')
def records_in(x):
 out=[]
 def walk(v):
  if isinstance(v,dict):
   r=repo_of(v)
   if isinstance(r,str) and '/' in r: out.append(v)
   for z in v.values(): walk(z)
  elif isinstance(v,list):
   for z in v: walk(z)
 walk(x); return out
# Recover unaffected public records from supplied source/result objects. We only retain one record per repo+commit.
cands=[]
for p in list((ROOT/'study').rglob('*.json'))+list((ROOT/'results').glob('*.json')):
 if p.name in {'corrections.json','public_change_study.json','entrypoint_matrix.json'}:continue
 try:d=json.loads(p.read_text())
 except Exception:continue
 rs=records_in(d)
 unique={(repo_of(r),commit_of(r)) for r in rs if repo_of(r)}
 if SS in {u[0] for u in unique} or MT in {u[0] for u in unique}:
  cands.append((len(unique),p,rs))
# Prefer object with the broadest public corpus.
base=[]; source=None
if cands:
 _,source,rs=max(cands,key=lambda z:z[0])
 seen=set()
 for r in rs:
  repo=repo_of(r); commit=commit_of(r)
  if not repo or repo in {SS,MT}:continue
  k=(repo,commit)
  if k in seen:continue
  seen.add(k)
  base.append({'repository':repo,'commit':commit,'role':r.get('role') or r.get('role_id') or 'reported-role',
               'configurations':[{'name':'before','result':r.get('before') or r.get('before_result') or 'source-stated'},
                                 {'name':'after','result':r.get('after') or r.get('after_result') or 'source-stated'}],
               'recovered_from':str(source.relative_to(ROOT))})
# The supplied study was nine commits. Keep seven unaffected only; if recovery is incomplete, report it, do not invent.
base=base[:7]
records=list(base)
for role in COR['sports_store']['roles']:
 records.append({'repository':SS,'commit':COR['sports_store']['commit'],'role':role['role'],
                 'configurations':[{'name':'before','result':'fail'},{'name':'after','result':'pass'}],
                 'source_evidence':COR['sports_store']['evidence']})
m=COR['microticket']
records.append({'repository':MT,'commit':m['commit'],'role':m['role'],'configurations':[
 {'name':x['name'],'result':x['expected'],'conditional_on':x.get('conditional_on')} for x in m['configurations']],
 'assignment_evidence':'unavailable; the observed token is not proof that the Terraform variable was assigned'})
commits=len({(r['repository'],r.get('commit')) for r in records}); roles=len(records); phases=sum(len(r['configurations']) for r in records)
result={'schema':'fedfence.public-change-study.v2','records':records,'denominators':{'commits':commits,'roles':roles,'evaluated_configurations':phases},
 'recovery':{'source_object':str(source.relative_to(ROOT)) if source else None,'unaffected_records_recovered':len(base),'expected_unaffected_records':7,
             'complete':len(base)==7},
 'interpretation':'source-backed purposive study, not prevalence or field accuracy'}
(ROOT/'results/public_change_study.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
assert len(base)==7, f'supplied corpus exposed {len(base)} unaffected records, expected 7; no records are invented'
print(json.dumps(result,sort_keys=True))
