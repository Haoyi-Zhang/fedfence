from __future__ import annotations
import hashlib,json,pathlib,re,urllib.parse,urllib.request
ROOT=pathlib.Path(__file__).resolve().parents[1]; STUDY=ROOT/'study'; DATA=STUDY/'source_frontier_sample.json'
d=json.loads(DATA.read_text()); records=d['records']; report=[]
HEAD={'User-Agent':'FedFence-repro/1','Accept':'application/vnd.github+json'}
def get(url):
 req=urllib.request.Request(url,headers=HEAD)
 with urllib.request.urlopen(req,timeout=30) as r:return r.read()
for i,r in enumerate(records):
 repo,path,ref=r.get('repository'),r.get('path'),r.get('commit')
 base=STUDY/'source_frontier_sources'/f'{i:02d}'; base.mkdir(parents=True,exist_ok=True)
 ctxdir=base/'context'; ctxdir.mkdir(exist_ok=True)
 directory=str(pathlib.PurePosixPath(path).parent)
 api=f'https://api.github.com/repos/{repo}/contents/{urllib.parse.quote(directory,safe="/")}?ref={urllib.parse.quote(ref,safe="")}'
 items=[]; status='unavailable'
 try:
  payload=json.loads(get(api)); status='listed'
  if isinstance(payload,dict):payload=[payload]
  # Full trust document context: source plus same-directory program/config files that may define values.
  allowed={'.tf','.tfvars','.json','.yaml','.yml','.ts','.js','.go','.py','.md'}
  for item in payload:
   if item.get('type')!='file':continue
   name=item.get('name',''); ext=pathlib.PurePosixPath(name).suffix.lower()
   if ext not in allowed and name not in {'README','Makefile'}:continue
   if item.get('size',0)>750000:continue
   raw=item.get('download_url')
   if not raw:continue
   try:
    b=get(raw); out=ctxdir/name; out.write_bytes(b)
    items.append({'name':name,'repository_path':item.get('path'),'sha':item.get('sha'),'sha256':hashlib.sha256(b).hexdigest(),'bytes':len(b)})
   except Exception as e:
    items.append({'name':name,'repository_path':item.get('path'),'status':'unavailable:'+type(e).__name__})
 except Exception as e:status='unavailable:'+type(e).__name__
r['context_manifest']=str((ctxdir/'manifest.json').relative_to(STUDY))
(ctxdir/'manifest.json').write_text(json.dumps({'directory':directory,'listing_status':status,'files':items},indent=2,sort_keys=True)+'\n')
report.append({'index':i,'repository':repo,'path':path,'listing_status':status,'context_files':sum('sha256' in x for x in items)})
DATA.write_text(json.dumps(d,indent=2,ensure_ascii=False)+'\n')
(STUDY/'source_frontier_context_report.json').write_text(json.dumps({'schema':'fedfence.source-context.v1','records':report,
 'limitation':'Only the fixed file and same-directory immutable-commit context are restored. External modules and absent callers are not guessed.'},indent=2,sort_keys=True)+'\n')
print(json.dumps({'total':len(report),'listed':sum(x['listing_status']=='listed' for x in report),'context_files':sum(x['context_files'] for x in report)},sort_keys=True))
