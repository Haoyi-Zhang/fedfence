from __future__ import annotations
import json,pathlib,re
ROOT=pathlib.Path(__file__).resolve().parents[1]; STUDY=ROOT/'study'; P=STUDY/'source_frontier_sample.json'
d=json.loads(P.read_text()); out=[]
VARBLOCK=re.compile(r'variable\s+"([^"]+)"\s*\{(.*?)\n\}',re.S)
def defaults(text):
 vals={}
 for name,body in VARBLOCK.findall(text):
  m=re.search(r'\bdefault\s*=\s*("(?:[^"\\]|\\.)*"|\[[^\]]*\]|true|false|-?\d+(?:\.\d+)?)',body,re.S)
  if m: vals[name]=m.group(1).strip()
 return vals
for i,r in enumerate(d['records']):
 source=STUDY/r['source_snapshot'] if r.get('source_snapshot') else None
 src=source.read_text(errors='replace') if source and source.exists() else ''
 ctx=[]
 mp=STUDY/r['context_manifest'] if r.get('context_manifest') else None
 if mp and mp.exists():
  md=json.loads(mp.read_text())
  for f in md.get('files',[]):
   q=mp.parent/f.get('name','')
   if q.exists():ctx.append(q.read_text(errors='replace'))
 full='\n'.join([src,*ctx]); defs=defaults(full)
 has_sub='token.actions.githubusercontent.com:sub' in full
 has_aud='token.actions.githubusercontent.com:aud' in full
 # Gather snippets around each subject key from the complete same-directory trust document.
 snippets=[]
 for m in re.finditer(r'token\.actions\.githubusercontent\.com:sub',full): snippets.append(full[max(0,m.start()-240):m.end()+520])
 ss='\n'.join(snippets)
 vars_used=set(re.findall(r'var\.([A-Za-z_][A-Za-z0-9_]*)',ss))
 all_defaults=bool(vars_used) and vars_used.issubset(defs)
 literal_subject=bool(re.search(r'["\']repo:[^"\']+["\']',ss)) and not vars_used
 constant_foldable=(literal_subject or all_defaults) and not re.search(r'\bmodule\s+"|formatlist\(|dynamic\s+"|for\s+\w+\s+in|jsonencode\([^)]*module\.|pulumi|aws-cdk|new\s+iam\.|GetPolicyDocument',ss,re.I)
 cls='literal-or-constant-foldable' if constant_foldable else 'requires-module-caller-or-language-evaluation'
 out.append({'index':i,'repository':r.get('repository'),'path':r.get('path'),'source_available':bool(src),
  'context_files':len(ctx),'has_subject_constraint':has_sub,'has_audience_constraint_in_complete_collected_document':has_aud,
  'variables_in_subject_expression':sorted(vars_used),'subject_variables_with_defaults':sorted(vars_used & defs.keys()),
  'recomputed_frontier_class':cls,'original_human_summary':r.get('human_summary'),
  'basis':'fixed source plus restored same-directory immutable-commit context; external modules and absent callers remain unresolved'})
summary={'total':len(out),'source_available':sum(x['source_available'] for x in out),'literal_or_constant_foldable':sum(x['recomputed_frontier_class']=='literal-or-constant-foldable' for x in out),'requires_context':sum(x['recomputed_frontier_class']!='literal-or-constant-foldable' for x in out),'missing_audience_in_complete_collected_document':sum(x['source_available'] and not x['has_audience_constraint_in_complete_collected_document'] for x in out)}
res={'schema':'fedfence.source-frontier-audit.v2','summary':summary,'records':out,'limitation':'The fixed 24 source files and available same-directory context are inspected. No missing caller, external module input, search ranking, or label source is invented.'}
(ROOT/'results').mkdir(exist_ok=True); (ROOT/'results/source_frontier_audit.json').write_text(json.dumps(res,indent=2,sort_keys=True)+'\n'); print(json.dumps(res,sort_keys=True))
