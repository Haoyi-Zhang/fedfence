from __future__ import annotations
import ast,importlib.util,inspect,json,pathlib,sys,traceback
ROOT=pathlib.Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT))
projection_modules=[]
for p in ROOT.rglob('projection.py'):
 t=p.read_text(errors='replace')
 if 'def observation_bases' in t and 'def inspect_projection' in t: projection_modules.append(p)
assert projection_modules,'projection module not found'
executed=[]; candidates=[]
for p in ROOT.rglob('test*.py'):
 src=p.read_text(errors='replace')
 try: tree=ast.parse(src)
 except SyntaxError: continue
 for node in tree.body:
  if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):
   frag=ast.get_source_segment(src,node) or ''
   if 'inspect_projection' in frag and 'mixed_classes' in frag:
    candidates.append({'path':p,'name':node.name,'source':frag})
# Execute zero-argument regression tests that directly check the native mixed_classes interface.
for c in candidates:
 p=c['path']; name=c['name']
 spec=importlib.util.spec_from_file_location('basis_test_'+str(len(executed)),p)
 mod=importlib.util.module_from_spec(spec)
 try:
  assert spec and spec.loader; spec.loader.exec_module(mod)
  fn=getattr(mod,name)
  if len(inspect.signature(fn).parameters)==0:
   fn(); executed.append({'path':str(p.relative_to(ROOT)),'test':name})
 except Exception as e:
  raise AssertionError(f'native mixed-class regression failed: {p}:{name}: {e}') from e
assert executed, 'no executable test of inspect_projection.mixed_classes was found'
# Require the regression source to create at least two distinct states and distinguish intended labels.
combined='\n'.join(c['source'] for c in candidates)
state_constructors=len(re.findall(r'(?:WorkflowState|State|EventState)\s*\(',combined))
label_signal=bool(re.search(r'intent|intended|positive|negative',combined,re.I))
assert state_constructors>=2 and label_signal,'mixed-class regression does not visibly construct positive/negative states'
report={'schema':'fedfence.basis-witness-audit.v2','status':'pass','projection_modules':[str(p.relative_to(ROOT)) for p in projection_modules],
 'executed_native_mixed_class_tests':executed,'acceptance':'native inspect_projection.mixed_classes is executed on a regression with at least two states and intent labels',
 'api_contract':'observation_bases returns bases/cardinality; no-solution empty list is not a witness; mixed_classes is obtained from inspect_projection'}
(ROOT/'results').mkdir(exist_ok=True); (ROOT/'results/basis_witness_audit.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n'); print(json.dumps(report,sort_keys=True))
