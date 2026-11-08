#!/usr/bin/env python3
"""Check current-source I6 native artifacts. Never reinterpret missing tests as PASS."""
import hashlib,json,pathlib,re,subprocess,sys
root=pathlib.Path(__file__).resolve().parents[3]
evidence=pathlib.Path(sys.argv[1] if len(sys.argv)>1 else root/'build-pam-i6')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
import importlib.util
_spec=importlib.util.spec_from_file_location('i6_source_manifest',pathlib.Path(__file__).with_name('i6-source-manifest.py'))
_manifest=importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_manifest)
source=_manifest.source_manifest(root)
required=['baseline password change','baseline correct authentication','baseline incorrect authentication',
 'quality positive','quality weak rejected','quality root bypass positive','quality root enforce negative',
 'quality refresh short candidate rejected','quality refresh relaxed candidate accepted',
 'quality+history first change','quality+history second change','quality+history reuse rejected',
 'history token beyond refreshed window accepted','history root enforced positive-control rejection','history root bypass reuse','history root enforce reuse rejected',
 'history-only new token','history-only reuse rejected','combined correct authentication',
 'combined correct password blocked','combined after explicit reset','combined new password',
 'combined weak password rejected','combined recent password rejected','history+lockout authentication',
 'history+lockout reuse rejected','quality+lockout authentication','quality+lockout weak rejected',
 'post-release password change','post-release authentication']
summary={'base':json.loads((evidence/'debian12'/'functional.json').read_text())['base'],
 'source_sha256':source,'proof_boundary':'L1 + L2 production classes + L3 installed native PAM consumers; no full daemon L4',
 'platforms':{}}
assert subprocess.run(['git','-C',str(root),'merge-base','--is-ancestor',summary['base'],'HEAD']).returncode==0
# Test secrets are never copied into reports/logs. Only scan candidate constants.
testsource=(root/'tests/integration/pam-dependencies/native-functional.py').read_text()
secrets=re.findall(r"'([^'\n]*![^'\n]*#[^'\n]*)'",testsource)
for tag in ['debian12','debian13','ubuntu2404','ubuntu2604','alt-p11']:
 out=evidence/tag;x=json.loads((out/'functional.json').read_text());audit=json.loads((out/'audit.json').read_text())
 assert x['platform']==tag and x['base']==summary['base'] and x['source_sha256']==source,tag
 assert x['status']=='PASS measured scenarios only',tag
 assert x['installed_L4'].startswith('BLOCKED:'),tag
 rows=x['scenarios'];names={r['name'] for r in rows}
 assert set(required)<=names,(tag,'missing scenarios',set(required)-names)
 assert all(r['status']=='PASS' for r in rows),tag
 assert set(x['parameters'])=={p['name'] for p in audit['policies'] if p['registered']},tag
 assert audit['graph_valid'] and all(not p['registered'] for p in audit['policies'] if p['support']=='Unsupported'),tag
 assert all(p['rollback_enrollment'] in {'Supported','Unsupported','NotEnrolled'} for p in audit['policies']),tag
 before=(evidence/f'i6-source-{tag}.before').read_text().strip();after=(evidence/f'i6-source-{tag}.after').read_text().strip()
 assert before==after==source,tag
 log=(evidence/f'i6-tests-{tag}.log').read_text();assert '100% tests passed, 0 tests failed out of 25' in log,tag
 for r in rows:
  if r['level']=='L3':
   assert (r['exit']==0)==r['expected_success'],(tag,r['name'])
   assert r['hash_changed']==(r['expected_success'] and r['service']=='passwd'),(tag,r['name'])
   identity=re.search(r'uid=(\d+) euid=(\d+)',r['consumer']);assert identity,(tag,r['name'])
   assert int(identity[2])==0,(tag,r['name'])
   assert (int(identity[1])==0)==(' root ' in r['name']),(tag,r['name'])
  elif r['request']['action']=='apply':
   detail=json.loads((out/r['artifact']).read_text())['functional']
   if not r['expected']:
    target=next(v for v in detail['results'] if v['name']==r['request']['policy'])
    assert not target['own_attempted'],(tag,r['name'])
 final_action=next(r for r in reversed(rows) if r['level']=='L2')
 final_state=json.loads((out/final_action['artifact']).read_text())['functional']
 journal=json.loads(final_state['journal']) if final_state['journal'] else {'records':[]}
 assert not any(r['status'] in {'prepared','applied','rollback_failed'} for r in journal['records']),tag
 if tag=='alt-p11':
  assert {'passwdqc similar-match rejected','ALT pwtxn locked rejection','ALT pwtxn after unlock',
          'ALT requisite correct blocked','ALT requisite after reset'}<=names
 else:assert {'quality missing digit rejected','quality username rejected','quality gecos rejected','quality difok small edit rejected','quality classes rejected','quality classes relaxed accepted','quality credits positive'}<=names
 for p in out.glob('*.json'):
  text=p.read_text();assert not any(s in text for s in secrets if len(s)>5),(tag,'secret in evidence',p.name)
 summary['platforms'][tag]={'L1':'25/25 CTest','L2':'PASS production policy/registry/journal lifecycle',
  'L3':'PASS measured passwd + login consumers','L4':'BLOCKED no full daemon lifecycle',
  'parameter_policies':x['parameters'],'consumer_scenarios':[r for r in rows if r['level']=='L3'],
  'image':(out/'image-id.txt').read_text().strip(),
  'artifacts':{str(p.relative_to(evidence)):sha(p) for p in sorted(out.glob('*.json'))},
  'packages_sha256':sha(out/'packages.txt'),'driver_sha256':x['driver_sha256'],'consumer_sha256':x['consumer_sha256']}
(evidence/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print('PASS I6 measured L1/L2/L3 matrix, current source, all parameter identities and required consumers; L4 NOT PROVEN')
