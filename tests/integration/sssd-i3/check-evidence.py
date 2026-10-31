#!/usr/bin/env python3
"""Ordinary CTest: retained evidence/source contracts only; never launches Docker."""
import ast,hashlib,json,subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
e=json.loads((HERE/'evidence.json').read_text())
assert e['schema']=='sssd-i3-native-v1' and e['base']=='ad41b954b009989cf9b12bed6fade17c1b7d2e9e'
assert set(e['profiles'])=={'debian-12','debian-13','ubuntu-24.04','ubuntu-26.04','alt-p11'}
for path,h in {**e['source_sha256'],**e['historical_sha256']}.items():assert digest(ROOT/path)==h,path
assert digest(HERE/'source-review.json')==e['source_review_sha256']
positives=('positive','readonly-write','missing-main','missing-conf-d','backend-only','cache-disabled','two-ldap',*(f'ldap-activation-{i}' for i in range(1,5)))
refusals=('bad-expectation','missing-environment','lazy-pam-unsupported','relation-conflict','unknown-provider','xattr-refused','stopped','shared-parent','shared-slave-parent')
faults=('unit-before','unit-after','snippet-inode','source-fd','persistent-drift','mount-change','stop-monitor','stop-pam','stop-backend','stale-configdb','stop-pam-after','environment-replace','negative-create','cleanup-fail')
for platform,p in e['profiles'].items():
 assert p['status']=='PASS' and not p['policy_success'] and p['policy_coverage']=='NotEvaluated'
 path=ROOT/p['report'];assert digest(path)==p['report_sha256']
 report=json.loads(path.read_text());o=report['experiments'];assert p['observations']==len(o) and o['result']['status']=='PASS'
 baseline=json.loads(subprocess.check_output(['git','-c','safe.directory='+str(ROOT),'-C',str(ROOT),'show',e['base']+':'+p['report']]))['experiments']
 changed=[]
 for name,before in baseline.items():
  if 'proofs' not in before:continue
  after=o[name]
  for key in ('status','success','runtime_effect_possible','policy_success','policy_coverage'):assert before[key]==after[key],(platform,name,key)
  assert {k:v for k,v in before['proofs'].items() if k!='A'}=={k:v for k,v in after['proofs'].items() if k!='A'},(platform,name,'B/C/P/admission changed')
  assert {k:v for k,v in before['engine'].items() if k!='diagnostic'}=={k:v for k,v in after['engine'].items() if k!='diagnostic'},(platform,name,'engine outcome changed')
  if before['proofs']['A']!=after['proofs']['A']:changed.append(name)
 assert set(changed)=={'unit-before','unit-after','mount-change','stop-monitor','stop-pam','stop-backend','stale-configdb'},(platform,changed)
 for name in ('unit-before','mount-change'):
  assert baseline[name]['diagnostic']==o[name]['diagnostic'] and baseline[name]['engine']['diagnostic']==o[name]['engine']['diagnostic'],(platform,name,'interference diagnostic changed')
 for name,x in o.items():
  if isinstance(x,dict) and 'proofs' in x:
   assert x['proofs']['A']==('Proven' if 'semantics' in x['checkpoints'] else 'NotProven'),(platform,name,'historical consumption phase')
 for name in positives:
  x=o[name];assert x['success'] and x['status']=='Success' and set(x['proofs'].values())=={'Proven'},(platform,name)
  assert x['old_invocation']!=x['new_invocation'] and x['configdb_generation']
  assert x['engine']['attempted'] and x['engine']['readiness'] and x['engine']['primary']=='Success'
  assert not x['engine']['cleanup_errors'] and not x['engine']['residual_mounts']
  assert all(v['initialized'] and v['configdb'] for v in x['processes'])
  for backend in (v for v in x['processes'] if v['role']=='backend'):
   assert backend['consumer_socket'] and backend['monitor_socket']
   if platform in ('debian-13','ubuntu-26.04'):assert backend['backend_bus_owner'].startswith(':')
  assert x['parameters'] and all(v['generation']==x['configdb_generation'] and v['token'] and v['source_contract'] for v in x['parameters'])
  assert not x['policy_success'] and x['policy_coverage']=='NotEvaluated'
 for name in refusals:
  x=o[name];assert not x['success'] and not x.get('engine',{}).get('attempted'),(platform,name)
 for name in faults:assert not o[name]['success'],(platform,name)
 for name in ('unit-before','mount-change'):
  x=o[name];assert x['proofs']['A']=='NotProven' and x['proofs']['B']=='NotProven' and x['proofs']['C']=='NotProven' and not x['engine']['attempted'],(platform,name,x['proofs'])
 x=o['timeout-published'];assert x['proofs']['A']==x['proofs']['B']==x['proofs']['C']=='NotProven' and not x['success'] and not x['engine']['attempted'] and x['engine']['primary']=='TimedOut' and 'published' in x['checkpoints']
 for name in ('snippet-inode','source-fd','persistent-drift','environment-replace','negative-create'):
  assert o[name]['proofs']['P']=='Drifted' and o[name]['proofs']['A']==o[name]['proofs']['B']==o[name]['proofs']['C']=='Proven',(platform,name)
 for name in ('stop-monitor','stop-pam','stop-backend','stale-configdb'):
  assert o[name]['engine']['attempted'] and o[name]['runtime_effect_possible'] and o[name]['proofs']['C']!='Proven' and o[name]['proofs']['A']=='NotProven'
 x=o['stop-pam-after'];assert x['status']=='RuntimeEffectUnknown' and x['proofs']['A']=='Proven' and x['proofs']['P']=='Proven' and x['proofs']['C']=='NotProven'
 x=o['cleanup-fail'];assert x['status']=='CleanupFailed' and x['proofs']['A']==x['proofs']['B']==x['proofs']['C']=='Proven' and x['proofs']['P']=='NotProven' and x['engine']['residual_mounts'] and x['engine']['primary']=='Success'
 assert o['ldap-functional-result']['status']=='PASS' and o['ldap-functional-result']['adapter_activations']==4
 for name in ('online-password','offline-password','aged-expiration-unlimited'):assert o[name]['exit_code']==0
 for name in ('offline-wrong-password','offline-cache-disabled-existing-db','aged-expiration-one-day'):assert o[name]['exit_code']!=0
 if platform in ('debian-13','ubuntu-26.04'):
  for name in ('bus-unsafe-parent','bus-foreign-acl'):assert not o[name]['success'] and not o[name]['engine']['attempted']
 if platform=='alt-p11':
  assert not o['stock-absent-environment']['success'] and o['explicit-environment-fixture']['stock_absent']
  children=[v for v in o['positive']['processes'] if v['role']!='monitor'];assert children and all(v['uid']!=0 for v in children)
reg=json.loads((HERE/'i1-regressions.json').read_text())
assert set(reg['profiles'])==set(e['profiles'])
for path,h in reg['production_source_sha256'].items():assert e['source_sha256'][path]==h
for path,digest_value in reg['fixture_sha256'].items():assert digest(ROOT/path)==digest_value
for platform,item in reg['profiles'].items():
 path=ROOT/item['report'];assert digest(path)==item['report_sha256']
 o=json.loads(path.read_text())['experiments'];assert item['status']=='PASS' and o['result']['status']=='PASS' and len(o)==item['observations']
 for race in ('create','delete','inode','bytes','metadata','restore'):assert o['race-'+race]['status']=='InterferenceDetected'
for path in HERE.glob('*.py'):ast.parse(path.read_text())
subprocess.run(['bash','-n',str(HERE/'run-native.sh')],check=True)
print('I3 retained source-bound native matrix PASS (evidence validation, not native reexecution)')
