#!/usr/bin/env python3
"""Checks retained I2 evidence only. Never launches privileged runtime tests."""
import ast,hashlib,json,subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
e=json.loads((HERE/'evidence.json').read_text())
platforms={'debian-12','debian-13','ubuntu-24.04','ubuntu-26.04','alt-p11'}
assert e['schema']=='sssd-i2-native-v1' and set(e['profiles'])==platforms
for group in ('source_sha256','historical_sha256'):
 for path,digest in e[group].items():assert hashlib.sha256((ROOT/path).read_bytes()).hexdigest()==digest,path
for platform,p in e['profiles'].items():
 assert p['status']=='PASS' and not p['runtime_receipt'] and not p['completed_proofs']
 report=p['report'];o=report['experiments']
 assert o['result']['status']=='PASS' and not o['result']['runtime_receipt'] and not o['result']['completed_proofs']
 for cmd in report['commands']:assert 'command' in cmd and 'exit_code' in cmd
 for name in ('one-ldap','two-ldap','ldap-default-auth','inactive-section','enabled-true','native-defaults','boolean-TRUE','boolean-False'):
  x=o[name];assert x['computed']['status']=='PROJECTED' and x['computed']['semantic_status']=='Validated',(platform,name)
  assert x['native']['state']['ActiveState']=='active'
 assert o['inactive-section']['computed']['unselected']==['other']
 assert o['inactive-section']['computed']['expected_backends']==['test']
 for name in ('ldap-proxy','unknown-provider','scope-ad','scope-ipa'):
  assert o[name]['computed']['semantic_status']=='UnsupportedProvider',(platform,name)
 for name in ('scope-ad','scope-ipa'):
  assert o[name]['native_status'].startswith('NOT_TESTED') and o[name]['functional_auth']=='NOT_TESTED'
  assert o[name]['computed']['scope']['test']['dynamic_possible']
 for name in ('dynamic-scope','trusted-child'):assert o[name]['computed']['semantic_status']=='UnknownSemantics'
 for name in ('enabled-false','auto-enabled-root'):assert o[name]['computed']['semantic_status']=='UnsupportedConfiguration'
 assert o['enabled-false']['native']['state']['ActiveState']=='failed'
 assert o['auto-enabled-root']['native']['state']['ActiveState']=='active'
 for provider in ('ldap','proxy'):
  for offline,account in ((0,0),(0,1),(1,0),(1,1),(2,1),(1,2)):
   r=o[f'relation-{provider}-{offline}-{account}'];valid=account==0 or (offline>0 and account>=offline)
   expected=('Validated' if valid else 'Conflict') if provider=='ldap' else 'UnsupportedProvider'
   assert r['computed']['semantic_status']==expected,(platform,provider,offline,account)
   assert r['computed']['offline']['value']==offline and r['computed']['values']['test']['account']['value']==account
   assert r['config_check']['exit_code']==0
   assert (r['native']['state']['ActiveState']=='active')==(valid or provider=='proxy')
   assert f'offline_credentials_expiration: {offline}' in r['native']['configdb']['stdout']
   assert f'account_cache_expiration: {account}' in r['native']['configdb']['stdout']
   if not valid and provider=='ldap':assert any('Conflicting' in log or 'Invalid argument' in log for log in r['logs'].values())
 for name in ('two-ldap-one-conflict','relation-cache-false'):
  assert o[name]['computed']['semantic_status']=='Conflict' and o[name]['native']['state']['ActiveState']=='failed'
 assert o['relation-cache-false']['computed']['values']['test']['cache']['value'] is False
 assert o['native-defaults']['computed']['offline']['value']==0 and o['native-defaults']['computed']['offline']['origin']=='native-default'
 assert o['boolean-yes']['computed']['semantic_status']=='UnsupportedConfiguration' and o['boolean-yes']['native']['state']['ActiveState']=='failed'
 for kind in ('domains','provider','enabled','same-scope-value'):
  x=o['scope-change-'+kind];assert x['status']=='PROJECTED' and not x['scope_unchanged'] and x['graph']!=x['next_graph']
source=json.loads((HERE/'source-review.json').read_text())
r2=json.loads((HERE.parent/'sssd-research/source-r2.json').read_text())
assert set(source)==platforms
for platform,data in source.items():
 for path,review in data['files'].items():
  if path in r2[platform]['files']:assert review['sha256']==r2[platform]['files'][path]['sha256']
  assert review['excerpts']
for p in HERE.glob('*.py'):ast.parse(p.read_text())
subprocess.run(['bash','-n',str(HERE/'run-native.sh')],check=True)
print('SSSD I2 retained evidence PASS; not native reexecution or completed A/B/C/P')
