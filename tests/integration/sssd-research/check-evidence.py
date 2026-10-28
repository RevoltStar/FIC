#!/usr/bin/env python3
"""Cheap CI guard for research evidence completeness and scope, not a native gate."""
import ast,json,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3];HERE=Path(__file__).resolve().parent
for p in HERE.glob('*.py'):ast.parse(p.read_text(),filename=str(p))
for p in HERE.glob('*.sh'):subprocess.run(['bash','-n',str(p)],check=True)
d=json.loads((ROOT/'docs/sssd-native-research-evidence.json').read_text())
assert set(d['profiles'])=={'debian-12','debian-13','ubuntu-24.04','ubuntu-26.04','alt-p11'}
for profile,v in d['profiles'].items():
 for stage,s in v['stages'].items():
  assert s['collection_complete'] and s['container']['network']=='none'
  assert not s['container']['binds']
  assert s['experiments']
 e=v['stages']['R1']['experiments']
 assert e['stock-active']['restart']['exit_code']==0
 assert e['stock-active']['state']['InvocationID']
 assert e['stock-ro-prepared']['write_attempt']['exit_code']!=0
 assert e['alternate-daemon-input-graph']['configdb']['exit_code']==0
 if profile in ('debian-13','ubuntu-26.04'):
  m=v['stages']['R1_MORE']['experiments']
  assert m['engine-replace-inode']['engine']['result']['status']=='InterferenceDetected'
  assert m['engine-ro-write']['engine']['result']['hook_observations'][0]['errno']==30
  assert m['engine-preopened-write']['engine']['result']['hook_observations'][0]['write_count']==1
  assert m['engine-preopened-write']['persistent_main_sha256']!=m['engine-preopened-write']['engine']['request']['paths'][0]['sha256']
assert d['coverage']['functional_auth']['status']=='NOT_TESTED'
r2=ROOT/'docs/sssd-semantics-research-evidence.json'
s=json.loads(r2.read_text());assert set(s['profiles'])==set(d['profiles'])
for profile,v in s['profiles'].items():
 assert v['functional_password_fixture']['level']=='FUNCTIONAL_AUTH_CONFIRMED'
 assert v['functional_password_fixture']['status']=='PASS'
 assert len(v['matrix'])==6
 for row in v['matrix']:
  assert row['providers']['ldap']['config_check_exit']==0
  assert row['providers']['proxy']['state']['ActiveState']=='active'
 for stage,obs in v['stages'].items():
  assert obs['collection_complete'] and obs['container']['network']=='none' and not obs['container']['binds']
 a=v['stages']['R2_AUTH']['experiments']
 for name in ('online-password','offline-password','aged-expiration-unlimited'):assert json.loads(a[name]['stdout'])['pam_authenticate']==0
 for name in ('offline-cache-disabled-existing-db','aged-expiration-one-day','offline-wrong-password'):assert json.loads(a[name]['stdout'])['pam_authenticate']!=0
assert s['coverage']['AD_IPA_functional']['status']=='NOT_TESTED'
assert s['coverage']['smartcard_passkey']['status']=='NOT_TESTED'
print('SSSD research evidence/syntax guard PASS (not a native runtime rerun)')
