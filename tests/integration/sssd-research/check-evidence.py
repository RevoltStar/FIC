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
print('SSSD research evidence/syntax guard PASS (not a native runtime rerun)')
