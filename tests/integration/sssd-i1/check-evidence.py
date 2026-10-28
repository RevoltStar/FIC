#!/usr/bin/env python3
"""Saved I1 evidence/fixture validation only. No Docker or native runtime."""
import ast,hashlib,json,subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
e=json.loads((HERE/'evidence.json').read_text());fixtures=json.loads((HERE/'launch-fixtures.json').read_text())
platforms={'debian-12','debian-13','ubuntu-24.04','ubuntu-26.04','alt-p11'}
assert e['schema']=='sssd-i1-native-v1' and set(e['profiles'])==platforms==set(fixtures)
for p,digest in e['source_sha256'].items():assert hashlib.sha256((ROOT/p).read_bytes()).hexdigest()==digest,p
for p,item in e['profiles'].items():
 assert item['status']=='PASS' and item['activation_status']=='NOT_TESTED' and not item['runtime_receipt']
 o=item['observations']
 for key in ('main-snippets','ordered-duplicates-hidden','optional-environment-absent','absent-main'):
  assert o[key]['status']=='CAPTURED',(p,key)
 assert o['absent-main']['engine_negative_gap'] and '/etc/sssd/sssd.conf' in o['absent-main']['absent']
 for kind in ('matching','conflicting','unrelated'):
  r=o['late-'+kind];assert r['status']=='CAPTURED' and r['apply_conflict'] and r['fic_named_file_observed'] and len(r['later'])==1
 for kind in ('create','delete','inode','bytes','metadata','restore'):
  assert o['race-'+kind]['status']=='InterferenceDetected',(p,kind)
 for key in ('launch-environment-change','launch-dropin-change','launch-unit-source-change'):
  assert o[key]['status']=='InterferenceDetected',(p,key)
 for key in ('absent-all','stopped','unsupported-environment-variable','nested-mount',
             'unsafe-symlink','unsafe-hardlink','unsafe-mode','unsafe-owner','unsafe-directory'):
  assert o[key]['status']!='CAPTURED',(p,key)
 assert o['profile-group-mode']['status']==('CAPTURED' if p in ('debian-13','ubuntu-26.04') else 'UnsupportedConfiguration')
 assert o['native-merge']['state']['ActiveState']=='active'
 assert 'offline_credentials_expiration: 23' in o['native-merge']['configdb']['stdout']
 assert not o['ordered-duplicates-hidden']['apply_conflict']
 for key in ('launch.Type','launch.UnitPath','launch.InvocationID','launch.ExecStartPreEx','launch.EnvironmentFiles'):
  assert key in fixtures[p]
for path in HERE.glob('*.py'):ast.parse(path.read_text())
subprocess.run(['bash','-n',str(HERE/'run-native.sh')],check=True)
print('SSSD I1 saved evidence/fixtures PASS (not native reexecution)')
