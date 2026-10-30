#!/usr/bin/env python3
"""Saved I1 evidence/fixture validation only. No Docker or native runtime."""
import ast,hashlib,json,subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
e=json.loads((HERE/'evidence.json').read_text());fixtures=json.loads((HERE/'launch-fixtures.json').read_text())
platforms={'debian-12','debian-13','ubuntu-24.04','ubuntu-26.04','alt-p11'}
assert e['schema']=='sssd-i1-native-v1' and set(e['profiles'])==platforms==set(fixtures)
# Historical runtime evidence binds to its accepted implementation, not future
# adapters. Current-source/runtime regression binding belongs to the I3 gate.
accepted='807538d89643be0ec2d63f5b0b9de95661610892'
for p,digest in e['source_sha256'].items():
 source=subprocess.run(['git','-c','safe.directory='+str(ROOT),'-C',str(ROOT),'show',f'{accepted}:{p}'],check=True,stdout=subprocess.PIPE).stdout
 assert hashlib.sha256(source).hexdigest()==digest,p
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
 for kind in ('control','unit','env-bytes','env-inode','env-create','dropin'):
  r=o['admission-'+kind];assert 'checkpoint' in r,(p,kind)
  if kind=='control':assert r['status']=='CAPTURED' and not r.get('injected'),(p,kind)
  else:
   assert r['injected'],(p,kind)
   if kind=='dropin' and r['status']=='UnsupportedConfiguration':
    assert r['diagnostic']=='SSSD: unapproved nonempty drop-in directory: /etc/systemd/system/sssd.service.d',(p,kind)
   else:assert r['status']=='InterferenceDetected',(p,kind)
   env=json.loads(r['checkpoint']['environment'])
   if kind=='env-create':assert not env['present']
   elif kind.startswith('env-'):assert env['present'] and env['digest']
 mount=o['nested-mount'];assert mount['status']=='UnsupportedConfiguration' and mount['diagnostic']=='nested mount in controlled tree',p
 m=mount['fixture'];assert m['mount']!=m['parent_mount'] and m['uid']==m['gid']==0 and int(m['mode'],8)&0o7777==0o700 and m['entries']==[],p
 assert mount['mount_command']['exit_code']==0
 if p=='alt-p11':
  for kind in ('correct','missing','root','unknown'):
   for topology in ('services','sockets'):
    r=o['alt-identity-'+kind+'-'+topology];assert r['status']==('CAPTURED' if kind=='correct' else 'UnsupportedConfiguration'),(kind,topology)
  for last in ('root','_sssd'):
   r=o['alt-identity-effective-'+last];assert r['status']==('CAPTURED' if last=='_sssd' else 'UnsupportedConfiguration')
  r=o['alt-identity-effective-_sssd'];assert r['projection']['sssd']['user']=={'value':'_sssd','source':'/etc/sssd/conf.d/99-user.conf'}
  for kind in ('correct','missing','root'):
   r=o['alt-native-identity-'+kind];assert r['monitor_after']['ActiveState']=='active'
   fields=dict(line.split('=',1) for line in r['responder']['stdout'].splitlines() if '=' in line)
   assert fields['User']=='_sssd' and fields['ExecMainStatus']==('0' if kind=='correct' else '3')
   assert fields['ActiveState']==('active' if kind=='correct' else 'failed')
  assert 'user: _sssd' in o['alt-native-identity-correct']['monitor_start']['configdb']['stdout']
  assert o['alt-native-identity-unknown']['state']['ActiveState']=='failed'
review=e['alt_identity_source_review']['files']
r1=json.loads((HERE.parent/'sssd-research/source-r1.json').read_text())['alt-p11']
assert review['src/monitor/monitor.c']['sha256']==r1['files']['src/monitor/monitor.c']['sha256']
assert 'user = _sssd' in review['sssd-default.conf']['text']
for path in HERE.glob('*.py'):ast.parse(path.read_text())
subprocess.run(['bash','-n',str(HERE/'run-native.sh')],check=True)
print('SSSD I1 saved evidence/fixtures PASS (not native reexecution)')
