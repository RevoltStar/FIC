#!/usr/bin/env python3
"""Current-source I5 retained gates; no privileged operations in CTest."""
import ast,gzip,hashlib,importlib.util,json,subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
def sha(b):return hashlib.sha256(b).hexdigest()
spec=importlib.util.spec_from_file_location('i5_manifest',HERE/'source-manifest.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
e=json.loads((HERE/'evidence.json').read_text())
assert e['schema']=='sssd-i5-native-v1' and e['base']=='be53994aca09959965aa7e13ad328989147fe265'
assert e['verified_release'] and not e['policy_integration'] and not e['production_disable_acknowledgement']
assert e['source_sha256']==m.manifest(),'current native sources changed; rerun I5 matrix'
assert set(e['profiles'])=={'debian-12','debian-13','ubuntu-24.04','ubuntu-26.04','alt-p11'}
positives=('single-active-last','three-release-offline','three-release-cache','three-release-account',
 'two-release-max','two-release-last','multi-cache-release','offline-last','offline-survivor',
 'late-matching','late-conflicting','late-unrelated','late-inactive-section','late-unknown-key','late-survivor-true','scope-changed-historical-group')
faults=('cas-drift','publication-not-durable','cleanup-fail','persistent-drift','post-i3-owned-touch','restart-timeout','stop-monitor','stop-backend','stop-pam',
 'stale-configdb','finalization-not-installed','journal-indeterminate')
crashes=('before-prepared','prepared','mutation-armed','staged-write','partial-staged-write','atomic-published','published',
 'durable-published','before-activation','restart-dispatched','i3-semantics','i3-persistent','runtime-verified','journal-installed',
 'completed','rename_away','staged_reproved','staged_unlink','removal_directory_fsync','released-offline','released-awaiting-disable')
for platform,data in e['profiles'].items():
 compressed=(ROOT/data['report']).read_bytes();raw=gzip.decompress(compressed)
 assert sha(compressed)==data['report_sha256'] and sha(raw)==data['raw_sha256']
 o=json.loads(raw)['experiments'];assert data['status']=='PASS' and data['exit_code']==0 and len(o)==data['observations']
 assert o['result']['status']=='PASS' and tuple(o['result']['crash_phases'])==crashes and tuple(data['crash_phases'])==crashes
 assert o['inventory']['platform']==platform
 for name in positives:
  x=o[name];assert x['success'] and x['physical_released'] and x['durable'] and x['finalized'] and not x['unresolved'],(platform,name)
  assert not x['disable_acknowledged'] and not x['staged_artifacts'] and not x['engine']['residuals'] and not x['engine']['cleanup_errors']
  if name.startswith('offline-'):
   assert x['offline'] and x['offline_verified'] and not x['engine']['attempted'] and x['proofs']['B']==x['proofs']['C']=='NotProven'
  else:
   assert set(x['proofs'].values())=={'Proven'} and x['engine']['attempted'] and x['old_invocation']!=x['new_invocation']
   assert x['parameters'] and x['configdb_generation'] and x['native_configdb']['exit_code']==0
  released=next(r for r in x['records'] if r['id']==x['mutation'])
  assert released['status']=='rolled_back' and released['ownership']['version']==2 and released['ownership']['transition']['phase']=='completed'
  assert released['ownership']['current']==released['ownership']['transition']['previous']
  for r in x['records']:
   if r['status']=='applied':assert r['ownership']['container']['publication']==x['native_witness']
 assert 'LoadState=not-found' in o['empty-absent-socket-placeholder']['stdout']
 assert o['single-active-last']['managed_bytes'] is None and 'offline_credentials_expiration: 5' in o['single-active-last']['native_configdb']['stdout']
 assert len(o['multi-cache-release']['released'])==2
 for target in ('offline','cache','account'):
  for op in ('apply','refresh'):assert o['post-release-'+op+'-'+target]['success']
 x=o['active-responder-socket-refused'];assert not x['prepared'] and not x['physical_released'] and 'socket unit' in x['diagnostic']
 x=o['disable-pending'];assert x['status']=='ReleasedAwaitingDisable' and x['physical_released'] and x['durable'] and x['unresolved'] and not x['success'] and not x['finalized']
 assert o['disable-pending-sibling-gate']['unresolved'] and o['disable-pending-inspect']['inspection']['phase']=='released_awaiting_disable'
 for name in ('repeat-no-adoption','orphan-without-provenance','owned-value','owned-inode','missing-file','missing-key','unrecorded-key','sibling-drift'):
  x=o[name];assert not x['prepared'] and not x['physical_released'] and not x['success'],(platform,name)
 x=o['unsupported-provider-after-owning'];assert x['physical_released'] and x['unresolved'] and not x['engine']['attempted']
 x=o['late-survivor-false'];assert x['physical_released'] and x['unresolved'] and not x['engine']['attempted']
 x=o['revealed-relation-conflict'];assert x['physical_released'] and x['durable'] and x['unresolved'] and not x['engine']['attempted']
 for name in faults:
  x=o['fault-'+name];assert not x['success'] and x['prepared'] and x['unresolved'] and not x['finalized'],(platform,name)
  if name!='cas-drift':assert x['physical_released']
  if name!='journal-indeterminate':assert o['fault-'+name+'-sibling-gate']['unresolved']
 assert o['fault-cas-drift']['cas_refused'] and not o['fault-cas-drift']['physical_released']
 assert not o['fault-publication-not-durable']['durable']
 assert o['fault-cleanup-fail']['engine']['residuals'] and o['fault-cleanup-fail']['engine']['cleanup_errors']
 assert o['fault-persistent-drift']['proofs']['A']=='Proven' and o['fault-persistent-drift']['proofs']['P']=='Drifted'
 assert o['fault-restart-timeout']['engine']['attempted'] and o['fault-restart-timeout']['runtime_possible'] and o['fault-restart-timeout']['proofs']['A']!='Proven'
 assert set(o['fault-post-i3-owned-touch']['proofs'].values())=={'Proven'}
 assert o['fault-stale-configdb']['fixture_db_change']['exit_code']==0 and o['fault-stale-configdb']['proofs']['A']!='Proven'
 assert o['journal-indeterminate-reload']['inspection']['classification']=='NoTransition' and o['journal-indeterminate-survivor']['success']
 x=o['remove-publication-not-durable'];assert x['physical_released'] and not x['durable'] and x['unresolved'] and x['managed_bytes'] is None
 for name in ('offline-start','offline-start-stop'):
  x=o[name];assert x['physical_released'] and x['durable'] and x['unresolved'] and not x['offline_verified'] and not x['engine']['attempted']
 for phase in crashes:
  prefix='remove-crash-' if phase in crashes[15:] else 'crash-'
  x=o[prefix+phase];assert x['process_exit']==74 and x['checkpoint']==phase
  inspected=o[prefix+phase+'-inspect']
  if phase in ('before-prepared','journal-installed','completed'):assert inspected['inspection']['classification']=='NoTransition'
  else:
   assert o[prefix+phase+'-sibling-gate']['unresolved']
   assert o[prefix+phase+'-resolve']['inspection']['resolvable']==(phase=='prepared')
   pending=[r for r in inspected['records'] if r['status']=='prepared'];assert len(pending)==1
   assert pending[0]['ownership']['current']==pending[0]['ownership']['transition']['previous']
  if phase in ('rename_away','staged_reproved','staged-write','partial-staged-write'):assert inspected['staged_artifacts']
 for name in ('unknown-version','corrupt-journal','legacy-applied','legacy-prepared','staged-artifact'):
  assert not o[name]['success'] and not o[name].get('prepared',False)
# Preserve the failed exploratory observation instead of hiding it behind a
# later PASS. Its cause/source generation is deliberately not overclaimed.
diagnostic=json.loads((HERE/'diagnostics/ubuntu2604-unattributed-mount-event.json').read_text())
assert diagnostic['classification']=='UNATTRIBUTED_MOUNT_INTERFERENCE' and diagnostic['source_became_stale_during_run']
compressed=(ROOT/diagnostic['report']).read_bytes();raw=gzip.decompress(compressed)
assert sha(compressed)==diagnostic['report_sha256'] and sha(raw)==diagnostic['raw_sha256']
x=json.loads(raw)['experiments']['remove-crash-staged_reproved-base']
assert not x['success'] and not x['finalized'] and x['unresolved'] and set(x['proofs'].values())=={'Proven'}
assert x['engine']['primary']=='InterferenceDetected' and x['engine']['status']=='InterferenceDetected'
assert diagnostic['outcome']['diagnostic']=='mount namespace event before commit'
for p in HERE.glob('*.py'):ast.parse(p.read_text())
subprocess.run(['bash','-n',str(HERE/'run-native.sh')],check=True)
print('I5 current-source five-platform release/offline/crash gates PASS; retained evidence only, no containers started')
