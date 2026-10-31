#!/usr/bin/env python3
"""Retained native I4 contracts only; ordinary CTest never starts containers."""
import ast,gzip,hashlib,importlib.util,json,subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
def sha(data):return hashlib.sha256(data).hexdigest()
spec=importlib.util.spec_from_file_location('i4_manifest',HERE/'source-manifest.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
e=json.loads((HERE/'evidence.json').read_text())
assert e['schema']=='sssd-i4-native-v1' and e['base']=='2e6b72ae16236a9d871f59cb4e3e845cbc275d73'
assert not e['policy_integration'] and not e['verified_release']
assert e['source_sha256']==module.manifest(),'native sources changed; rerun the matrix'
assert set(e['profiles'])=={'debian-12','debian-13','ubuntu-24.04','ubuntu-26.04','alt-p11'}
crashes=('before-prepared','prepared','mutation-armed','partial-staged-write','staged-write','atomic-published',
 'published','durable-published','before-activation','restart-dispatched','i3-semantics','before-cleanup',
 'i3-persistent','after-activation','runtime-verified','before-finalization','journal-installed')
positives=('first-matching','first-differing','same-value','refresh-up','refresh-down','refresh-same',
 'readonly-template','missing-main','siblings-offline','siblings-cache','siblings-account','siblings-refresh','multi-offline','multi-cache',
 'multi-account','multi-refresh','relation-equality','relation-unbounded-account','relation-default-account',
 'relation-zero-zero','crash-prepared-after-resolution')
refusals=('relation-conflict','relation-conflict-cache-false','relation-zero-nonzero','relation-multi-conflict',
 'account-default-offline-conflict','unsupported-proxy','unsupported-ad','unsupported-ipa','unsupported-unknown',
 'selected-disabled-root','owned-drift','sibling-drift','unrecorded-key','partial-sibling-record','legacy-staging-artifact','stale-inode','scope-change','provider-change','orphan',
 'untrusted-parent','untrusted-file','late-unrelated','late-matching','late-refresh','missing-owned',
 'missing-conf-d','missing-environment','stopped-service')
for platform,data in e['profiles'].items():
 compressed=(ROOT/data['report']).read_bytes();assert sha(compressed)==data['report_sha256']
 raw=gzip.decompress(compressed);assert sha(raw)==data['raw_sha256']
 report=json.loads(raw);o=report['experiments']
 assert data['status']=='PASS' and data['exit_code']==0 and len(o)==data['observations']
 assert tuple(o['result']['crash_phases'])==crashes and tuple(data['crash_phases'])==crashes
 assert o['result']['status']=='PASS' and o['inventory']['platform']==platform
 for name in positives:
  x=o[name];assert x['success'] and x['finalized'] and x['durable'] and not x['unresolved'],(platform,name)
  assert set(x['proofs'].values())=={'Proven'} and x['engine']['attempted'] and x['engine']['primary']=='Success'
  assert not x['engine']['cleanup_errors'] and not x['engine']['residuals'] and x['journal_health']=='Healthy'
  assert x['required']==x['confirmed'] and x['required'] and x['old_invocation']!=x['new_invocation']
  for a in x['required']:
   found=[p for p in x['parameters'] if p['section']==a['section'] and p['key']==a['key']]
   assert found and all(p['process'] and p['consumer'] and p['source_contract'] and p['generation']==x['configdb_generation'] for p in found)
   value=True if a['key']=='cache_credentials' else int(a['value'])
   assert all(p['value']['value']==value for p in found),(platform,name,a)
  assert all(r['status']=='applied' for r in x['records'])
  latest=max((r['ownership']['current'] for r in x['records']),key=lambda r:r['sequence'])
  assert latest['publication']==x['native_witness']
  assert latest['publication']['sha256']==sha(x['managed_bytes'].encode()) and latest['publication']['inode']>0
  owned=[a for r in x['records'] for a in r['ownership']['current']['assignments']]
  assert len({(a['section'],a['key']) for a in owned})==len(owned)
 for name in refusals:
  x=o[name];assert not x['success'] and not x['prepared'] and not x['installed'] and not x['engine']['attempted'],(platform,name)
 for name in ('missing-journal','corrupt-journal','unknown-schema'):
  assert not o[name]['success'] and o[name]['initialization_error'],(platform,name)
 for name in ('legacy-applied','legacy-prepared'):
  x=o[name];assert not x['success'] and x['unresolved'] and x['raw_journal']['records'][0]['undo']['action']=='remove_sssd_managed_setting'
 assert len(o['first-matching']['records'])==1 and o['first-matching']['managed_bytes']
 original=o['first-matching']['mutation']
 for name in ('same-value','refresh-up','refresh-down','refresh-same'):
  assert o[name]['mutation']==original and len(o[name]['records'])==1
 for name in ('same-value','refresh-same'):assert o[name]['same_value'] and not o[name]['installed']
 assert len(o['siblings-refresh']['records'])==3
 for name in ('multi-cache','multi-account','multi-refresh'):
  assert {a['section'] for a in o[name]['required']}=={'domain/test','domain/other'}
 for name in ('cas-drift','publication-not-durable','hidden-source-fd','persistent-drift','timeout-runtime','post-i3-owned-touch','finalization-not-installed','journal-indeterminate','cleanup-fail'):
  x=o[name];assert not x['success'] and not x['finalized'] and x['unresolved'],(platform,name)
  if name!='journal-indeterminate':
   assert o[name+'-sibling-gate']['unresolved'] and not o[name+'-sibling-gate']['installed']
 assert o['cas-drift']['cas_refused'] and not o['cas-drift']['installed']
 assert o['publication-not-durable']['installed'] and not o['publication-not-durable']['durable']
 for name in ('hidden-source-fd','persistent-drift'):assert o[name]['proofs']['P']!='Proven'
 assert o['hidden-source-fd']['hidden_write']==1
 x=o['post-i3-owned-touch'];assert set(x['proofs'].values())=={'Proven'} and not x['confirmed'] and x['status']=='Unresolved'
 x=o['timeout-runtime'];assert x['engine']['attempted'] and x['runtime_possible'] and x['proofs']['A']!='Proven'
 x=o['finalization-not-installed'];assert set(x['proofs'].values())=={'Proven'} and x['status']=='FinalizationFailed'
 assert o['finalization-not-installed-inspection']['inspection']['classification']=='RuntimeUnknown'
 x=o['journal-indeterminate'];assert x['journal_health']=='Indeterminate' and x['status']=='FinalizationFailed'
 assert o['journal-indeterminate-inspection']['inspection']['classification']=='NoTransition'
 x=o['cleanup-fail'];assert x['engine']['residuals'] and x['activation_status']=='CleanupFailed'
 assert o['cleanup-fail-inspection']['inspection']['classification']=='ResidualMounts'
 for phase in crashes:
  x=o['crash-'+phase];assert x['process_exit']==74 and x['checkpoint']==phase
  inspected=o['crash-'+phase+'-inspection'];state=inspected['inspection']['classification']
  if phase in ('before-prepared','journal-installed'):
   assert state=='NoTransition' and inspected['records'][0]['status']=='applied'
  else:
   own=inspected['records'][0]['ownership'];assert inspected['records'][0]['status']=='prepared'
   assert own['current']['assignments'][0]['value']=='10' and own['transition']['target'][0]['value']=='30'
   assert o['crash-'+phase+'-sibling-gate']['unresolved']
   if phase=='prepared':
    assert state=='NoEffectPrepared' and inspected['inspection']['resolvable']
    assert o['crash-prepared-resolved']['records'][0]['ownership']['current']['assignments'][0]['value']=='10'
   else:assert not o['crash-'+phase+'-resolution-refused']['inspection']['resolvable']
  if phase in ('partial-staged-write','staged-write'):assert inspected['staged_artifacts'] and state=='ForeignDrift'
  if phase=='partial-staged-write':assert all(a['sha256']!=inspected['records'][0]['ownership']['transition']['target_sha256'] for a in inspected['staged_artifacts'])
  if phase=='atomic-published':assert state=='TargetBytesUnattributed' and inspected['inspection']['target_bytes_match'] and not inspected['inspection']['target_matches']
  if phase=='published':assert state=='TargetImage' and not inspected['inspection']['publication_durable']
  if phase=='durable-published':assert state=='DurableTarget'
  if phase in ('restart-dispatched','i3-semantics','before-cleanup'):assert state=='ResidualMounts'
  if phase in ('before-activation','i3-persistent','after-activation','runtime-verified','before-finalization'):assert state=='RuntimeUnknown'
 assert not o['unsafe-recovery-parent-inspection']['inspection']['resolvable']
 assert o['unsafe-recovery-parent-resolution']['records'][0]['status']=='prepared'
 assert not o['fresh-prepared-resolved']['records'] and o['fresh-prepared-resolved']['managed_bytes'] is None
for path in HERE.glob('*.py'):ast.parse(path.read_text())
subprocess.run(['bash','-n',str(HERE/'run-native.sh')],check=True)
print('SSSD I4 retained five-platform source-bound apply/REFRESH/crash contracts PASS; no native reexecution')
