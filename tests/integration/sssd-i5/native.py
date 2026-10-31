"""Disposable I5 native transaction/crash fixture; never runs on the host."""
from common import *
import shutil,sys
platform=sys.argv[1]
OWN=DROP/'zzzz-fic.conf'
JOURNAL=Path('/var/lib/fic-i4/journal.json')
def fixture(text):
 return text.replace('[sssd]\n','[sssd]\nuser=_sssd\n') if platform=='alt-p11' else text
def clean_mounts():
 # Explicit fault-fixture teardown only, after recovery observations. Production
 # never unmounts/adopts leftovers after another process has died.
 paths=[]
 for line in Path('/proc/self/mountinfo').read_text().splitlines():
  fields=line.split();sep=fields.index('-');target=fields[4];source=fields[sep+2]
  if source.startswith('fic-vcsa.') or target in ('/etc/sssd','/etc/default/sssd','/etc/sysconfig/sssd'):
   paths.append(target)
 for p in sorted(paths,key=lambda p:p.count('/'),reverse=True):
  assert run(['umount',p])['exit_code']==0,p

def prepared(text=None):
 clean_mounts()
 configure(fixture(base(offline=10,account=0) if text is None else text))
 shutil.rmtree('/var/lib/fic-i4',ignore_errors=True)
 result=observe_start();assert result['state']['ActiveState']=='active',result
 return result

def stop_fixture():
 # Eager native responders can leave their alternative socket units failed.
 # An offline positive needs a fully quiescent topology, not MainPID=0 alone.
 # Explicit fixture preparation only; production never stops/resets units.
 assert ctl('stop','sssd.service')['exit_code']==0
 listing=run(['systemctl','list-unit-files','--no-legend','sssd*.socket'])
 assert listing['exit_code']==0,listing
 names=[line.split()[0] for line in listing['stdout'].splitlines() if line.split() and line.split()[0].endswith('.socket')]
 if names:assert ctl('stop',*names)['exit_code']==0
 # ALT immediately garbage-collects inactive units; resetting every installed
 # name then fails with 'not loaded'. Failed units are retained by systemd.
 failed=ctl('list-units','--all','--state=failed','--plain','--no-legend','sssd*.socket')
 assert failed['exit_code']==0,failed
 failed_names=[line.split()[0] for line in failed['stdout'].splitlines() if line.split() and line.split()[0].endswith('.socket')]
 if failed_names:assert ctl('reset-failed',*failed_names)['exit_code']==0

def probe(operation='apply',param='offline',value=10,action='normal',timeout=60000):
 # Repeated native restarts exercise systemd's stock burst limit; reset only
 # this disposable test counter, without replacing units or production fallback.
 if operation not in ('inspect','resolve') and state()['ActiveState']=='active':
  assert ctl('reset-failed','sssd.service')['exit_code']==0
 args=['/usr/local/bin/sssd-i5-probe',operation,param,str(value),action,str(timeout)]
 # common.run intentionally truncates display output. Structured transaction
 # reports are larger; parse exact stdout, not its diagnostic tail.
 p=subprocess.run(args,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout/1000+40)
 r={'command':args,'exit_code':p.returncode,'stdout':p.stdout,'stderr':p.stderr}
 report['commands'].append(r);save()
 if action.startswith('crash-'):
  assert r['exit_code']==74,r
  return {'process_exit':74,'checkpoint':(OUT/'last-checkpoint').read_text(),'managed_bytes':OWN.read_text() if OWN.exists() else None,'journal':json.loads(JOURNAL.read_text()) if JOURNAL.exists() else None}
 assert r['exit_code']==0,r
 x=json.loads(r['stdout']);assert 'driver_error' not in x,x
 if OWN.exists():
  st=OWN.stat();x['native_witness']={'present':True,'device':st.st_dev,'inode':st.st_ino,'mode':st.st_mode&0o7777,
   'owner':st.st_uid,'group':st.st_gid,'sha256':hashlib.sha256(OWN.read_bytes()).hexdigest()}
 else:x['native_witness']=None
 return x

def case(name,operation='apply',param='offline',value=10,action='normal',success=False,timeout=60000):
 x=probe(operation,param,value,action,timeout);experiment(name,x)
 assert x.get('success',False)==success,(name,x)
 if success:
  assert x['finalized'] and x['durable'] and not x['unresolved'],x
  assert set(x['proofs'].values())=={'Proven'} and x['engine']['attempted'],x
  assert not x['engine']['cleanup_errors'] and not x['engine']['residuals'],x
  assert x['required']==x['confirmed'] and x['required'],x
  assert x['old_invocation']!=x['new_invocation'] and x['configdb_generation'],x
  assert x['parameters'] and all(e['consumer'] and e['process'] and e['source_contract'] and e['generation']==x['configdb_generation'] for e in x['parameters']),x
  assert all(r['status']=='applied' for r in x['records']),x
  latest=max((r['ownership']['current'] for r in x['records']),key=lambda r:r['sequence'])
  assert latest['publication']==x['native_witness'],x
 return x

def gated(name):
 x=case(name+'-sibling-gate',param='cache');assert x['unresolved'] and not x['installed'] and not x['engine']['attempted'],x

def unchanged(before):
 assert MAIN.read_bytes()==before['main']
 assert {p.name:p.read_bytes() for p in DROP.iterdir() if p.name!='zzzz-fic.conf' and not p.name.startswith('.zzzz-fic.conf.tmp.')}==before['foreign']
def foreign():return {'main':MAIN.read_bytes(),'foreign':{p.name:p.read_bytes() for p in DROP.iterdir() if p.name!='zzzz-fic.conf' and not p.name.startswith('.zzzz-fic.conf.tmp.')}}

experiment('inventory',{'platform':platform,'unit':ctl('cat','sssd.service'),'version':run(['sssd','--version']),
 'packages':run(['rpm','-q','sssd','sssd-tools','systemd'] if platform=='alt-p11' else ['dpkg-query','-W','sssd-common','sssd-tools','systemd']),
 'kernel':run(['uname','-r']),'pid1':Path('/proc/1/comm').read_text()})
assert ctl('mask','--runtime','--now','getty@tty1.service','console-getty.service')['exit_code']==0
assert run(['mount','--bind','/etc','/etc'])['exit_code']==0
assert run(['mount','--make-private','/etc'])['exit_code']==0
assert run(['mount','--make-private','/run'])['exit_code']==0
if platform=='alt-p11' and not Path('/etc/sysconfig/sssd').exists():write('/etc/sysconfig/sssd','DEBUG_LOGGER=--logger=files\n')

def apply(name,param='offline',value=10,operation='apply'):
 x=probe(operation,param,value);experiment(name,x);assert x['success'],(name,x)
 assert set(x['proofs'].values())=={'Proven'} and not x['engine']['residuals'],x
 return x

def release(name,param='offline',success=True,offline=False,operation='release',action='normal',timeout=60000):
 x=probe(operation,param,10,action,timeout)
 if success and not offline:x['native_configdb']=run(['ldbsearch','-H','/var/lib/sss/db/config.ldb','-b','cn=config'])
 experiment(name,x)
 assert x['success']==success,(name,x)
 if success:
  assert x['physical_released'] and x['durable'] and x['finalized'] and not x['unresolved'],x
  assert x['offline']==offline and x['offline_verified']==offline and not x['disable_acknowledged'],x
  assert not x['staged_artifacts'] and not x['engine']['residuals'] and not x['engine']['cleanup_errors'],x
  if offline:assert x['status']=='ReleasedOffline' and not x['engine']['attempted'] and x['proofs']['B']!='Proven' and x['proofs']['C']!='Proven',x
  else:assert set(x['proofs'].values())=={'Proven'} and x['old_invocation']!=x['new_invocation'],x
  owner=next(r for r in x['records'] if r['id']==x['mutation'])
  assert owner['status']=='rolled_back' and owner['ownership']['transition']['phase']=='completed',owner
  for r in x['records']:
   if r['status']=='applied':assert r['ownership']['container']['publication']==x['native_witness'],r
 return x

prepared(base(offline=5,account=0));apply('single-apply');before=foreign()
x=release('single-active-last');assert not OWN.exists() and x['managed_bytes'] is None,x
assert x['parameters'] and x['configdb_generation'] and x['native_configdb']['exit_code']==0 and 'offline_credentials_expiration: 5' in x['native_configdb']['stdout'],x
unchanged(before)
x=release('repeat-no-adoption',success=False);assert not x['prepared'] and not OWN.exists(),x

for target in ('offline','cache','account'):
 prepared();apply('three-'+target+'-offline');apply('three-'+target+'-cache','cache');apply('three-'+target+'-account','account',90)
 before=foreign();x=release('three-release-'+target,target);assert len(x['surviving'])==2 and OWN.exists(),x;unchanged(before)
 survivor='cache' if target=='offline' else 'offline'
 apply('post-release-apply-'+target,survivor);apply('post-release-refresh-'+target,survivor,10,'refresh')

prepared();apply('two-offline');apply('two-cache','cache');release('two-release-max','cache');apply('two-surviving-refresh','offline',30,'refresh')
release('two-release-last');assert not OWN.exists()

two=base(offline=10,account=0).replace('domains = test','domains = test, other')+'\n[domain/other]\nid_provider=ldap\nauth_provider=ldap\nldap_uri=ldap://127.0.0.1:9\nldap_search_base=dc=example,dc=test\ncache_credentials=false\naccount_cache_expiration=0\n'
prepared(two);apply('multi-cache','cache');apply('multi-offline');x=release('multi-cache-release','cache');assert len(x['released'])==2,x
prepared();apply('offline-last-base');stop_fixture()
placeholder=ctl('show','sssd-i5-absent.socket','-p','LoadState','-p','ActiveState','-p','ActiveEnterTimestampMonotonic')
assert 'LoadState=not-found' in placeholder['stdout'] and 'ActiveState=inactive' in placeholder['stdout'] and 'ActiveEnterTimestampMonotonic=0' in placeholder['stdout'],placeholder
experiment('empty-absent-socket-placeholder',placeholder)
before=state();x=release('offline-last',offline=True);assert state()['ActiveState']=='inactive' and before['MainPID']=='0',x
prepared();apply('offline-sibling-base');apply('offline-sibling-cache','cache');stop_fixture()
release('offline-survivor',offline=True);assert 'cache_credentials = true' in OWN.read_text()

# A custom lazy socket can target a native responder without TriggeredBy on
# the monitor and without a /var/lib/sss endpoint. Endpoint absence is not enough.
prepared();apply('socket-topology-base');stop_fixture()
lazy=Path('/run/systemd/system/fic-i5-lazy.socket')
write(lazy,'[Unit]\nDescription=I5 stopped admission fixture\n[Socket]\nListenStream=/run/i5-lazy-endpoint\nService=sssd-pam.service\n')
assert ctl('daemon-reload')['exit_code']==0
assert ctl('start','fic-i5-lazy.socket')['exit_code']==0
old=OWN.read_bytes();x=release('active-responder-socket-refused',success=False)
assert not x['prepared'] and not x['physical_released'] and OWN.read_bytes()==old and 'socket unit' in x['diagnostic'],x
assert ctl('stop','fic-i5-lazy.socket')['exit_code']==0
lazy.unlink();assert ctl('daemon-reload')['exit_code']==0

prepared();apply('disable-base');x=release('disable-pending',success=False,operation='disable-release')
assert x['status']=='ReleasedAwaitingDisable' and x['physical_released'] and x['durable'] and x['unresolved'] and not x['finalized'],x
gated('disable-pending');y=probe('inspect');experiment('disable-pending-inspect',y);assert y['inspection']['phase']=='released_awaiting_disable',y

for suffix,text in (
 ('matching','[pam]\noffline_credentials_expiration=10\n'),
 ('conflicting','[pam]\noffline_credentials_expiration=5\n'),
 ('unrelated','[pam]\ndebug_level=0\n'),
 ('inactive-section','[domain/inactive]\nid_provider=ldap\n'),
 ('unknown-key','[pam]\nfuture_foreign_option=some-value\n')):
 prepared();apply('late-'+suffix+'-base');write(DROP/'zzzzz-foreign.conf',text,MAIN.stat().st_mode&0o777);os.chown(DROP/'zzzzz-foreign.conf',0,MAIN.stat().st_gid)
 before=foreign();x=release('late-'+suffix,success=True);assert x['physical_released'],x;unchanged(before)

prepared(base(offline=5,account=10));apply('revealed-relation-base',value=5)
MAIN.write_text(MAIN.read_text().replace('offline_credentials_expiration = 5','offline_credentials_expiration = 30'));before=foreign()
x=release('revealed-relation-conflict',success=False);assert x['physical_released'] and x['durable'] and x['unresolved'] and not x['engine']['attempted'],x;unchanged(before);gated('revealed-relation')
for value in ('true','false'):
 prepared();apply('late-survivor-'+value+'-base');apply('late-survivor-'+value+'-cache','cache')
 late=DROP/'zzzzz-survivor.conf';write(late,'[domain/test]\ncache_credentials='+value+'\n',MAIN.stat().st_mode&0o777);os.chown(late,0,MAIN.stat().st_gid)
 before=foreign();x=release('late-survivor-'+value,success=value=='true');assert x['physical_released'] and 'cache_credentials = true' in OWN.read_text(),x;unchanged(before)
 if value=='false':assert x['unresolved'] and not x['engine']['attempted'],x

prepared(two);apply('scope-changed-base','cache');MAIN.write_text(MAIN.read_text().replace('domains = test, other','domains = test'))
before=foreign();x=release('scope-changed-historical-group','cache');assert len(x['released'])==2 and not OWN.exists(),x;unchanged(before)
prepared();apply('unsupported-provider-base');MAIN.write_text(MAIN.read_text().replace('id_provider = ldap','id_provider = proxy'))
before=foreign();x=release('unsupported-provider-after-owning',success=False)
assert x['physical_released'] and x['unresolved'] and not x['engine']['attempted'],x;unchanged(before)
prepared();write(OWN,'[pam]\noffline_credentials_expiration = 10\n');old=OWN.read_bytes()
x=release('orphan-without-provenance',success=False);assert not x['prepared'] and OWN.read_bytes()==old,x

for change in ('owned-value','owned-inode','missing-file','missing-key','unrecorded-key','sibling-drift'):
 prepared();apply(change+'-base')
 if change=='sibling-drift':apply(change+'-cache','cache')
 if change=='owned-value':OWN.write_text(OWN.read_text().replace('= 10','= 11'))
 elif change=='owned-inode':
  tmp=DROP/'replacement';write(tmp,OWN.read_text(),OWN.stat().st_mode&0o777);os.chown(tmp,0,OWN.stat().st_gid);os.replace(tmp,OWN)
 elif change=='missing-file':OWN.unlink()
 elif change=='missing-key':OWN.write_text('# empty\n')
 elif change=='unrecorded-key':OWN.write_text(OWN.read_text()+'debug_level = 0\n')
 else:OWN.write_text(OWN.read_text().replace('cache_credentials = true','cache_credentials = false'))
 old=OWN.read_bytes() if OWN.exists() else None;x=release(change,success=False)
 assert not x['prepared'] and not x['physical_released'] and (OWN.read_bytes() if OWN.exists() else None)==old,x

for action in ('cas-drift','publication-not-durable','cleanup-fail','persistent-drift','post-i3-owned-touch','restart-timeout','stop-monitor','stop-backend','stop-pam','stale-configdb','finalization-not-installed','journal-indeterminate'):
 prepared();apply('fault-'+action+'-base');apply('fault-'+action+'-cache','cache')
 x=release('fault-'+action,success=False,action=action,timeout=6000 if action in ('restart-timeout','stop-monitor','stop-backend','stop-pam') else 60000)
 assert x['prepared'] and x['unresolved'] and not x['finalized'],x
 if action!='cas-drift':assert x['physical_released'],x
 if action=='cleanup-fail':assert x['engine']['cleanup_errors'] and x['engine']['residuals'],x
 if action=='persistent-drift':assert x['proofs']['A']=='Proven' and x['proofs']['P']=='Drifted',x
 if action=='journal-indeterminate':
  inspected=probe('inspect');experiment('journal-indeterminate-reload',inspected);assert inspected['inspection']['classification']=='NoTransition',inspected
  apply('journal-indeterminate-survivor','cache')
 else:gated('fault-'+action)

prepared();apply('remove-durability-base')
x=release('remove-publication-not-durable',success=False,action='publication-not-durable')
assert x['physical_released'] and not x['durable'] and x['unresolved'] and x['managed_bytes'] is None,x
gated('remove-publication-not-durable')

for action in ('offline-start','offline-start-stop'):
 prepared();apply(action+'-base');stop_fixture()
 x=release(action,success=False,action=action);assert x['physical_released'] and x['durable'] and x['unresolved'] and not x['offline_verified'] and not x['engine']['attempted'],x
 gated(action)

for kind in ('unknown-version','corrupt-journal','legacy-applied','legacy-prepared','staged-artifact'):
 prepared();apply(kind+'-base');old=OWN.read_bytes()
 if kind=='unknown-version':
  doc=json.loads(JOURNAL.read_text());doc['records'][0]['undo']['ownership']['version']=99;JOURNAL.write_text(json.dumps(doc))
 elif kind=='corrupt-journal':JOURNAL.write_text('{corrupt')
 elif kind.startswith('legacy-'):
  doc=json.loads(JOURNAL.read_text());r=doc['records'][0];r['status']='prepared' if kind.endswith('prepared') else 'applied'
  r['resource']='pam/offline_credentials_expiration';r['undo']={'backend':'sssd','action':'remove_sssd_managed_setting','section':'pam','option':'offline_credentials_expiration','applied_value':'10'};JOURNAL.write_text(json.dumps(doc))
 else:write(DROP/'zzzz-fic.conf.fic-removing-orphan','stranded')
 x=probe('release');experiment(kind,x);assert not x['success'] and not x.get('prepared',False) and OWN.read_bytes()==old,x

# Real child termination, followed by fresh journal + physical/mount inspection.
crash_phases=('before-prepared','prepared','mutation-armed','staged-write','partial-staged-write','atomic-published','published','durable-published','before-activation','restart-dispatched','i3-semantics','i3-persistent','runtime-verified','journal-installed','completed')
for phase in crash_phases:
 prepared();apply('crash-'+phase+'-base');apply('crash-'+phase+'-cache','cache')
 dead=probe('release','offline',10,'crash-'+phase);experiment('crash-'+phase,dead)
 x=probe('inspect');experiment('crash-'+phase+'-inspect',x)
 if phase=='before-prepared':assert x['inspection']['classification']=='NoTransition',x
 elif phase in ('journal-installed','completed'):
  assert x['inspection']['classification']=='NoTransition' and any(r['status']=='rolled_back' for r in x['records']),x
  apply('crash-'+phase+'-survivor','cache')
 else:
  gated('crash-'+phase)
  resolved=probe('resolve');experiment('crash-'+phase+'-resolve',resolved)
  assert resolved['inspection']['resolvable']==(phase=='prepared'),resolved
  if phase=='prepared':apply('crash-prepared-resumed','cache')

for phase in ('rename_away','staged_reproved','staged_unlink','removal_directory_fsync','released-offline','released-awaiting-disable'):
 prepared();apply('remove-crash-'+phase+'-base')
 if phase=='released-offline':stop_fixture()
 op='disable-release' if phase=='released-awaiting-disable' else 'release'
 dead=probe(op,'offline',10,'crash-'+phase);experiment('remove-crash-'+phase,dead)
 x=probe('inspect');experiment('remove-crash-'+phase+'-inspect',x);gated('remove-crash-'+phase)
 resolved=probe('resolve');experiment('remove-crash-'+phase+'-resolve',resolved)
 assert not resolved['inspection']['resolvable'],resolved
 if phase in ('rename_away','staged_reproved'):assert x['staged_artifacts'],x
 else:assert x['managed_bytes'] is None,x

experiment('result',{'status':'PASS','crash_phases':list(crash_phases)+['rename_away','staged_reproved','staged_unlink','removal_directory_fsync','released-offline','released-awaiting-disable']})
save();print(json.dumps({'platform':platform,'observations':len(report['experiments']),'result':'PASS'}))
