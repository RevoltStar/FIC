"""Disposable I4 native transaction/crash fixture; never runs on the host."""
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

def probe(operation='apply',param='offline',value=10,action='normal',timeout=60000):
 # Repeated native restarts exercise systemd's stock burst limit; reset only
 # this disposable test counter, without replacing units or production fallback.
 if operation not in ('inspect','resolve') and state()['ActiveState']=='active':
  assert ctl('reset-failed','sssd.service')['exit_code']==0
 args=['/usr/local/bin/sssd-i4-probe',operation,param,str(value),action,str(timeout)]
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
prepared();before=foreign();a=case('first-matching',success=True);unchanged(before)
assert 'offline_credentials_expiration = 10' in a['managed_bytes'] and len(a['records'])==1,a
b=case('same-value',success=True);assert b['same_value'] and not b['installed'] and b['mutation']==a['mutation'],b
c=case('refresh-up','refresh',value=30,success=True);assert c['mutation']==a['mutation'] and len(c['records'])==1,c
c=case('refresh-down','refresh',value=10,success=True)
c=case('refresh-same','refresh',value=10,success=True);assert c['same_value'] and not c['installed'],c
unchanged(before)
prepared(base(offline=5,account=0));before=foreign();case('first-differing',success=True);unchanged(before)

prepared();case('siblings-offline',success=True);case('siblings-cache',param='cache',success=True);case('siblings-account',param='account',value=90,success=True)
before=foreign();siblings=OWN.read_text();x=case('siblings-refresh','refresh',value=30,success=True);unchanged(before)
assert len(x['records'])==3 and 'cache_credentials = true' in OWN.read_text() and 'account_cache_expiration = 90' in OWN.read_text(),x
prepared();mode=MAIN.stat().st_mode&0o777;MAIN.chmod(mode&~0o200)
x=case('readonly-template',success=True);assert OWN.stat().st_mode&0o777==(0o640 if mode&0o40 else 0o600),x
prepared();os.replace(MAIN,DROP/'10-full.conf');x=case('missing-main',success=True);assert not MAIN.exists(),x
# Canonical full selected LDAP scope, including single-domain relation conflict.
two=base(offline=10,account=0).replace('domains = test','domains = test, other')+'\n[domain/other]\nid_provider=ldap\nauth_provider=ldap\nldap_uri=ldap://127.0.0.1:9\nldap_search_base=dc=example,dc=test\ncache_credentials=false\naccount_cache_expiration=0\n'
prepared(two);case('multi-offline',success=True);x=case('multi-cache',param='cache',success=True);assert len(x['required'])==2,x
x=case('multi-account',param='account',value=90,success=True);assert len(x['required'])==2,x
case('multi-refresh','refresh',param='account',value=60,success=True)
# Read-only semantics must consider foreign/default values, even cache=false.
for name,text,value in (
 ('relation-equality',base(offline=1,account=10),10),
 ('relation-unbounded-account',base(offline=1,account=0),30),
 ('relation-default-account',base(offline=1,account=0).replace('account_cache_expiration = 0\n',''),30),
 ('relation-zero-zero',base(offline=0,account=0),0)):
 prepared(text);case(name,value=value,success=True)
for name,text,value in (
 ('relation-conflict',base(offline=1,account=10),30),
 ('relation-conflict-cache-false',base(offline=1,account=10,cache='false'),30),
 ('relation-zero-nonzero',base(offline=1,account=10),0),
 ('relation-multi-conflict',two.replace('account_cache_expiration=0','account_cache_expiration=20'),30)):
 prepared(text);before=foreign();x=case(name,value=value);assert not x['prepared'] and 'I2' in x['diagnostic'] and not OWN.exists(),x;unchanged(before)
prepared(base(offline=10,account=0).replace('offline_credentials_expiration = 10\n',''));case('account-default-offline-conflict',param='account',value=10)
# Complete target set is generated, not supplied by a caller. No arbitrary raw key API.
for provider in ('proxy','ad','ipa','unknown'):
 prepared();MAIN.write_text(MAIN.read_text().replace('id_provider = ldap','id_provider = '+provider));before=foreign()
 x=case('unsupported-'+provider,param='cache');assert not x['prepared'] and not OWN.exists(),x;unchanged(before)
for setting in ('subdomain_inherit = cache_credentials\n','subdomains_provider = ldap\n','[domain/test/child]\nid_provider=ldap\n'):
 prepared();MAIN.write_text(MAIN.read_text()+'\n'+setting);before=foreign();x=case('unsupported-topology-'+str(len(report['experiments'])),param='cache');assert not x['prepared'],x;unchanged(before)
prepared(two);MAIN.write_text(MAIN.read_text()+'enabled=false\n');x=case('selected-disabled-root',param='cache');assert not x['prepared'],x
# Existing ownership/scope/physical state cannot be silently repaired.
for action in ('owned-drift','sibling-drift','unrecorded-key','stale-inode','scope-change','provider-change'):
 prepared();case(action+'-base',success=True)
 if action=='sibling-drift':case(action+'-cache',param='cache',success=True)
 if action in ('owned-drift','sibling-drift'):
  OWN.write_text(OWN.read_text().replace('= 10','= 11') if action=='owned-drift' else OWN.read_text().replace('cache_credentials = true','cache_credentials = false'))
 elif action=='unrecorded-key':OWN.write_text(OWN.read_text()+'debug_level = 7\n')
 elif action=='stale-inode':
  st=OWN.stat();tmp=OWN.with_suffix('.replace');tmp.write_bytes(OWN.read_bytes());tmp.chmod(st.st_mode&0o777);os.chown(tmp,st.st_uid,st.st_gid);os.replace(tmp,OWN)
 elif action=='scope-change':MAIN.write_text(MAIN.read_text()+'\n[domain/inactive]\nid_provider=ldap\n')
 else:MAIN.write_text(MAIN.read_text().replace('id_provider = ldap','id_provider = proxy'))
 before=foreign();old=OWN.read_bytes();x=case(action,'refresh',value=30)
 assert not x['prepared'] and OWN.read_bytes()==old,x;unchanged(before)
# A structurally healthy journal is not enough: all sibling target keys
# must match the whole canonical policy scope, not just the requested policy.
prepared(two);case('partial-sibling-base',param='cache',success=True)
doc=json.loads(JOURNAL.read_text());own=doc['records'][0]['undo']['ownership'];keep=own['current']['assignments'][0]
OWN.write_text(f"[{keep['section']}]\n{keep['key']} = {keep['value']}\n\n");digest=hashlib.sha256(OWN.read_bytes()).hexdigest()
own['current']['assignments']=[keep];own['current']['publication']['sha256']=digest
own['transition']['target']=[keep];own['transition']['target_sha256']=digest;own['transition']['publication']['sha256']=digest
JOURNAL.write_text(json.dumps(doc));old=OWN.read_bytes()
x=case('partial-sibling-record');assert not x['prepared'] and x['journal_health']=='Healthy' and 'target set' in x['diagnostic'] and OWN.read_bytes()==old,x
prepared();stage=DROP/'zzzz-fic.conf.fic-removing-12345-0';write(stage,'[pam]\noffline_credentials_expiration = 10\n',MAIN.stat().st_mode&0o777);os.chown(stage,0,MAIN.stat().st_gid)
x=case('legacy-staging-artifact');assert not x['prepared'] and 'staging artifact' in x['diagnostic'] and stage.exists() and not OWN.exists(),x
# Orphans, witness loss, corrupt payload, legacy records, metadata and later inputs.
prepared();write(OWN,'[pam]\noffline_credentials_expiration = 10\n');old=OWN.read_bytes();x=case('orphan');assert x['status']=='OwnershipConflict' and not x['prepared'] and OWN.read_bytes()==old,x
for name in ('missing-journal','corrupt-journal','unknown-schema','legacy-applied','legacy-prepared'):
 prepared();case(name+'-base',success=True);old=OWN.read_bytes()
 if name=='missing-journal':JOURNAL.unlink()
 elif name=='corrupt-journal':JOURNAL.write_text('{broken')
 else:
  doc=json.loads(JOURNAL.read_text());rec=doc['records'][0]
  if name=='unknown-schema':rec['undo']['ownership']['transition']['version']=999
  else:
   rec['resource']='pam/offline_credentials_expiration';rec['undo']={'action':'remove_sssd_managed_setting','backend':'sssd','section':'pam','option':'offline_credentials_expiration','applied_value':'10'}
   if name=='legacy-prepared':rec['status']='prepared'
  JOURNAL.write_text(json.dumps(doc))
 x=case(name,'refresh',value=30);assert OWN.read_bytes()==old,x
 if name.startswith('legacy'):assert x['unresolved'] and x['raw_journal']['records'][0]['undo']['action']=='remove_sssd_managed_setting',x
for name in ('untrusted-parent','untrusted-file','late-unrelated','late-matching','missing-conf-d','missing-environment'):
 prepared()
 if name=='untrusted-parent':DROP.chmod(0o777)
 elif name=='untrusted-file':write(OWN,'[pam]\noffline_credentials_expiration=10\n',0o666)
 elif name.startswith('late-'):write(DROP/'zzzzz-foreign.conf','[pam]\n'+('offline_credentials_expiration=10\n' if name=='late-matching' else 'debug_level=1\n'))
 elif name=='missing-conf-d':DROP.rmdir()
 else:
  env=Path('/etc/sysconfig/sssd' if platform=='alt-p11' else '/etc/default/sssd');backup=env.read_bytes();mode=env.stat().st_mode&0o777;env.unlink()
 x=case(name);assert not x['prepared'] and not x['engine']['attempted'],x
 if name=='untrusted-parent':DROP.chmod(0o755)
 if name=='missing-environment':write(env,backup.decode(),mode)
prepared();case('late-refresh-base',success=True);write(DROP/'zzzzz-late.conf','[pam]\ndebug_level=1\n');old=OWN.read_bytes()
x=case('late-refresh','refresh',value=30);assert not x['prepared'] and OWN.read_bytes()==old,x
prepared();case('missing-owned-base',success=True);OWN.unlink();x=case('missing-owned','refresh',value=30);assert not x['prepared'] and not OWN.exists(),x
prepared();assert ctl('stop','sssd.service')['exit_code']==0
x=case('stopped-service');assert not x['prepared'] and not x['engine']['attempted'] and not OWN.exists() and state()['ActiveState']!='active',x
# Faults retain durable intent and exact previous/target projections.
for name,action,timeout in (
 ('cas-drift','cas-drift',60000),('publication-not-durable','publication-not-durable',60000),
 ('hidden-source-fd','source-fd',60000),('persistent-drift','persistent-drift',60000),
 ('timeout-runtime','stop-monitor',15000),('post-i3-owned-touch','post-i3-owned-touch',60000),('finalization-not-installed','finalization-not-installed',60000),
 ('journal-indeterminate','journal-indeterminate',60000)):
 prepared();case(name+'-base',success=True);before=foreign()
 x=case(name,'refresh',value=30,action=action,timeout=timeout);assert x['unresolved'] and not x['finalized'],x
 if name=='cas-drift':assert x['cas_refused'] and not x['installed'],x
 if name=='publication-not-durable':assert x['installed'] and not x['durable'],x
 if name in ('hidden-source-fd','persistent-drift'):assert x['proofs']['P']!='Proven' and not x['finalized'],x
 if name=='timeout-runtime':assert x['engine']['attempted'] and x['runtime_possible'],x
 if name=='finalization-not-installed':assert set(x['proofs'].values())=={'Proven'} and x['status']=='FinalizationFailed',x
 if name=='journal-indeterminate':assert x['journal_health']=='Indeterminate' and set(x['proofs'].values())=={'Proven'},x
 if name not in ('hidden-source-fd','persistent-drift'):unchanged(before)
 inspection=probe('inspect');experiment(name+'-inspection',inspection)
 if name=='journal-indeterminate':
  # The completed document was installed. A NEW witness-aware load now proves
  # its durability; this is not promotion of Prepared by matching target bytes.
  assert inspection['inspection']['classification']=='NoTransition' and inspection['records'][0]['status']=='applied',inspection
 else:gated(name)
prepared();case('unsafe-recovery-parent-base',success=True);x=probe('refresh','offline',30,'crash-prepared');experiment('unsafe-recovery-parent-crash',x)
DROP.chmod(0o777);x=probe('inspect');experiment('unsafe-recovery-parent-inspection',x);assert not x['inspection']['resolvable'],x
x=probe('resolve');experiment('unsafe-recovery-parent-resolution',x);assert x['records'][0]['status']=='prepared' and not x['inspection']['resolvable'],x
DROP.chmod(0o755)
# Real process termination at each requested durable/effect boundary.
crashes=('before-prepared','prepared','mutation-armed','partial-staged-write','staged-write','atomic-published','published','durable-published',
 'before-activation','restart-dispatched','i3-semantics','before-cleanup','i3-persistent','after-activation','runtime-verified','before-finalization','journal-installed')
for phase in crashes:
 prepared();case('crash-'+phase+'-base',success=True);before=foreign()
 x=probe('refresh','offline',30,'crash-'+phase);experiment('crash-'+phase,x);assert x['checkpoint']==phase,x
 observed=probe('inspect');experiment('crash-'+phase+'-inspection',observed);unchanged(before)
 classification=observed['inspection']['classification']
 if phase in ('before-prepared','journal-installed'):
  assert classification=='NoTransition',observed
  assert observed['records'][0]['status']=='applied',observed
  assert observed['records'][0]['ownership']['current']['assignments'][0]['value']==('10' if phase=='before-prepared' else '30'),observed
 else:
  assert observed['records'][0]['status']=='prepared',observed
  own=observed['records'][0]['ownership'];assert own['current']['assignments'][0]['value']=='10' and own['transition']['target'][0]['value']=='30',observed
  gated('crash-'+phase)
  if phase=='prepared':
   assert classification=='NoEffectPrepared' and observed['inspection']['resolvable'],observed
   resolved=probe('resolve');experiment('crash-prepared-resolved',resolved);assert resolved['records'][0]['status']=='applied' and resolved['records'][0]['ownership']['current']['assignments'][0]['value']=='10',resolved
   case('crash-prepared-after-resolution',param='cache',success=True)
  else:
   attempted=probe('resolve');experiment('crash-'+phase+'-resolution-refused',attempted)
   assert attempted['records'][0]['status']=='prepared' and not attempted['inspection']['resolvable'],attempted
prepared();x=probe('apply','offline',10,'crash-prepared');experiment('fresh-prepared-crash',x)
x=probe('resolve');experiment('fresh-prepared-resolved',x);assert not x['records'] and x['managed_bytes'] is None,x
# Successful native runtime but failed cleanup retains residual evidence; last
# scenario so no fixture reset could accidentally hide an unresolved mount.
prepared();case('cleanup-fail-base',success=True);x=case('cleanup-fail','refresh',value=30,action='cleanup-fail')
assert x['engine']['residuals'] and x['activation_status']=='CleanupFailed' and x['proofs']['A']==x['proofs']['B']==x['proofs']['C']=='Proven',x
y=probe('inspect');experiment('cleanup-fail-inspection',y);assert y['inspection']['classification']=='ResidualMounts',y;gated('cleanup-fail')
experiment('result',{'status':'PASS','scope':'I4 backend only; I5/I6 and policy SUCCESS not claimed','crash_phases':list(crashes)})
