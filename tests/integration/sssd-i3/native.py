"""I3 disposable native fixture. Production adapter performs no fixture writes."""
from common import *
import sys
platform=sys.argv[1]
def fixture(text):
 return text.replace('[sssd]\n','[sssd]\nuser=_sssd\n') if platform=='alt-p11' else text
def probe(action='positive',timeout=60000):
 r=run(['/usr/local/bin/sssd-i3-probe',action,str(timeout)],timeout=timeout/1000+35)
 assert r['exit_code']==0,r
 return json.loads(r['stdout'])
experiment('inventory',{'platform':platform,'version':run(['sssd','--version']),
 'packages':run(['rpm','-q','--qf','%{NAME} %{VERSION}-%{RELEASE}\n','sssd','sssd-tools','systemd'] if platform=='alt-p11' else ['dpkg-query','-W','-f','${binary:Package} ${Version}\n','sssd-common','sssd-tools','systemd']),
 'unit':ctl('cat','sssd.service'),'os_release':Path('/etc/os-release').read_text(),'kernel':run(['uname','-r'])})
# Unrelated container getty restarts publish /run/credentials mounts on systemd259.
# Quiesce fixture-only console services; never change native SSSD units.
assert ctl('mask','--runtime','--now','getty@tty1.service','console-getty.service')['exit_code']==0
# Pre-provisioned PRIVATE boundaries are test deployment preparation, not adapter actions.
assert run(['mount','--bind','/etc','/etc'])['exit_code']==0
assert run(['mount','--make-private','/etc'])['exit_code']==0
assert run(['mount','--make-private','/run'])['exit_code']==0
configure(fixture(base(offline=1,account=2)))
write(DROP/'10-input.conf','[pam]\ndebug_level=9\n')
start=observe_start();experiment('prepared-native-start',start);assert start['state']['ActiveState']=='active',start
def prepared(text=None):
 configure(fixture(base(offline=1,account=2) if text is None else text))
 write(DROP/'10-input.conf','[pam]\ndebug_level=9\n')
 result=observe_start();assert result['state']['ActiveState']=='active',result
 return result

def case(name,action='positive',success=False,timeout=60000):
 x=probe(action,timeout);x['native_after']=state();experiment(name,x)
 assert x['success']==success,(name,x)
 if success:
  assert set(x['proofs'].values())=={'Proven'} and x['engine']['attempted'] and x['engine']['readiness'],x
  assert x['old_invocation']!=x['new_invocation'] and x['new_invocation'],x
  assert x['processes'] and x['parameters'] and all(p['initialized'] for p in x['processes']),x
 assert not x.get('engine',{}).get('residual_mounts') or name=='cleanup-fail',x
 return x
if platform=='alt-p11':
 env=Path('/etc/sysconfig/sssd')
 if not env.exists():
  case('stock-absent-environment')
  # Explicit administrator-supplied native launch configuration is the supported
  # positive fixture. Absence remains an independently tested refusal; the
  # production adapter never fabricates this file.
  write(env,'DEBUG_LOGGER=--logger=files\n',0o600)
  experiment('explicit-environment-fixture',{'path':str(env),'content':env.read_text(),'stock_absent':True})
case('positive',success=True)
case('readonly-write','readonly-write',True)
case('bad-expectation','bad-expectation')
if platform in ('debian-13','ubuntu-26.04'):
 import struct
 runtime=Path('/var/lib/sss/pipes/private');old_mode=runtime.stat().st_mode&0o777
 runtime.chmod(0o777);case('bus-unsafe-parent');runtime.chmod(old_mode)
 acl=struct.pack('<I',2)+b''.join(struct.pack('<HHI',tag,permissions,who) for tag,permissions,who in [(1,7,0xffffffff),(2,7,123456),(4,0,0xffffffff),(16,7,0xffffffff),(32,0,0xffffffff)])
 os.setxattr(runtime,'system.posix_acl_access',acl);case('bus-foreign-acl');os.removexattr(runtime,'system.posix_acl_access');runtime.chmod(old_mode)

# Parent snapshot also protects these negative input slots.
prepared();text=MAIN.read_text();MAIN.unlink();write(DROP/'10-input.conf',text);assert ctl('restart','sssd.service')['exit_code']==0
case('missing-main',success=True)
prepared();(DROP/'10-input.conf').unlink();DROP.rmdir()
case('missing-conf-d',success=True)
prepared();env=Path('/etc/sysconfig/sssd' if platform=='alt-p11' else '/etc/default/sssd');env_bytes=env.read_bytes();env_mode=env.stat().st_mode&0o777;env.unlink()
case('missing-environment')
write(env,env_bytes.decode(),env_mode)
prepared(base(offline=1,account=2,services='nss'))
case('lazy-pam-unsupported')
case('backend-only','account-only',True)
prepared(base(offline=0,account=0,cache='false'))
case('cache-disabled',success=True)
text=base(offline=1,account=2).replace('domains = test','domains = test, other')+'\n[domain/other]'+base(offline=1,account=2).split('[domain/test]')[1]
prepared(text);case('two-ldap',success=True)
for name,text in [('relation-conflict',base(offline=2,account=1)),('unknown-provider',base(provider='proxy'))]:
 prepared();write(MAIN,fixture(text));case(name)
prepared();write('/etc/sssd/unexpected-xattr','test')
assert run(['python3','-c',"import os;os.setxattr('/etc/sssd/unexpected-xattr','user.i3',b'blocked')"])['exit_code']==0
case('xattr-refused');Path('/etc/sssd/unexpected-xattr').unlink()
prepared();ctl('stop','sssd.service');case('stopped')
for action in ('unit-before','unit-after','snippet-inode','source-fd','persistent-drift','mount-change','stop-monitor','stop-pam','stop-backend','stale-configdb','stop-pam-after','environment-replace','negative-create'):
 prepared();unit=Path('/usr/lib/systemd/system/sssd.service' if platform in ('debian-13','ubuntu-26.04','alt-p11') else '/lib/systemd/system/sssd.service');original=unit.read_bytes()
 x=case(action,action,timeout=15000 if (action.startswith('stop-') or action=='stale-configdb') else 60000)
 if action.startswith('unit-'):unit.write_bytes(original);ctl('daemon-reload')
 if action=='mount-change':assert run(['umount','/run/i3-mount'])['exit_code']==0
 if action in ('stop-monitor','stop-pam','stop-backend','stale-configdb'):assert x['runtime_effect_possible'] and x['proofs']['C']!='Proven',x
 if action in ('source-fd','snippet-inode','persistent-drift'):assert x['proofs']['P']=='Drifted',x
 if action in ('environment-replace','negative-create'):assert x['proofs']['P']=='Drifted' and x['proofs']['C']=='Proven',x
 if action=='stop-pam-after':assert x['status']=='RuntimeEffectUnknown' and x['proofs']['P']=='Proven' and x['proofs']['C']=='NotProven',x
 if action=='persistent-drift':assert x['proofs']['C']=='Proven' and x['status']=='RuntimeActivatedButPersistentUnproven',x
prepared()
assert run(['mount','--make-shared','/etc'])['exit_code']==0
case('shared-parent')
# The same mount both receives from a master and has an outward peer group.
assert run(['mount','--bind','/etc','/etc'])['exit_code']==0
assert run(['mount','--make-slave','/etc'])['exit_code']==0
assert run(['mount','--make-shared','/etc'])['exit_code']==0
case('shared-slave-parent')
assert run(['mount','--make-private','/etc'])['exit_code']==0
assert run(['umount','/etc'])['exit_code']==0
assert run(['mount','--make-private','/etc'])['exit_code']==0
# Reuse the R2 fixture unchanged. Every native SSSD restart is followed by the
# real I3 adapter; subsequent synthetic PAM actions are validation only.
if Path('/usr/sbin/slapd').exists():
 import common
 original_start=common.observe_start;original_base=common.base
 activation_count=[0]
 def ldap_start():
  start=original_start();assert start['state']['ActiveState']=='active',start
  activation_count[0]+=1
  case('ldap-activation-'+str(activation_count[0]),success=True)
  return start
 common.observe_start=ldap_start
 common.base=lambda *args,**kwargs:fixture(original_base(*args,**kwargs))
 exec(compile(Path('/usr/local/bin/r2_auth.py').read_text(),'r2_auth.py','exec'),{'__name__':'__sssd_i3_fixture__'})
 common.observe_start=original_start;common.base=original_base
 o=report['experiments']
 for name in ('online-password','offline-password','aged-expiration-unlimited'):
  assert o[name]['exit_code']==0,(name,o[name])
 assert o['cached-auth-while-ldap-online']['old_password_auth']['exit_code']==0
 for name in ('offline-wrong-password','offline-cache-disabled-existing-db','aged-expiration-one-day'):
  assert o[name]['exit_code']!=0,(name,o[name])
 experiment('ldap-functional-result',{'status':'PASS','adapter_activations':activation_count[0],'synthetic_user_only':True})
else:experiment('ldap-functional-result',{'status':'NOT_TESTED','reason':'fixture tools absent; use test-only I3 image'})
prepared();x=case('cleanup-fail','cleanup-fail');assert x['status']=='CleanupFailed' and x['proofs']['C']=='Proven' and x['proofs']['P']!='Proven' and x['engine']['residual_mounts'],x
experiment('result',{'status':'PASS','scope':'I3 adapter only; no policy SUCCESS/ownership/journal proof'})
