"""Narrow I2 regression: SSSD remains strict; no new shared support."""
from common import *
import sys
platform=sys.argv[1]
assert not any('shared:' in row or 'master:' in row for row in Path('/proc/self/mountinfo').read_text().splitlines())
assert ctl('mask','--runtime','--now','getty@tty1.service','console-getty.service')['exit_code']==0
assert run(['mount','--bind','/etc','/etc'])['exit_code']==0
assert run(['mount','--make-private','/etc'])['exit_code']==0
assert run(['mount','--make-private','/run'])['exit_code']==0
configure(base(offline=1,account=2))
write(DROP/'10-input.conf','[pam]\ndebug_level=9\n')
start=observe_start();experiment('private-start',start)
assert start['state']['ActiveState']=='active',start

def case(name,action='positive',success=False):
 before=state()
 r=run(['/usr/local/bin/sssd-i3-probe',action,'60000'],timeout=100)
 assert r['exit_code']==0,r
 x=json.loads(r['stdout']);x['native_after']=state();experiment(name,x)
 assert x['success']==success,x
 assert not x.get('engine',{}).get('residual_mounts'),x
 if success:
  assert set(x['proofs'].values())=={'Proven'} and x['engine']['attempted'] and x['engine']['readiness'],x
  assert x['old_invocation']!=x['new_invocation'] and x['new_invocation'],x
  assert x['processes'] and all(p['initialized'] for p in x['processes']),x
 else:
  assert not x.get('engine',{}).get('attempted',False),x
  assert x['native_after']['InvocationID']==before['InvocationID'],x
 return x
case('private-positive',success=True)
case('private-readonly-write','readonly-write',True)
assert run(['mount','--make-shared','/etc'])['exit_code']==0
case('shared-refused')
assert run(['mount','--bind','/etc','/etc'])['exit_code']==0
assert run(['mount','--make-slave','/etc'])['exit_code']==0
assert run(['mount','--make-shared','/etc'])['exit_code']==0
case('shared-slave-refused')
assert run(['mount','--make-private','/etc'])['exit_code']==0
assert run(['umount','/etc'])['exit_code']==0
assert run(['mount','--make-private','/etc'])['exit_code']==0
case('private-after-refusals',success=True)
assert run(['umount','/etc'])['exit_code']==0
experiment('result',{'status':'PASS','scope':'I2 SSSD strict propagation boundary and private A/B/C/P; no full matrix'})
