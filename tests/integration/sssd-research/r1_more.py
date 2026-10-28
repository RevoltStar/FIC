"""Supplemental admission/launch fixtures. Explicitly NOT stock-unit proofs."""
from common import *
import sys
report.update(stage='R1_MORE',platform=sys.argv[1])
configure();experiment('stock-baseline',observe_start())
env=Path('/etc/sysconfig/sssd') if Path('/etc/altlinux-release').exists() else Path('/etc/default/sssd')
experiment('optional-environment-file',{'path':str(env),'exists':env.exists(),'engine':generic()})
if not env.exists():write(env,'# Explicit controlled fixture for absent optional environment file\n',0o644)
experiment('explicit-environment-target',{'engine':generic(),'file':run(['stat','-c','%n %u %g %a',str(env)])})
if sys.argv[1] in ('debian-13','ubuntu-26.04'):
 for action in ('replace-inode','new-snippet','environment-change','ro-write','preopened-write'):
  configure();experiment('engine-'+action+'-baseline',observe_start())
  # Use native prepared ownership/mode; temporary private boundary is fixture only.
  assert run(['mount','--bind',str(MAIN.parent),str(MAIN.parent)])['exit_code']==0
  assert run(['mount','--make-private',str(MAIN.parent)])['exit_code']==0
  try:
   result=generic(action=action)
   experiment('engine-'+action,{'fixture':'existing engine test checkpoint + stock unit','engine':result,'state':state(),
    'persistent_main_sha256':hashlib.sha256(MAIN.read_bytes()).hexdigest(),
    'persistent_snippets':sorted(p.name for p in DROP.iterdir()),'configdb':configdb()})
  finally:assert run(['umount',str(MAIN.parent)])['exit_code']==0
# Source checks vs later read: block a supplemental ExecStartPre on a FIFO.
# This is a native monitor with an explicitly modified launch contract.
ctl('stop','sssd.service');fifo=Path('/run/sssd-input-barrier');os.mkfifo(fifo)
override=Path('/run/systemd/system/sssd.service.d/research-barrier.conf')
write(override,'[Service]\nExecStartPre=/bin/sh -c "read value < /run/sssd-input-barrier"\n',0o644)
ctl('daemon-reload');ctl('start','--no-block','sssd.service')
deadline=time.monotonic()+10
while time.monotonic()<deadline:
 s=state()
 if s.get('ActiveState')=='activating' and s.get('SubState')=='start-pre':break
 time.sleep(.02)
else:raise RuntimeError('native pre-start barrier not reached')
pre=check_config();write(DROP/'zzzzz-race.conf','[pam]\noffline_credentials_expiration=71\n')
experiment('activating-input-race',{'fixture':'supplemental FIFO ExecStartPre, stock unit file unchanged',
 'state':s,'preflight_before_mutation':pre,'engine':generic(),'configdb_before':configdb()})
with fifo.open('w') as f:f.write('continue\n')
experiment('barrier-released',{'job_completion':ctl('start','sssd.service',timeout=40),'state':state(),'configdb':configdb()})
ctl('stop','sssd.service');override.unlink();ctl('daemon-reload')
# Metadata observations; no claim that this is a copied generic snapshot.
configure();run(['setfattr','-n','user.fic-research','-v','fixture',str(MAIN)])
run(['setfacl','-m','u:65534:r',str(MAIN)])
experiment('acl-xattr',{'xattrs':run(['getfattr','-d','-m','-',str(MAIN)]),
 'acl':run(['getfacl','-p',str(MAIN)]),'check':check_config(),'runtime':observe_start(),'engine':generic()})
report['collection_complete']=True;save()
