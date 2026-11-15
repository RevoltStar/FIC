#!/usr/bin/env python3
"""Production SSH lifecycle on isolated shared root/run; never a permission flag."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import time

spec=importlib.util.spec_from_file_location('native','/usr/local/bin/fic-openssh-harness.py')
h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h);h.guard()
platform=sys.argv[1];alt=platform=='alt-p11';ubuntu=platform.startswith('ubuntu-')
if alt:
    h.MAIN=Path('/etc/openssh/sshd_config');h.ENV=Path('/etc/sysconfig/sshd')
    h.DROP=Path('/etc/openssh/sshd_config.local.d');h.KEY=Path('/etc/openssh/ssh_host_ed25519_key')
unit='sshd.service' if alt else 'ssh.service'
ctl=lambda *a,**kw:h.run(['systemctl',*a],**kw)
# A copied namespace alone is not isolation: refuse all inherited peer links.
assert not any('shared:' in x or 'master:' in x for x in Path('/proc/self/mountinfo').read_text().splitlines())
ctl('mask','--runtime','--now','getty@tty1.service','console-getty.service',check=False)
h.run(['mount','--make-rshared','/']) # Only this guarded disposable container.
h.DROP.mkdir(parents=True,exist_ok=True);Path('/run/fic').mkdir(exist_ok=True);h.run(['ssh-keygen','-A'])
report={'platform':platform,'cases':[],'kernel':os.uname().release,'initial_shared_mountinfo':Path('/proc/self/mountinfo').read_text()}
def save():(h.OUT/'shared-results.json').write_text(json.dumps(report,indent=2))
def residuals():return [x for x in Path('/proc/self/mountinfo').read_text().splitlines() if ' - tmpfs fic-vcsa.' in x]
def record(name,data):
    report['cases'].append({'name':name,'result':data,'local_residuals':residuals()});save()
def request():
    r=h.request();r['policies']={'ssh_use_pam':'yes'};return r
def reference():
    data=h.drive('capture-reference',request());assert data['reference_capture_succeeded'],data
    r=data['reference'];r['glob_dir']=str(h.DROP);return r
ctl('stop',unit,'ssh.socket',check=False)
for p in h.DROP.iterdir():
    if p.is_dir():shutil.rmtree(p)
    else:p.unlink()
(h.DROP/'10-fixture.conf').write_text('LogLevel VERBOSE\n')
h.MAIN.write_text(h.config(extra='MaxAuthTries 3\n'));h.MAIN.chmod(0o600 if alt else 0o644)
h.ENV.write_text(('EXTRAOPTIONS' if alt else 'SSHD_OPTS')+'=\n');h.ENV.chmod(0o644)
shutil.rmtree(h.WORK/'module-state',ignore_errors=True)
if ubuntu:ctl('disable',unit,check=False);ctl('enable','ssh.socket')
else:ctl('enable',unit)
ctl('daemon-reload');ctl('start','ssh.socket' if ubuntu else unit)
# ALT's stock Type=simple start job completes before sshd binds its socket.
deadline=time.monotonic()+10
while True:
    try:h.handshake(2222);break
    except OSError:
        if time.monotonic()>=deadline:raise
        time.sleep(.02)
original=h.MAIN.read_bytes()
r=request();r['operations']=[dict(policy='ssh_use_pam',value='yes')]*2
v=h.drive('module',r);record('first-owned-apply-and-receipt-repeat',v);a,b=v['module'];assert a['applied'] and b['applied'] and not a['main_unchanged']
assert b['main_unchanged'] and b['journal_unchanged'] and b['before_invocation']==b['after_invocation'],v
r=request();r['operations']=[dict(policy='ssh_use_pam',value='yes')]
v=h.drive('module',r);record('owned-repeat-without-process-receipt',v);a=v['module'][0]
assert a['applied'] and a['main_unchanged'] and a['journal_unchanged'] and a['before_invocation']!=a['after_invocation'],v
v=h.drive('adapter-ro-write',reference());record('real-ABCP-listeners-and-RO',v)
assert v['adapter_success'] and v['A']==v['C']==v['P']=='Proven' and v['readinessConfirmed'] and v['write_errno']=='EROFS',v
r=request();r['operations']=[dict(policy='ssh_use_pam',value='yes',rollback=True)]
v=h.drive('module',r);record('active-verified-release',v)
assert v['module'][0]['applied'] and 'RuntimeVerified' in v['module'][0]['release_message'] and h.MAIN.read_bytes()==original and not residuals(),v
r=request();r['operations']=[dict(policy='ssh_max_auth_tries',value='3'),dict(policy='ssh_max_auth_tries',value='4'),dict(policy='ssh_max_auth_tries',value='4'),dict(policy='ssh_max_auth_tries',value='4',rollback=True)]
v=h.drive('module',r);record('foreign-compliant-refresh-repeat-release',v);rows=v['module'];assert all(x['applied'] for x in rows),v
assert not rows[0]['main_unchanged'] and not rows[1]['main_unchanged'] and rows[1]['before_invocation']!=rows[1]['after_invocation'],v
assert rows[2]['main_unchanged'] and rows[2]['journal_unchanged'] and rows[2]['before_invocation']==rows[2]['after_invocation'],v
assert h.MAIN.read_bytes()==original and not residuals(),v
foreign=original.replace(b'UsePAM no',b'UsePAM yes');h.MAIN.write_bytes(foreign)
for fault in ['busy','original-write']:
    h.MAIN.write_bytes(foreign)
    if fault=='original-write':(h.WORK/'mutation.conf').write_bytes(original)
    v=h.drive('adapter-'+fault,reference());record('negative-'+fault,v);assert not v['adapter_success'],v
    if fault=='busy':assert v['status']=='CleanupFailed' and v['primaryStatus']=='Success' and v['readinessConfirmed'],v
    else:assert v['A']==v['C']=='Proven' and v['P']=='NonCompliant',v
    h.drive('cleanup',{'paths':[]});assert not residuals()
h.MAIN.write_bytes(foreign);r=request();r['operations']=[dict(policy='ssh_use_pam',value='yes'),dict(policy='ssh_use_pam',value='yes',rollback=True,offline=True)]
v=h.drive('module',r);record('foreign-compliant-owned-offline-release-validation',v)
assert all(x['applied'] for x in v['module']) and 'ReleasedOffline' in v['module'][1]['release_message'],v
assert h.MAIN.read_bytes()==foreign and not residuals(),v
report['status']='PASS';save();print('PASS shared root/run production SSH lifecycle '+platform)
