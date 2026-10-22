"""M1 private-container native prerequisite, not production mask ownership code."""
import os
assert os.environ.get('FIC_FINALIZER_RESEARCH') == '1'
from pathlib import Path
import subprocess
r=Path('/var/lib/m1-mask');r.mkdir(exist_ok=True)
unit=Path('/usr/lib/systemd/system/m1-legacy.service')
unit.write_text('[Service]\nExecStart=/bin/sleep infinity\n[Install]\nWantedBy=multi-user.target\n')
def ctl(*args, check=True):
    return subprocess.run(['systemctl',*args],check=check,text=True,capture_output=True,timeout=15)
ctl('daemon-reload');ctl('enable','--now','m1-legacy.service')
assert ctl('is-active','m1-legacy.service').stdout.strip()=='active'
# Unique operation-owned empty file: identity can be persisted before publishing
# the symlink. Does native systemd recognize this as a persistent mask?
mask=r/'operation-owned-empty-unit';mask.write_bytes(b'');mask.chmod(0o600)
Path('/etc/systemd/system/m1-legacy.service').symlink_to(mask)
ctl('daemon-reload');ctl('stop','m1-legacy.service')
props=ctl('show','m1-legacy.service','-p','LoadState','-p','ActiveState','-p','MainPID','-p','ControlPID').stdout
print(props,end='')
assert 'LoadState=masked\n' in props and 'ActiveState=inactive\n' in props and 'MainPID=0\n' in props
assert ctl('start','m1-legacy.service',check=False).returncode!=0
ctl('daemon-reexec')
assert ctl('start','m1-legacy.service',check=False).returncode!=0
print('PASS: operation-owned empty-file mask recognized; start refused after manager reexec',flush=True)
