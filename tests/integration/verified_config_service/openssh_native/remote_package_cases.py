#!/usr/bin/env python3
"""Actual packages, production daemon/CLI and pre-existing authenticated SSH TCP."""
import hashlib
import json
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path
assert os.environ.get('FIC_PACKAGE_LIFECYCLE_NATIVE')=='1'
assert Path('/.dockerenv').exists() and Path('/proc/1/comm').read_text().strip()=='systemd'
assert os.stat('/proc/self/ns/mnt').st_ino!=int(os.environ['FIC_HOST_MNT_INODE'])
assert [p.name for p in Path('/sys/class/net').iterdir()]==['lo']
platform=sys.argv[1];alt=platform=='alt-p11';ubuntu=platform.startswith('ubuntu-')
main=Path('/etc/openssh/sshd_config' if alt else '/etc/ssh/sshd_config')
env=Path('/etc/sysconfig/sshd' if alt else '/etc/default/ssh')
unit='sshd.service' if alt else 'ssh.service'
key=main.parent/'ssh_host_ed25519_key';out=Path('/var/tmp/fic-package-results');out.mkdir(exist_ok=True)
report={'platform':platform,'events':[]};control='/run/fic-remote-control';cli='/opt/fic/bin/fic-cli'
def save():(out/'ssh-remote-results.json').write_text(json.dumps(report,indent=2))
def run(args,check=True,timeout=300):
    p=subprocess.run(args,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=timeout)
    report['events'].append({'command':args,'exit_code':p.returncode,'output':p.stdout});save()
    print('EXIT',p.returncode,shlex.join(args),flush=True)
    if check:assert p.returncode==0,p.stdout
    return p
ctl=lambda *args,**kw:run(['systemctl',*args],**kw)
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
ssh=['ssh','-F','/dev/null','-S',control,'-o','BatchMode=yes','-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile=/dev/null','-o','ConnectTimeout=5','-p','22','root@127.0.0.1']
def remote(args,timeout=300):
    # An explicit control socket and false ProxyCommand prohibit silently
    # replacing the original TCP connection with a fresh authenticated login.
    p=run(ssh[:-1]+['-o','ProxyCommand=false',ssh[-1],shlex.join(args)],timeout=timeout)
    run(ssh[:-1]+['-O','check',ssh[-1]])
    return p
def policy(*args):return remote([cli,'policy',*args])
def journal():return json.loads(Path('/opt/fic/db/mutation-journal.json').read_text())
def config():return {p.name:sha(p) for p in Path('/opt/fic/config').glob('*') if p.is_file()}
try:
    # Native fixture only: readonly sysfs disables distro udev conditions.
    # Reuse the package gate's udev-control setup, never modify SSH units.
    for u in ('systemd-udevd.service','systemd-udevd-control.socket','systemd-udevd-kernel.socket'):
        directory=Path('/etc/systemd/system')/(u+'.d');directory.mkdir(exist_ok=True)
        (directory/'readonly-test.conf').write_text('[Unit]\nConditionPathIsReadWrite=\n')
    ctl('daemon-reload');ctl('start','systemd-udevd-control.socket','systemd-udevd-kernel.socket','systemd-udevd.service')
    ctl('stop',unit,'ssh.socket',check=False)
    for parent in (main.parent,env.parent):
        run(['mount','--bind',str(parent),str(parent)]);run(['mount','--make-private',str(parent)])
    run(['ssh-keygen','-A']);Path('/run/sshd').mkdir(exist_ok=True)
    main.write_text(f'Port 22\nListenAddress 127.0.0.1\nHostKey {key}\nPermitRootLogin yes\nPubkeyAuthentication yes\nUsePAM no\nMaxAuthTries 6\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n')
    main.chmod(0o600 if alt else 0o644);env.write_text('EXTRAOPTIONS=\n' if alt else 'SSHD_OPTS=\n');env.chmod(0o644)
    (main.parent/('sshd_config.local.d' if alt else 'sshd_config.d')).mkdir(exist_ok=True)
    if alt and Path('/etc/sudoers.d/99-sudopw').exists():Path('/etc/sudoers.d/99-sudopw').chmod(0o400) # native fixture before FIC
    packages=sorted(Path('/var/tmp/fic-packages').glob('*.rpm' if alt else '*.deb'));assert len(packages)==3,packages
    report['packages']={p.name:sha(p) for p in packages}
    run(['rpm','-Uvh',*map(str,packages)] if alt else ['dpkg','-i',*map(str,packages)])
    assert Path('/var/lib/fic-lifecycle/status').read_text()=='INSTALLED\n'
    ctl('is-active','fic.service','fic-device.service')
    fragment=ctl('show',unit,'-p','FragmentPath','--value').stdout.strip();vendor=sha(fragment)
    report['vendor_unit']={'path':fragment,'sha256':vendor,'kill_mode':ctl('show',unit,'-p','KillMode','--value').stdout.strip()}
    ctl('enable','ssh.socket' if ubuntu else unit);ctl('daemon-reload');ctl('start','ssh.socket' if ubuntu else unit)
    root=Path('/root/.ssh');root.mkdir(mode=0o700,exist_ok=True);root.chmod(0o700)
    run(['ssh-keygen','-q','-t','ed25519','-N','','-f','/run/fic-admin-key'])
    (root/'authorized_keys').write_text(Path('/run/fic-admin-key.pub').read_text());(root/'authorized_keys').chmod(0o600)
    # Master connected BEFORE restrictive root policy, stays open for all operations.
    run(ssh[:-1]+['-i','/run/fic-admin-key','-M','-N','-f','-o','ControlPersist=900',ssh[-1]])
    report['tcp_before']={p:Path(p).read_text() for p in ('/proc/net/tcp','/proc/net/tcp6')}
    remote([cli,'status'])
    policy('apply','NET','ssh_use_pam') # default ENABLE; initial stopped-SSH apply intentionally could not activate
    policy('set','NET','ssh_root_login','no');policy('enable','NET','ssh_root_login');policy('apply','NET','ssh_root_login')
    disabled=policy('disable','NET','ssh_root_login')
    assert 'RuntimeVerified' in disabled.stdout and 'awaiting durable DISABLE' not in disabled.stdout
    assert 'PermitRootLogin yes' in main.read_text()
    root_records=[r for r in journal()['records'] if r['policy']['policy']=='ssh_root_login'];assert root_records and all(r['status']=='rolled_back' for r in root_records)
    policy('enable','NET','ssh_max_auth_tries');policy('apply','NET','ssh_max_auth_tries')
    policy('set','NET','ssh_max_auth_tries','2');policy('apply','NET','ssh_max_auth_tries')
    policy('set','NET','ssh_port','2222');policy('enable','NET','ssh_port');policy('apply','NET','ssh_port')
    report['tcp_after_refresh']={p:Path(p).read_text() for p in ('/proc/net/tcp','/proc/net/tcp6')}
    saved=config();report['config_before_uninstall']=saved
    remote([cli,'prepare-uninstall']);remote([cli,'policy','rollback','all'],timeout=600)
    assert config()==saved and '#@FIC_' not in main.read_text()
    records=journal()['records'];assert all(r['status']=='rolled_back' for r in records if r['backend']=='ssh'),records
    report['ssh_release_records']=[r for r in records if r['backend']=='ssh']
    assert sha(fragment)==vendor
    remote(['rpm','-e','fic-cli','fic','fic-dick'] if alt else ['dpkg','--remove','fic-cli','fic','fic-dick'],timeout=600)
    assert config()==saved and Path('/var/lib/fic-lifecycle/status').read_text()=='REMOVED\n'
    remote(['/usr/bin/true'])
    if not alt:
        remote(['dpkg','--purge','fic-cli','fic','fic-dick'],timeout=600)
        assert not Path('/opt/fic/db/mutation-journal.json').exists()
    report['tcp_after_remove']={p:Path(p).read_text() for p in ('/proc/net/tcp','/proc/net/tcp6')}
    report['status']='PASS';save()
finally:
    report['diagnostics']=run(['journalctl','-u','fic.service','-u',unit,'-n','160','--no-pager'],check=False).stdout;save()
