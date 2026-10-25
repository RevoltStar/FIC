"""Actual ALT FIC RPM lifecycle gate. Requires a disposable systemd PID1 container."""
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import time

assert os.environ.get('FIC_PACKAGE_LIFECYCLE_NATIVE') == '1'
assert Path('/proc/1/comm').read_text().strip() == 'systemd'
assert os.stat('/proc/self/ns/mnt').st_ino != int(os.environ['FIC_HOST_MNT_INODE'])
results = Path('/var/tmp/fic-package-results')
results.mkdir()
events = []

def run(args, success=True, timeout=180):
    p = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       timeout=timeout, env=dict(os.environ, DEBIAN_FRONTEND='noninteractive'))
    event = dict(command=args, exit_code=p.returncode, output=p.stdout)
    events.append(event)
    (results/'commands.json').write_text(json.dumps(events, indent=2))
    print('EXIT', p.returncode, ' '.join(args), flush=True)
    if success:
        assert p.returncode == 0, p.stdout
    return p

def request(command, **fields):
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as client:
        client.settimeout(120)
        client.connect('/run/fic/fic.sock')
        client.send(json.dumps(dict(api_version=1, command=command, **fields)).encode())
        body = b''
        while True:
            frame = client.recv(1024*1024)
            assert len(frame) >= 16, 'truncated response'
            magic, total, offset, length = struct.unpack('!4I', frame[:16])
            assert magic == 0x00464943 and offset == len(body) and len(frame) == length+16
            assert len(body)+length <= total <= 1024*1024
            body += frame[16:]
            if len(body) == total:
                reply=json.loads(body)
                events.append(dict(ipc_command=command,request_fields=fields,response=reply))
                (results/'commands.json').write_text(json.dumps(events,indent=2))
                return reply

def config_snapshot():
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in Path('/opt/fic/config').glob('*') if p.is_file()}

def snapshot(label):
    files={}
    for root in (Path('/etc/pam.d'),Path('/opt/fic/config')):
        if root.exists():
            for file in root.rglob('*'):
                if file.is_file():
                    files[str(file)]=hashlib.sha256(file.read_bytes()).hexdigest()
    for file in (Path('/opt/fic/db/mutation-journal.json'),
                 Path('/opt/fic/db/mutation-journal.json.initialized'),
                 Path('/opt/fic/lockstatus')):
        files[str(file)]=hashlib.sha256(file.read_bytes()).hexdigest() if file.exists() else None
    state=Path('/var/lib/fic-lifecycle/status')
    events.append(dict(snapshot=label,lifecycle=state.read_text() if state.exists() else None,
                       sha256=files))
    (results/'commands.json').write_text(json.dumps(events,indent=2))


def package(name):
    found = list(Path('/var/tmp/fic-packages').glob(name+'_*.deb'))
    assert len(found) == 1, found
    return str(found[0])

try:
    run(['mount', '--rbind', '/sys', '/sys'])
    run(['mount', '-o', 'remount,bind,ro', '/sys'])
    assert os.statvfs('/sys').f_flag & os.ST_RDONLY
    run(['systemctl','stop','sshd.service','sshd.socket'],success=False)
    # The minimal ALT base ships this distro sudo snippet with mode 0644,
    # which its native visudo rejects. Establish a valid disposable fixture
    # BEFORE FIC is installed; FIC must never repair foreign permissions.
    run(['stat','-c','%a %n','/etc/sudoers.d/99-sudopw'])
    run(['chmod','0400','/etc/sudoers.d/99-sudopw'])
    run(['visudo','-c'])
    packages=[]
    for name in ('fic-dick','fic','fic-cli'):
        found=list(Path('/var/tmp/fic-packages').glob(name+'-0.1.0-*.rpm'))
        assert len(found)==1,found
        packages.append(str(found[0]))
        run(['rpm','-qp','--qf','%{NAME} %{VERSION}-%{RELEASE}\\n',str(found[0])])
    run(['rpm','-Uvh',packages[0]],timeout=300)
    run(['rpm','-e','fic-dick'],timeout=300)
    assert not Path('/opt/fic/db/mutation-journal.json').exists()
    run(['rpm','-Uvh','--replacepkgs',*packages],timeout=300)
    # RPM may return zero after failed %post; readiness requires real proofs.
    assert Path('/var/lib/fic-lifecycle/status').read_text()=='INSTALLED\n'
    run(['systemctl','is-active','fic.service','fic-device.service'])
    run(['/opt/fic/bin/fic-cli','policy','enable','IDENTITY_ACCESS','password_max_age_days'])
    run(['/opt/fic/bin/fic-cli','policy','apply','IDENTITY_ACCESS','password_max_age_days'])
    for policy in ('sudo_disable_scoped_defaults','sudo_exempt_group_disable','sudo_env_reset','sudo_timeout'):
        run(['/opt/fic/bin/fic-cli','policy','enable','DAC',policy])
        run(['/opt/fic/bin/fic-cli','policy','apply','DAC',policy])
    # ALT passwdqc is StaticVerifyOnly and has no topology activation policy.
    for policy in ('enable_authentication_lockout','enable_password_history'):
        run(['/opt/fic/bin/fic-cli','policy','enable','IDENTITY_ACCESS',policy])
        run(['/opt/fic/bin/fic-cli','policy','apply','IDENTITY_ACCESS',policy])
    run(['/opt/fic/bin/fic-cli','policy','enable','IDENTITY_ACCESS','passwdqc_retry_count'])
    run(['/opt/fic/bin/fic-cli','policy','apply','IDENTITY_ACCESS','passwdqc_retry_count'])
    saved=config_snapshot()
    snapshot("owned-before-upgrade")
    upgrades=sorted(Path('/var/tmp/fic-packages/upgrades').glob('*.rpm'))
    if upgrades:
        def active():
            return {r['id'] for r in json.loads(Path('/opt/fic/db/mutation-journal.json').read_text())['records']
                    if r['status'] in ('prepared','applied','rollback_failed')}
        owned=active()
        assert owned
        run(['rpm','-Uvh',*map(str,upgrades)],timeout=300)
        assert Path('/var/lib/fic-lifecycle/status').read_text()=='INSTALLED\n'
        assert owned<=active() and config_snapshot()==saved
        # All subsequent reinstalls use the matching exact-version package set.
        packages=list(map(str,upgrades))
    run(['/opt/fic/bin/fic-cli','prepare-uninstall'])
    assert request('apply_all').get('error_code')=='UNINSTALL_IN_PROGRESS'
    staged=Path('/etc/sssd/conf.d/zzzz-fic.conf.fic-removing-native-test')
    staged.parent.mkdir(parents=True,exist_ok=True)
    staged.write_text('foreign staging object\n')
    staged.chmod(0o600)
    partial=request('rollback_all')
    assert not partial['ok'] and any(r.get('policy','').endswith(':password_max_age_days')
                                   and r.get('status')=='success' for r in partial['results']),partial
    assert staged.read_text()=='foreign staging object\n' and config_snapshot()==saved
    staged.unlink()
    run(['/opt/fic/bin/fic-cli','policy','rollback','all'],timeout=300)
    run(['visudo','-c'])
    snapshot('released-before-remove')
    assert config_snapshot()==saved
    run(['rpm','-e','fic-cli','fic'],timeout=300)
    assert config_snapshot()==saved
    assert Path('/var/lib/fic-lifecycle/status').read_text()=='REMOVED\n'
    assert not Path('/opt/fic/bin/fic').exists()
    snapshot('removed-with-journal-witness')
    run(['rpm','-Uvh','--replacepkgs',*packages],timeout=300)
    assert config_snapshot()==saved
    run(['/opt/fic/bin/fic-cli','policy','apply','IDENTITY_ACCESS','password_max_age_days'])
    run(['rpm','-e','fic-cli','fic'],timeout=300)
    run(['rpm','-e','fic-dick'],timeout=300)
    run(['rpm','-Uvh','--replacepkgs',*packages],timeout=300)
    # RPM erase preserves enabled PAM policy configuration; reinstall applies
    # it again. Establish a real physical detach before breaking the engine.
    # SKIP must never be expected to remove policy-owned PAM references itself.
    run(['/opt/fic/bin/fic-cli','prepare-uninstall'])
    run(['/opt/fic/bin/fic-cli','policy','rollback','all'],timeout=300)
    run(['systemctl','stop','fic.service','fic-device.service','fic-notify.service',
         'fic_get_device_info.service','fic_get_device_udev_info.service'])
    Path('/opt/fic/bin/fic').chmod(0o640)
    journal=Path('/opt/fic/db/mutation-journal.json')
    journal.write_text('intentionally invalid native journal\n')
    assert run(['rpm','-e','fic-cli','fic'],success=False).returncode!=0
    override=Path('/etc/fic-uninstall-overload')
    override.write_text('ROLLBACK_TYPE=SKIP\nFIC_REQUIRED_UNINSTALL_STATUS=SKIP\n')
    override.chmod(0o600)
    foreign=Path('/etc/pam.d/fic-native-foreign')
    foreign.write_text('account required pam_fic_access.so\n')
    assert run(['rpm','-e','fic'],success=False).returncode!=0
    assert Path('/opt/fic/bin/fic').exists() and journal.read_text()=='intentionally invalid native journal\n'
    foreign.unlink()
    run(['rpm','-e','fic'],timeout=300)
    assert not Path('/opt/fic/bin/fic').exists() and journal.read_text()=='intentionally invalid native journal\n'
    run(['rpm','-e','fic-dick'],timeout=300)
    (results/'result.json').write_text(json.dumps(dict(status='PASS',
        compatible_upgrade_tested=bool(upgrades),
        scope='actual ALT FIC RPM install/shared-apply/partial-rollback/erase/reinstall/emergency/config-preservation',
        limits=['no physical-device, real PAM login or graphical boot validation']),indent=2))
except BaseException:
    run(['systemctl','show','fic.service','fic-device.service','--no-pager',
         '--property=Id,LoadState,ActiveState,SubState,MainPID,ControlPID,Job'],success=False)
    run(['journalctl','-u','fic.service','-u','fic-device.service','-n','150','--no-pager'],success=False)
    raise
