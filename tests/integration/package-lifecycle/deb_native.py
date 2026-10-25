"""Actual FIC DEB lifecycle gate. Requires a disposable systemd PID1 container."""
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
use_upgrades = False

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
    directory=Path('/var/tmp/fic-packages/upgrades' if use_upgrades else '/var/tmp/fic-packages')
    found = list(directory.glob(name+'_*.deb'))
    assert len(found) == 1, found
    return str(found[0])

try:
    # Per-mount read-only flags; do not remount the shared sysfs superblock.
    # Keep the container's cgroup submount writable for its own PID1.
    run(['mount', '--rbind', '/sys', '/sys'])
    run(['mount', '-o', 'remount,bind,ro', '/sys'])
    run(['findmnt', '-n', '-T', '/sys', '-o', 'OPTIONS'])
    assert os.statvfs('/sys').f_flag & os.ST_RDONLY, Path('/proc/self/mountinfo').read_text()
    # No real SSH login/physical-device claims are made by this package gate.
    run(['systemctl', 'stop', 'ssh.service', 'ssh.socket'], success=False)
    pkgs = [package(name) for name in ('fic-dick', 'fic', 'fic-cli')]
    for item in pkgs:
        run(['dpkg-deb', '-f', item, 'Package', 'Version', 'Depends'])
    run(['dpkg','-i',package('fic-dick')],timeout=300)
    run(['dpkg','--remove','fic-dick'],timeout=300)
    assert not Path('/opt/fic/db/mutation-journal.json').exists()
    assert Path('/var/lib/fic-lifecycle/status').read_text()=='REMOVED\n'
    run(['dpkg', '-i', *pkgs], timeout=300)
    run(['systemctl', 'is-active', 'fic.service', 'fic-device.service'])
    assert Path('/var/lib/fic-lifecycle/status').read_text() == 'INSTALLED\n'
    run(['/opt/fic/bin/fic-cli', 'status'])
    # SKIP never overrides exclusion of an actually running daemon.
    override=Path('/etc/fic-uninstall-overload')
    override.write_text('ROLLBACK_TYPE=SKIP\nFIC_REQUIRED_UNINSTALL_STATUS=SKIP\nFIC_REQUIRED_STOP=SKIP\n')
    override.chmod(0o600)
    refused=run(['/opt/fic/bin/fic-package-infrastructure','remove'],success=False)
    assert refused.returncode!=0 and Path('/var/lib/fic-lifecycle/status').read_text()=='INSTALLED\n'
    override.chmod(0o666)
    refused=run(['/opt/fic/bin/fic-package-infrastructure','remove'],success=False)
    assert refused.returncode!=0 and Path('/var/lib/fic-lifecycle/status').read_text()=='INSTALLED\n'
    override.unlink()

    # Exercise a real journal-owned login.defs backend in the container rootfs.
    run(['/opt/fic/bin/fic-cli', 'policy', 'enable', 'IDENTITY_ACCESS', 'password_max_age_days'])
    run(['/opt/fic/bin/fic-cli', 'policy', 'apply', 'IDENTITY_ACCESS', 'password_max_age_days'])
    run(['/opt/fic/bin/fic-cli', 'policy', 'enable', 'IDENTITY_ACCESS', 'password_min_age_days'])
    run(['/opt/fic/bin/fic-cli', 'policy', 'apply', 'IDENTITY_ACCESS', 'password_min_age_days'])
    for policy in ('sudo_disable_scoped_defaults','sudo_exempt_group_disable','sudo_env_reset','sudo_timeout'):
        run(['/opt/fic/bin/fic-cli','policy','enable','DAC',policy])
        run(['/opt/fic/bin/fic-cli','policy','apply','DAC',policy])
    # Actual generated PAM topology and joint password domain ownership.
    # No authentication is attempted; native semantic release must remove
    # these owned profiles without changing their configured ENABLE values.
    for policy in ('enable_authentication_lockout','enable_password_quality','enable_password_history'):
        run(['/opt/fic/bin/fic-cli','policy','enable','IDENTITY_ACCESS',policy])
        run(['/opt/fic/bin/fic-cli','policy','apply','IDENTITY_ACCESS',policy])
    run(['/opt/fic/bin/fic-cli','policy','enable','IDENTITY_ACCESS','password_min_length'])
    run(['/opt/fic/bin/fic-cli','policy','apply','IDENTITY_ACCESS','password_min_length'])
    saved = config_snapshot()
    snapshot("owned-before-upgrade")
    upgrades=list(Path('/var/tmp/fic-packages/upgrades').glob('*.deb'))
    if upgrades:
        active=lambda: {r['id'] for r in json.loads(Path('/opt/fic/db/mutation-journal.json').read_text())['records']
                        if r['status'] in ('prepared','applied','rollback_failed')}
        owned=active()
        assert owned, 'upgrade gate requires real active ownership'
        # Network is disabled at the container boundary. Do not use apt's
        # --no-download: it also prevents copying these local DEB archives.
        run(['apt-get','install','-y',*map(str,sorted(upgrades))],timeout=300)
        assert Path('/var/lib/fic-lifecycle/status').read_text()=='INSTALLED\n'
        assert owned<=active(), 'upgrade performed ownership rollback'
        assert config_snapshot()==saved, 'upgrade changed desired policy config'
        run(['dpkg','--configure','-a'],timeout=300)
        run(['dpkg','-i',*map(str,sorted(upgrades))],timeout=300)
        assert owned<=active() and config_snapshot()==saved

        # Genuine failing configure phases, followed by explicit administrator
        # repair and dpkg recovery. Neither invalid input may admit a daemon.
        for damaged in (Path('/opt/fic/config/GLOBAL.conf'),
                        Path('/opt/fic/db/mutation-journal.json')):
            original=damaged.read_bytes()
            # Enter the actual stopped/configuring phase before fault injection;
            # the earlier Installed preflight intentionally rejects before stop.
            run(['/opt/fic/bin/fic-package-infrastructure','prepare-install'])
            damaged.write_bytes(b'intentionally invalid native upgrade input\n')
            failed=run(['dpkg','-i',*map(str,sorted(upgrades))],success=False,timeout=300)
            assert failed.returncode!=0, 'invalid persistent state accepted by configure'
            assert damaged.read_bytes()==b'intentionally invalid native upgrade input\n'
            assert Path('/var/lib/fic-lifecycle/status').read_text()=='INSTALLING\n'
            assert run(['systemctl','is-active','--quiet','fic.service'],success=False).returncode!=0
            damaged.write_bytes(original)  # explicit test administrator repair
            run(['dpkg','--configure','-a'],timeout=300)
            assert Path('/var/lib/fic-lifecycle/status').read_text()=='INSTALLED\n'
            assert owned<=active() and config_snapshot()==saved
        use_upgrades=True
        pkgs=[package(name) for name in ('fic-dick','fic','fic-cli')]

    # Race through the actual IPC server: apply either completes before the
    # durable prepare acknowledgement or is denied by the uninstall gate.
    applying=subprocess.Popen(['/opt/fic/bin/fic-cli','policy','apply','IDENTITY_ACCESS',
                              'password_max_age_days'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    run(['/opt/fic/bin/fic-cli', 'prepare-uninstall'])
    output=applying.communicate(timeout=120)[0]
    events.append(dict(command=['concurrent','policy apply','prepare-uninstall'],
                       exit_code=applying.returncode,output=output))
    assert applying.returncode==0 or 'процессе удаления' in output,output
    reply = request('apply_all')
    assert reply.get('error_code') == 'UNINSTALL_IN_PROGRESS' and not reply['ok'], reply
    # An independent orphan/staging conflict must block its resource only.
    # The genuine login.defs ownership still releases; retry after an explicit
    # administrator fixture repair cannot rewrite configured ENABLE/values.
    staged = Path('/etc/sssd/conf.d/zzzz-fic.conf.fic-removing-native-test')
    staged.parent.mkdir(parents=True, exist_ok=True)
    staged.write_text('foreign staging object\n')
    staged.chmod(0o600)
    partial = request('rollback_all')
    assert not partial['ok'], partial
    assert any(r.get('policy', '').endswith(':password_max_age_days') and
               r.get('status') == 'success' for r in partial['results']), partial
    assert staged.read_text() == 'foreign staging object\n'
    assert config_snapshot() == saved
    staged.unlink()
    run(['/opt/fic/bin/fic-cli', 'policy', 'rollback', 'all'], timeout=300)
    run(['visudo','-c'])
    assert config_snapshot() == saved, 'rollback altered ENABLE/values'
    snapshot("released-before-remove")
    prelogin=run(['dpkg-query','-W','-f=${Status}','fic-prelogin'],success=False)
    if prelogin.returncode==0 and prelogin.stdout.strip()=='install ok installed':
        # Exercise the actual optional infrastructure ELF while its payload
        # still exists; the later apt remove repeats this idempotently.
        run(['/opt/fic/bin/fic-package-infrastructure','remove'],timeout=300)
        assert Path('/var/lib/fic-lifecycle/status').read_text()=='REMOVED\n'
    run(['apt-get', 'remove', '-y', 'fic-cli', 'fic'], timeout=300)
    assert config_snapshot() == saved, 'remove erased policy config'
    assert Path('/var/lib/fic-lifecycle/status').read_text() == 'REMOVED\n'
    assert Path('/opt/fic/db/mutation-journal.json').exists()
    assert Path('/opt/fic/db/mutation-journal.json.initialized').exists()
    snapshot('removed-with-journal-witness')
    run(['dpkg', '-i', package('fic'), package('fic-cli')], timeout=300)
    assert config_snapshot() == saved, 'reinstall changed saved policy config'
    run(['/opt/fic/bin/fic-cli', 'policy', 'apply', 'IDENTITY_ACCESS', 'password_max_age_days'])
    run(['dpkg', '--remove', 'fic-cli', 'fic'], timeout=300)
    # Actual late postrm purge after the main ELF is already gone.
    assert not Path('/opt/fic/bin/fic').exists()
    run(['dpkg', '--purge', 'fic'])
    assert not Path('/opt/fic/config').exists()
    assert not Path('/opt/fic/db/mutation-journal.json').exists()
    assert not Path('/opt/fic/db/mutation-journal.json.initialized').exists()
    run(['dpkg', '-i', package('fic'), package('fic-cli')], timeout=300)
    assert Path('/var/lib/fic-lifecycle/status').read_text() == 'INSTALLED\n'
    run(['apt-get', 'purge', '-y', 'fic-cli', 'fic'], timeout=300)
    run(['dpkg', '--purge', 'fic-dick', 'fic-cli'])
    # Reinstall the complete real package set after the helper was erased.
    run(['dpkg', '-i', *pkgs], timeout=300)
    # IGNORE_ERROR permits individual reported conflicts, preserving their
    # foreign bytes and the retained journal. It does not fabricate rollback.
    staged.parent.mkdir(parents=True,exist_ok=True)
    staged.write_text('foreign retained by emergency uninstall\n')
    staged.chmod(0o600)
    override=Path('/etc/fic-uninstall-overload')
    override.write_text('ROLLBACK_TYPE=IGNORE_ERROR\n')
    override.chmod(0o600)
    run(['dpkg','--remove','fic-cli','fic'],timeout=300)
    assert staged.read_text()=='foreign retained by emergency uninstall\n'
    assert Path('/var/lib/fic-lifecycle/status').read_text()=='REMOVED\n'
    snapshot('ignore-error-retained-provenance')
    staged.unlink()  # explicit administrator fixture repair before reinstall
    override.unlink()
    run(['dpkg','-i',package('fic'),package('fic-cli')],timeout=300)
    # Real systemd stop failure: best-effort means warn about the failed job,
    # then independently prove that its processes/cgroups are actually empty.
    dropin=Path('/etc/systemd/system/fic.service.d/native-stop-failure.conf')
    dropin.parent.mkdir(parents=True,exist_ok=True)
    dropin.write_text('[Service]\nExecStop=/bin/false\n')
    run(['systemctl','daemon-reload'])
    override=Path('/etc/fic-uninstall-overload')
    override.write_text('FIC_REQUIRED_STOP=FALSE\n')
    override.chmod(0o600)
    run(['dpkg','--remove','fic-cli','fic'],timeout=300)
    assert Path('/var/lib/fic-lifecycle/status').read_text()=='REMOVED\n'
    override.unlink()
    dropin.unlink()
    run(['systemctl','daemon-reload'])
    run(['dpkg','-i',package('fic'),package('fic-cli')],timeout=300)
    run(['systemctl', 'stop', 'fic.service', 'fic-device.service', 'fic-notify.service',
         'fic_get_device_info.service', 'fic_get_device_udev_info.service'])
    binary = Path('/opt/fic/bin/fic')
    binary.chmod(0o640)  # damaged/non-executable main ELF; helper remains usable
    journal = Path('/opt/fic/db/mutation-journal.json')
    journal.write_text('intentionally broken native journal\n')
    before = config_snapshot()
    refused = run(['dpkg', '--remove', 'fic-cli', 'fic'], success=False)
    assert refused.returncode != 0 and binary.exists()
    assert Path('/var/lib/fic-lifecycle/status').read_text() == 'INSTALLED\n'
    override = Path('/etc/fic-uninstall-overload')
    override.write_text('ROLLBACK_TYPE=IGNORE_ERROR\nFIC_REQUIRED_UNINSTALL_STATUS=FALSE\n')
    override.chmod(0o600)
    refused = run(['dpkg', '--remove', 'fic'], success=False)
    assert refused.returncode != 0 and binary.exists(), 'IGNORE_ERROR accepted absent rollback engine'
    override.write_text('ROLLBACK_TYPE=SKIP\nFIC_REQUIRED_UNINSTALL_STATUS=FALSE\nFIC_REQUIRED_STOP=TRUE\n')
    foreign = Path('/etc/pam.d/fic-native-foreign')
    foreign.write_text('account required pam_fic_access.so\n')
    refused = run(['dpkg', '--remove', 'fic'], success=False)
    assert refused.returncode != 0 and binary.exists(), 'SKIP bypassed remaining PAM references'
    assert config_snapshot() == before
    assert journal.read_text() == 'intentionally broken native journal\n'
    foreign.unlink()  # explicit administrator repair, never automatic adoption
    override.write_text('ROLLBACK_TYPE=SKIP\nFIC_REQUIRED_UNINSTALL_STATUS=SKIP\nFIC_REQUIRED_STOP=TRUE\n')
    run(['dpkg', '--remove', 'fic'], timeout=300)
    assert config_snapshot() == before
    assert journal.read_text() == 'intentionally broken native journal\n'
    run(['dpkg', '--purge', 'fic'])
    assert not journal.exists()
    override.unlink()
    run(['dpkg', '--purge', 'fic-dick', 'fic-cli'])

    (results/'result.json').write_text(json.dumps(dict(status='PASS',
        compatible_upgrade_tested=bool(upgrades),
        scope='real FIC dpkg fresh/shared-apply/partial-rollback/remove/reinstall/late-purge/direct-purge/emergency-broken-ELF/PAM-refusal',
        limits=['no physical device mutation', 'no PAM authentication or graphical boot proof']), indent=2))
    print('PASS: actual FIC DEB package lifecycle', flush=True)
except BaseException:
    logs=[log for log in Path('/opt/fic/log').rglob('*') if log.is_file()]
    for log in sorted(logs,key=lambda p:p.stat().st_mtime)[-12:]:
        run(['tail','-n','40',str(log)],success=False)
    run(['ss','-xlpn'],success=False)
    run(['systemctl','show','fic.service','fic-device.service','--no-pager',
         '--property=Id,LoadState,ActiveState,SubState,MainPID,ControlPID,Job'],success=False)
    run(['journalctl', '-u', 'fic.service', '-u', 'fic-device.service', '-n', '150', '--no-pager'], success=False)
    raise
