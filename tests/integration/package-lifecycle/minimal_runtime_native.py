"""Final real DEBs: install from Depends in a separate minimal PID1 runtime."""
import atexit
import hashlib
import json
import os
from pathlib import Path
import subprocess
import socket
import struct
import sys
import shutil

assert os.environ.get('FIC_PACKAGE_LIFECYCLE_NATIVE')=='1'
assert Path('/proc/1/comm').read_text().strip()=='systemd'
assert os.stat('/proc/self/ns/mnt').st_ino!=int(os.environ['FIC_HOST_MNT_INODE'])
out=Path('/var/tmp/fic-package-results');out.mkdir()
events=[]
negative_mode=sys.argv[1:]==['--optional-ownership']
assert not sys.argv[1:] or negative_mode
if negative_mode:assert Path('/usr/local/bin/optional-owner-fixture').is_file()
def diagnostics():
    data=[]
    for args in (['systemctl','show','fic.service','fic-device.service','systemd-udevd.service',
                  '-p','Id','-p','ActiveState','-p','SubState','-p','Result','-p','ConditionResult'],
                 ['journalctl','-u','fic.service','-u','fic-device.service','-u','systemd-udevd.service',
                  '-n','120','--no-pager']):
        p=subprocess.run(args,text=True,capture_output=True,timeout=20)
        data.append(dict(command=args,exit_code=p.returncode,output=p.stdout+p.stderr))
    (out/'diagnostics.json').write_text(json.dumps(data,indent=2))
atexit.register(diagnostics)
def run(args,success=True):
    p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=300,
                     env=dict(os.environ,DEBIAN_FRONTEND='noninteractive'))
    events.append(dict(command=args,exit_code=p.returncode,output=p.stdout))
    (out/'commands.json').write_text(json.dumps(events,indent=2))
    print('EXIT',p.returncode,' '.join(args),flush=True)
    if success:assert p.returncode==0,p.stdout
    return p
def request(command):
    with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as c:
        c.settimeout(120);c.connect('/run/fic/fic.sock')
        c.send(json.dumps(dict(command=command,api_version=1)).encode());body=b''
        while True:
            frame=c.recv(1024*1024);assert len(frame)>=16
            magic,total,offset,length=struct.unpack('!4I',frame[:16])
            assert magic==0x00464943 and offset==len(body) and len(frame)==16+length
            assert len(body)+length<=total<=1024*1024
            body+=frame[16:]
            if len(body)==total:
                r=json.loads(body);events.append(dict(ipc_command=command,response=r))
                (out/'commands.json').write_text(json.dumps(events,indent=2));return r
def active():
    return [r for r in json.loads(Path('/opt/fic/db/mutation-journal.json').read_text())['records']
            if r['status'] in ('prepared','applied','rollback_failed')]
def config():
    return {str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in Path('/opt/fic/config').glob('*') if p.is_file()}
def no_optional():
    for package in ('sudo','openssh-server','procps'):
        assert run(['dpkg-query','-W','-f=${Status}',package],False).stdout.strip()!='install ok installed',package
    for binary in ('sudo','visudo','sshd','sysctl'):
        assert shutil.which(binary) is None,binary
def assert_empty_report(r):
    assert r['ok'],r
    for prefix in ('NET:SshEdit:','DAC:SudoEdit:','SYSCTL:'):
        rows=[row for row in r['results'] if row.get('policy','').startswith(prefix)]
        assert rows and all(row['status']=='NOTHING_TO_RELEASE' for row in rows),rows
# The entrypoint establishes readonly sysfs BEFORE PID1/udev, not just now.
assert os.statvfs('/sys').f_flag & os.ST_RDONLY
assert os.statvfs('/proc/sys').f_flag & os.ST_RDONLY
run(['systemctl','is-active','systemd-udevd.service'])
assert run(['systemctl','is-enabled','systemd-udev-trigger.service'],False).stdout.strip()=='masked'
for package in ('cmake','make','gcc','g++','qt6-base-dev','qtbase5-dev','libssl-dev',
                'libsystemd-dev','libglib2.0-dev','libpam0g-dev','libsqlite3-dev',
                'nlohmann-json3-dev','dpkg-dev','pkg-config'):
    p=run(['dpkg-query','-W','-f=${Status}',package],False)
    assert p.stdout.strip()!='install ok installed',package
assert not list(Path('/usr/lib').glob('*/libQt6Core.so.*')), 'Qt Core was preinstalled'
archives=[];depends={};digests={}
for package in ('fic','fic-cli','fic-dick'):
    found=list(Path('/var/tmp/fic-packages').glob(package+'_*.deb'));assert len(found)==1,found
    archives.append(str(found[0]));digests[found[0].name]=hashlib.sha256(found[0].read_bytes()).hexdigest()
    depends[package]=run(['dpkg-deb','-f',str(found[0]),'Depends']).stdout.strip()
assert 'libqt6core' in depends['fic'] and 'libssl3' in depends['fic'],depends
assert 'libsqlite3-0' in depends['fic-dick'] and 'libssl3' in depends['fic-dick'],depends
for required in ('sudo','procps','openssh-server'):
    assert required not in depends['fic'],depends
# --no-download also blocks copying local DEBs. Network is disabled by runner;
# APT can only use the pre-fetched cache and local package archives.
run(['apt-get','-o','Dir::Cache::archives=/var/tmp/fic-dependency-cache',
     'install','--no-install-recommends','-y',*archives])
for package in ('fic','fic-cli','fic-dick'):
    assert run(['dpkg-query','-W','-f=${Status}',package]).stdout=='install ok installed'
assert not run(['dpkg','--audit']).stdout.strip()
no_optional()
elfs={}
for package in ('fic','fic-cli','fic-dick'):
    files=run(['dpkg-query','-L',package]).stdout.splitlines()
    for name in files:
        p=Path(name)
        if not p.is_file():continue
        with p.open('rb') as stream:magic=stream.read(4)
        if magic!=b'\x7fELF':continue
        linked=run(['ldd',name],False)
        assert 'not found' not in linked.stdout,(name,linked.stdout)
        assert linked.returncode==0 or any(s in linked.stdout for s in ('not a dynamic executable','statically linked')),linked.stdout
        elfs[name]=dict(package=package,sha256=hashlib.sha256(p.read_bytes()).hexdigest(),ldd=linked.stdout)
for expected in ('fic','fic-cli','fic-dick','fic-package-infrastructure'):
    assert '/opt/fic/bin/'+expected in elfs,elfs
run(['systemctl','is-active','fic.service','fic-device.service'])
run(['/opt/fic/bin/fic-cli','status']);run(['/opt/fic/bin/fic-dick','wait-daemon','30'])
assert Path('/var/lib/fic-lifecycle/status').read_text()=='INSTALLED\n'
if negative_mode:
    configured=config()
    assert request('prepare_uninstall')['ok']
    assert_empty_report(request('rollback_all'))
    assert not active()
    ssh=Path('/etc/ssh/sshd_config');sudo=Path('/etc/sudoers.d/detached.backup')
    staged=Path('/etc/sysctl.d/.zzzz-fic.conf.tmp.interrupted')
    for p in (ssh,sudo,staged):p.parent.mkdir(parents=True,exist_ok=True);assert not p.exists()
    ssh.write_text('#@FIC_ORPHAN_UNKNOWN\n');sudo.write_text('#@FIC_SUDO_AUTH_ORPHAN\n');staged.write_text('')
    before={str(p):p.read_bytes() for p in (ssh,sudo,staged)}
    rejected=request('rollback_all');assert not rejected['ok'] and not active(),rejected
    for prefix in ('NET:SshEdit:','DAC:SudoEdit:','SYSCTL:'):
        assert any(row.get('policy','').startswith(prefix) and row['status'] not in ('NOTHING_TO_RELEASE','success') for row in rejected['results']),prefix
    assert before=={str(p):p.read_bytes() for p in (ssh,sudo,staged)} and config()==configured
    for p in (ssh,sudo,staged):p.unlink()  # administrative teardown of test-only artifacts
    # Empty objects with unsafe identity/metadata must never authorize a no-op.
    original_mode=ssh.parent.stat().st_mode & 0o7777
    ssh.parent.chmod(0o777)
    managed_sudo=Path('/etc/sudoers.d/99-fic.conf');outside=Path('/var/tmp/optional-empty')
    outside.write_text('');os.link(outside,managed_sudo)
    managed_sysctl=Path('/etc/sysctl.d/zzzz-fic.conf');managed_sysctl.symlink_to(outside)
    rejected=request('rollback_all');assert not rejected['ok'] and not active(),rejected
    assert managed_sudo.stat().st_nlink==2 and managed_sysctl.is_symlink()
    for prefix in ('NET:SshEdit:','DAC:SudoEdit:','SYSCTL:'):
        assert any(row.get('policy','').startswith(prefix) and row['status'] not in ('NOTHING_TO_RELEASE','success') for row in rejected['results']),prefix
    managed_sudo.unlink();managed_sysctl.unlink();outside.unlink();ssh.parent.chmod(original_mode)
    assert_empty_report(request('rollback_all'));assert config()==configured
# Preserve existing active-SSH release restrictions; no live SSH claim.
run(['systemctl','stop','ssh.service','ssh.socket','sshd.service','sshd.socket'],False)
run(['apt-get','remove','-y','fic'])
assert Path('/var/lib/fic-lifecycle/status').read_text()=='REMOVED\n'
assert not Path('/opt/fic/bin/fic').exists()
run(['/opt/fic/bin/fic-package-infrastructure','prove-remove'])
assert 'not found' not in run(['ldd','/opt/fic/bin/fic-package-infrastructure']).stdout
run(['apt-get','purge','-y','fic','fic-dick'])
assert not Path('/opt/fic/config').exists() and not Path('/opt/fic/db').exists()
assert Path('/var/lib/fic-lifecycle/status').read_text()=='REMOVED\n'
assert not run(['dpkg','--audit']).stdout.strip()
negative_result=None
if negative_mode:
    # Fresh real reinstall: no restoration/discard of the negative journal.
    run(['apt-get','-o','Dir::Cache::archives=/var/tmp/fic-dependency-cache','install','--no-install-recommends','-y',*archives])
    no_optional();assert request('prepare_uninstall')['ok']
    run(['systemctl','stop','fic.service'])
    run(['/usr/local/bin/optional-owner-fixture'])
    before={r['id']:r for r in active()};assert len(before)==3,before
    configured=config();owned=Path('/etc/sysctl.d/zzzz-fic.conf').read_bytes()
    run(['systemctl','start','fic.service'])
    assert request('status')['lifecycle_state']=='UNINSTALLING'
    rejected=request('rollback_all');assert not rejected['ok'],rejected
    for prefix in ('NET:SshEdit:','DAC:SudoEdit:','SYSCTL:'):
        assert any(row.get('policy','').startswith(prefix) and row['status'] not in ('NOTHING_TO_RELEASE','success') for row in rejected['results']),prefix
    after={r['id']:r for r in active()};assert before.keys()==after.keys(),after
    for key in before:assert before[key]['undo']==after[key]['undo'],(before,after)
    assert not Path('/etc/ssh/sshd_config').exists() and not Path('/etc/sudoers').exists()
    assert Path('/etc/sysctl.d/zzzz-fic.conf').read_bytes()==owned and config()==configured
    failed=run(['apt-get','remove','-y','fic'],False)
    assert failed.returncode!=0 and Path('/opt/fic/bin/fic').exists(),failed.stdout
    assert Path('/var/lib/fic-lifecycle/status').read_text()=='UNINSTALLING\n'
    assert before.keys()=={r['id'] for r in active()} and config()==configured
    no_optional()
    negative_result=dict(status='PASS',fixture='test-seeded valid MutationJournal API records; no real provider apply',
        retained_active=active(),lifecycle='UNINSTALLING',clean_remove_purge_completed_before_negative_fixture=True)
(out/'result.json').write_text(json.dumps(dict(status='PASS',scope='minimal final DEB Depends install/all ELF/readiness/remove/purge',
    os_release=Path('/etc/os-release').read_text(),archives_sha256=digests,depends=depends,elfs=elfs,optional_ownership_negatives=negative_result),indent=2))
print('PASS: final real DEB runtime dependencies, every packaged ELF and remove/purge')
