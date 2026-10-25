"""Final real DEBs: install from Depends in a separate minimal PID1 runtime."""
import atexit
import hashlib
import json
import os
from pathlib import Path
import subprocess

assert os.environ.get('FIC_PACKAGE_LIFECYCLE_NATIVE')=='1'
assert Path('/proc/1/comm').read_text().strip()=='systemd'
assert os.stat('/proc/self/ns/mnt').st_ino!=int(os.environ['FIC_HOST_MNT_INODE'])
out=Path('/var/tmp/fic-package-results');out.mkdir()
events=[]
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
    assert required in depends['fic'],depends
# --no-download also blocks copying local DEBs. Network is disabled by runner;
# APT can only use the pre-fetched cache and local package archives.
run(['apt-get','-o','Dir::Cache::archives=/var/tmp/fic-dependency-cache',
     'install','--no-install-recommends','-y',*archives])
for package in ('fic','fic-cli','fic-dick'):
    assert run(['dpkg-query','-W','-f=${Status}',package]).stdout=='install ok installed'
assert not run(['dpkg','--audit']).stdout.strip()
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
(out/'result.json').write_text(json.dumps(dict(status='PASS',scope='minimal final DEB Depends install/all ELF/readiness/remove/purge',
    os_release=Path('/etc/os-release').read_text(),archives_sha256=digests,depends=depends,elfs=elfs),indent=2))
print('PASS: final real DEB runtime dependencies, every packaged ELF and remove/purge')
