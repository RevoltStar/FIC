"""Real package prerm failure after rollback/stop, including partial PAM detach."""
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import time

assert os.environ.get('FIC_PACKAGE_LIFECYCLE_NATIVE')=='1'
assert Path('/proc/1/comm').read_text().strip()=='systemd'
assert os.stat('/proc/self/ns/mnt').st_ino!=int(os.environ['FIC_HOST_MNT_INODE'])
out=Path('/var/tmp/fic-package-results');out.mkdir()
events=[]
def save(): (out/'commands.json').write_text(json.dumps(events,indent=2))
def run(args,success=True):
    p=subprocess.run(args,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=300,
                     env=dict(os.environ,DEBIAN_FRONTEND='noninteractive'))
    events.append(dict(command=args,exit_code=p.returncode,output=p.stdout));save()
    print('EXIT',p.returncode,' '.join(args),flush=True)
    if success: assert p.returncode==0,p.stdout
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
                result=json.loads(body);events.append(dict(ipc_command=command,response=result));save();return result

def hashes(root):
    return {str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in Path(root).rglob('*') if p.is_file()}
def active():
    return [r for r in json.loads(Path('/opt/fic/db/mutation-journal.json').read_text())['records']
            if r['status'] in ('prepared','applied','rollback_failed')]
def resources():
    return {str(p):hashlib.sha256(p.read_bytes()).hexdigest()
            for p in [Path('/etc/login.defs'),*Path('/etc/sudoers.d').glob('*')] if p.is_file()}
def snapshot(label):
    events.append(dict(snapshot=label,lifecycle=state.read_text(),config=hashes('/opt/fic/config'),
        pam=hashes('/etc/pam.d'),selection=hashes('/var/lib/pam'),resources=resources(),active=active(),
        journal=hashlib.sha256(Path('/opt/fic/db/mutation-journal.json').read_bytes()).hexdigest()))
    save()

def restricted():
    run(['systemctl','start','fic.service'])
    assert request('status')['lifecycle_state']=='UNINSTALLING'
    before=resources();journal=Path('/opt/fic/db/mutation-journal.json').read_bytes()
    time.sleep(2.2)  # --interval1: more than two startup/periodic opportunities.
    denied=request('apply_all')
    assert not denied['ok'] and denied['error_code']=='UNINSTALL_IN_PROGRESS',denied
    assert before==resources() and not active() and hashes('/opt/fic/config')==configured
    assert journal==Path('/opt/fic/db/mutation-journal.json').read_bytes()
    result=request('rollback_all')
    assert result['ok'],result
    assert any(r.get('domain')=='PAM_PASSWORD' and r.get('status')=='RELEASED' for r in result['results']),result
    assert before==resources() and not active() and hashes('/opt/fic/config')==configured

run(['mount','--rbind','/sys','/sys']);run(['mount','-o','remount,bind,ro','/sys'])
assert os.statvfs('/sys').f_flag & os.ST_RDONLY
run(['systemctl','stop','ssh.service','ssh.socket'],False)
packages=[]
for name in ('fic-dick','fic','fic-cli'):
    found=list(Path('/var/tmp/fic-packages').glob(name+'_*.deb'));assert len(found)==1,found
    packages.append(str(found[0]))
install=['apt-get']
if Path('/var/tmp/fic-dependency-cache').is_dir():
    install+=['-o','Dir::Cache::archives=/var/tmp/fic-dependency-cache']
run([*install,'install','--no-install-recommends','-y',*packages])
run(['systemctl','stop','ssh.service','ssh.socket'],False)
state=Path('/var/lib/fic-lifecycle/status')
assert state.read_text()=='INSTALLED\n'
for module,policies in [('IDENTITY_ACCESS',('password_max_age_days','password_min_age_days',
                         'enable_password_quality','enable_password_history','password_min_length')),
                        ('DAC',('sudo_disable_scoped_defaults','sudo_exempt_group_disable','sudo_env_reset'))]:
    for policy in policies:
        run(['/opt/fic/bin/fic-cli','policy','enable',module,policy])
        run(['/opt/fic/bin/fic-cli','policy','apply',module,policy])
assert active()
configured=hashes('/opt/fic/config')
module_files=[Path(p) for p in run(['dpkg-query','-L','fic']).stdout.splitlines() if p.endswith('/pam_fic_access.so')]
assert module_files and all(p.exists() for p in module_files)
dropin=Path('/etc/systemd/system/fic.service.d/native-detach-retry.conf');dropin.parent.mkdir(parents=True,exist_ok=True)
for phase,facility in [('before-detach','auth'),('partial-detach','account')]:
    fault=Path('/var/lib/pam')/(facility+'.new')
    assert not fault.exists()
    dropin.write_text('[Service]\nExecStart=\nExecStart=/opt/fic/bin/fic --interval 1\n'
                      'ExecStopPost=/usr/bin/mkdir '+str(fault)+'\n')
    run(['systemctl','daemon-reload'])
    before_auth=Path('/etc/pam.d/common-auth').read_bytes()
    assert b'fic-faillock-' in before_auth
    failed=run(['apt-get','remove','-y','fic'],False)
    assert failed.returncode!=0 and any(detail in failed.stdout for detail in
        ('package PAM detach failed','FIC PAM package hooks remain selected/attached after removal')),failed.stdout
    assert fault.is_dir() and Path('/opt/fic/bin/fic').exists()
    status=run(['dpkg-query','-W','-f=${Status}','fic']).stdout
    assert status.split()[-1]=='installed',status
    assert state.read_text()=='UNINSTALLING\n' and not active()
    assert hashes('/opt/fic/config')==configured
    assert run(['systemctl','is-active','--quiet','fic.service'],False).returncode!=0
    assert all(p.exists() for p in module_files)
    assert 'pam_fic_access.so' in Path('/etc/pam.d/common-account').read_text()
    if phase=='before-detach':assert Path('/etc/pam.d/common-auth').read_bytes()==before_auth
    else:
        assert b'fic-faillock-' not in Path('/etc/pam.d/common-auth').read_bytes()
        assert 'fic-faillock-account' in Path('/etc/pam.d/common-account').read_text()
        assert 'Module: fic-faillock-hook-preauth' not in Path('/var/lib/pam/auth').read_text()
    snapshot(phase+'-failed-real-prerm')
    released=resources()
    # Explicit administrative repair of the injected filesystem obstruction.
    fault.rmdir()
    dropin.write_text('[Service]\nExecStart=\nExecStart=/opt/fic/bin/fic --interval 1\n')
    run(['systemctl','daemon-reload'])
    restricted()
    assert resources()==released
    snapshot(phase+'-restricted-idempotent-rollback')
# Normal retry invokes real prerm again, including physical detach proofs.
run(['apt-get','remove','-y','fic'])
assert state.read_text()=='REMOVED\n' and not Path('/opt/fic/bin/fic').exists()
assert hashes('/opt/fic/config')==configured and resources()==released
assert not active()
assert 'pam_fic_access.so' not in Path('/etc/pam.d/common-account').read_text()
for p in Path('/etc/pam.d').iterdir():
    if p.is_file() and not p.name.startswith('fic-'):
        assert 'pam_fic_access.so' not in p.read_text(),p
assert all(not p.exists() for p in module_files)
snapshot('retry-removed')
run(['dpkg','--purge','fic','fic-cli','fic-dick'])
(out/'result.json').write_text(json.dumps(dict(status='PASS',scope='real prerm before/partial PAM detach failures, restricted restart/idempotent rollback, safe remove/purge retry')))
print('PASS: real infrastructure detach failure/partial failure and restricted manual retry')
