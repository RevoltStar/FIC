"""Real dpkg late-postrm failure/retry with an unavailable daemon.lock."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

assert os.environ.get('FIC_PACKAGE_LIFECYCLE_NATIVE')=='1'
assert Path('/proc/1/comm').read_text().strip()=='systemd'
assert os.stat('/proc/self/ns/mnt').st_ino!=int(os.environ['FIC_HOST_MNT_INODE'])
out=Path('/var/tmp/fic-package-results');out.mkdir()
events=[]
def run(args,success=True):
    p=subprocess.run(args,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=300,
                     env=dict(os.environ,DEBIAN_FRONTEND='noninteractive'))
    events.append(dict(command=args,exit_code=p.returncode,output=p.stdout))
    (out/'commands.json').write_text(json.dumps(events,indent=2))
    print('EXIT',p.returncode,' '.join(args),flush=True)
    if success: assert p.returncode==0,p.stdout
    return p
def saved():
    return {str(p):hashlib.sha256(p.read_bytes()).hexdigest()
            for root in ('/etc/pam.d','/opt/fic/config','/opt/fic/db','/var/lib/fic-lifecycle')
            for p in Path(root).rglob('*') if p.is_file()}
run(['mount','--rbind','/sys','/sys'])
run(['mount','-o','remount,bind,ro','/sys'])
assert os.statvfs('/sys').f_flag & os.ST_RDONLY
run(['systemctl','stop','ssh.service','ssh.socket'],False)
packages=[]
for name in ('fic-dick','fic','fic-cli'):
    found=list(Path('/var/tmp/fic-packages/upgrades').glob(name+'_*.deb'))
    assert len(found)==1,found
    packages.append(str(found[0]))
run(['dpkg','-i',*packages])
run(['dpkg','--remove','fic-cli','fic'])
assert not Path('/opt/fic/bin/fic').exists()
before=saved()
ready=Path('/run/native-purge-lock-ready')
holder=subprocess.Popen(['flock','--no-fork','-x','/run/fic/daemon.lock','sh','-ec',
                         'echo ready > /run/native-purge-lock-ready; exec sleep 60'])
try:
    for _ in range(100):
        assert holder.poll() is None
        if ready.exists(): break
        time.sleep(.05)
    assert ready.exists()
    failed=run(['dpkg','--purge','fic'],False)
    assert failed.returncode!=0 and 'daemon.lock' in failed.stdout,failed.stdout
    after=saved()
    changed={p for p in before.keys()|after.keys() if before.get(p)!=after.get(p)}
    # dpkg removes its own neutral conffiles BEFORE calling postrm. They no
    # longer carry live references after successful remove. The postrm lock
    # must protect desired config, journal/witness and every external PAM file.
    slots={'/etc/pam.d/'+n for n in ('fic-faillock-preauth','fic-faillock-authfail',
        'fic-faillock-authsucc','fic-faillock-account','fic-password-quality',
        'fic-password-history','fic-password-history-initial')}
    assert changed<=slots and all(p not in after for p in changed),changed
    events.append(dict(postrm_failure_dpkg_deleted_neutral_conffiles=sorted(changed)))
    (out/'commands.json').write_text(json.dumps(events,indent=2))
finally:
    # --no-fork and shell exec retain the lock in this exact child process.
    holder.terminate();holder.wait(timeout=10)
run(['flock','-n','/run/fic/daemon.lock','true'])
run(['dpkg','--purge','fic'])
assert not Path('/opt/fic/config').exists() and not Path('/opt/fic/db').exists()
assert Path('/var/lib/fic-lifecycle/status').read_text()=='REMOVED\n'
run(['dpkg','--purge','fic-dick','fic-cli'])
(out/'result.json').write_text(json.dumps(dict(status='PASS',scope='real dpkg late postrm failure/retry without daemon ELF')))
print('PASS: real late postrm failure preserves PAM/config/journal and retry purges data')
