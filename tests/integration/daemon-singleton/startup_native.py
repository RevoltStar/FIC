#!/usr/bin/env python3
"""Opt-in: execute real daemon's rejected startup only in a disposable container."""
import hashlib
import json
import os
from pathlib import Path
import select
import stat
import subprocess
import sys

if os.environ.get('FIC_DAEMON_SINGLETON_NATIVE') != '1' or os.geteuid() != 0:
    print('SKIP: explicit disposable root container opt-in required')
    sys.exit(77)

daemon, driver = sys.argv[1:3]

def snapshot():
    result = {}
    for root in map(Path, ('/opt/fic', '/etc/ssh', '/etc/pam.d', '/run/fic', '/var/lib/fic-lifecycle')):
        paths = [root]
        if root.is_dir():
            paths.extend(root.rglob('*'))
        for path in paths:
            try:
                info = path.lstat()
            except FileNotFoundError:
                result[str(path)] = None
                continue
            value = os.readlink(path) if stat.S_ISLNK(info.st_mode) else (
                hashlib.sha256(path.read_bytes()).hexdigest() if stat.S_ISREG(info.st_mode) else None)
            result[str(path)] = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, value)
    return result

holder = subprocess.Popen([driver, '--hold', '/run/fic'], stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
try:
    assert select.select([holder.stdout], [], [], 10)[0], 'lock-holder readiness timeout'
    assert holder.stdout.readline().strip() == 'LOCKED', 'lock-holder failed'
    before = snapshot()
    for command,action,version,abi in (('package-prepare','install','wrong','1'),('package-prepare','upgrade','1','2'),('package-release','remove','1','1')):
        result=subprocess.run([daemon,'--maintenance',command,action,version,abi],
                              capture_output=True,text=True,timeout=10)
        assert result.returncode!=0 and 'refusing package runtime prerequisite:' in result.stderr, result.stderr
        assert snapshot()==before, 'unproven package runtime changed security state before prerequisite'
    for extra in ([], ['--socket', '/tmp/fic-singleton-custom.sock']):
        result = subprocess.run([daemon, *extra], capture_output=True, text=True, timeout=10)
        assert result.returncode != 0, 'second daemon startup succeeded'
        assert 'another daemon instance holds the lock' in result.stderr, result.stderr
        assert snapshot() == before, 'rejected startup changed security/journal/runtime files'
        assert not Path('/tmp/fic-singleton-custom.sock').exists(), 'created custom socket before lock'
    for domain in ('dm', 'desktop', 'pam-provider', 'pam-password'):
        result = subprocess.run([daemon, '--maintenance', domain + '-prerm-prepare', 'release'],
                                capture_output=True, text=True, timeout=10)
        assert result.returncode != 0 and 'another daemon instance holds the lock' in result.stderr, result.stderr
        assert snapshot() == before, (domain, 'release modified persistent state before admission')
    for args in (['ensure-config'], ['ensure-config-first-install'], ['incident-init'],
                 ['bootstrap-pam-password-slots'], ['incident-pam-alt', 'attach'], ['incident-pam-alt', 'detach'],
                 ['pam-alt-faillock', 'enable'], ['pam-alt-faillock', 'disable'],
                 ['pam-alt-pwhistory', 'enable'], ['pam-alt-pwhistory', 'disable'], ['pam-alt-pwhistory', 'prepare']):
        result = subprocess.run([daemon, '--maintenance', *args],
                                capture_output=True, text=True, timeout=10)
        assert result.returncode != 0 and 'another daemon instance holds the lock' in result.stderr, result.stderr
        assert snapshot() == before, (args, 'mutation before admission')
    for flag in ('--version', '--build-info', '--trust-list-platform-paths'):
        result = subprocess.run([daemon, flag], capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, (flag, result.stderr)
    result = subprocess.run([daemon, '--maintenance', 'check-config'],
                            capture_output=True, text=True, timeout=10)
    assert 'singleton lock' not in result.stderr, 'maintenance was incorrectly singleton-gated'
    assert snapshot() == before, 'read-only command changed security files'
    holder.kill()
    holder.wait(timeout=10)
finally:
    if holder.poll() is None:
        holder.kill()
    holder.communicate(timeout=10)
# A crashed owner must not leave a stale PID-file denial.
restarted = subprocess.run([driver, '--hold', '/run/fic'], input='Q',
                           capture_output=True, text=True, timeout=10)
assert restarted.returncode == 0 and restarted.stdout.strip() == 'LOCKED', restarted.stderr
print('PASS: real daemon default/custom socket refused before startup effects; read-only scope, crash/restart')

# Real ELF lifecycle fence must reject before configuration-failure containment
# and journal/bootstrap, including after a crashed previous lock holder.
fence_root=Path('/var/lib/fic-lifecycle')
assert not fence_root.exists(), 'fixture refuses existing lifecycle provenance'
fence_root.mkdir(mode=0o700)
fence=fence_root/'state.json'
try:
    for phase,operation in ((0,0),(12,0),(13,2),('corrupt',0),('missing',0)):
        if fence.exists():
            fence.unlink()
        if phase=='corrupt':
            fence.write_text('{}\n')
        elif phase!='missing':
            fence.write_text(json.dumps({'version':2,'operation':operation,'phase':phase,
                'id':'a'*32,'mask_id':'a'*32,'package_version':'1','generation':0,'attempt_boot':'','attempt_ms':0,'failure':0})+'\n')
        if fence.exists():
            fence.chmod(0o600)
        before=snapshot()
        for args in ([],['--socket','/tmp/fic-singleton-custom.sock'],['--maintenance','incident-init'],
                     ['--maintenance','ensure-config'],['--maintenance','pam-alt-pwhistory','prepare']):
            result=subprocess.run([daemon,*args],capture_output=True,text=True,timeout=10)
            assert result.returncode!=0 and 'refusing lifecycle admission:' in result.stderr, result.stderr
            assert snapshot()==before, (phase,args,'lifecycle refusal mutated system state')
        result=subprocess.run([daemon,'--trust-sync-platform'],capture_output=True,text=True,timeout=10)
        assert result.returncode!=0 and 'refusing trust-sync lifecycle admission:' in result.stderr, result.stderr
        assert snapshot()==before, (phase,'trust-sync changed state before lifecycle proof')
finally:
    if fence.exists():
        fence.unlink()
    fence_root.rmdir()
print('PASS: actual daemon/standalone lifecycle gate rejects pending/tombstone/corrupt/missing proof before security effects')
