#!/usr/bin/env python3
"""Opt-in: execute real daemon's rejected startup only in a disposable container."""
import hashlib
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
    for root in map(Path, ('/opt/fic', '/etc/ssh', '/etc/pam.d', '/run/fic')):
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
    for extra in ([], ['--socket', '/tmp/fic-singleton-custom.sock']):
        result = subprocess.run([daemon, *extra], capture_output=True, text=True, timeout=10)
        assert result.returncode != 0, 'second daemon startup succeeded'
        assert 'another daemon instance holds the lock' in result.stderr, result.stderr
        assert snapshot() == before, 'rejected startup changed security/journal/runtime files'
        assert not Path('/tmp/fic-singleton-custom.sock').exists(), 'created custom socket before lock'
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
