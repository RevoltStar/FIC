"""RED reproduction: native dpkg invokes an uncooperative old abort script.

Uses the exact current legacy fic-dick postinst/prerm bodies frozen from the packaging
producer at 2c9e69c, plus dummy packages and a sentinel at the journal path. This is NOT
an actual FIC journal, finalizer, or production package migration test.
Run only in a disposable container with no host security mounts.
"""
import fcntl
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile

assert os.environ.get('FIC_MAINTENANCE_NATIVE') == '1'
assert os.geteuid() == 0 and Path('/.dockerenv').exists()
assert not Path('/opt/fic').exists(), 'fresh private fixture required'
root = Path(tempfile.mkdtemp(prefix='fic-legacy-abort-', dir='/var/lib'))
legacy = Path(sys.argv[1]) / 'tests/integration/maintenance-lifecycle/legacy-deb-fixture'
trace = root / 'trace'


postinst = (legacy / 'fic-dick.postinst').read_text()
prerm = (legacy / 'fic-dick.prerm').read_text()
print('LEGACY_POSTINST_SHA256=' + hashlib.sha256(postinst.encode()).hexdigest(), flush=True)


def run(*args, check=True):
    result = subprocess.run(args, text=True, capture_output=True, timeout=60)
    print(result.stdout + result.stderr, end='', flush=True)
    if check:
        assert result.returncode == 0, (args, result.returncode)
    return result


def package(version):
    tree = root / ('tree-' + version)
    control = tree / 'DEBIAN'
    control.mkdir(parents=True)
    (control / 'control').write_text('Package: fic-dick\nVersion: ' + version +
        '\nArchitecture: all\nMaintainer: FIC test\nDescription: legacy abort reproduction only\n')
    if version == '1':
        # Instrument only the argument trace; retain the original mutating body.
        script = '#!/bin/sh\nprintf "OLD_POSTINST %s\\n" "$*" >> ' + str(trace) + '\n' + postinst
        (control / 'postinst').write_text(script)
        (control / 'prerm').write_text(prerm)
        (control / 'prerm').chmod(0o755)
    else:
        script = '#!/bin/sh\nprintf "NEW_PREINST %s\\n" "$*" >> ' + str(trace) + '\nexit 1\n'
        (control / 'preinst').write_text(script)
        (control / 'preinst').chmod(0o755)
    if version == '1':
        (control / 'postinst').chmod(0o755)
    archive = root / ('fixture-' + version + '.deb')
    run('dpkg-deb', '--build', str(tree), str(archive))
    return str(archive)


assert run('dpkg-query', '-s', 'fic-dick', check=False).returncode != 0
run('dpkg', '-i', package('1'))
journal = Path('/opt/fic/db/mutation-journal.json')
journal.parent.mkdir(parents=True)
journal.write_text('read-only sentinel, NOT a FIC journal\n')
journal.chmod(0o600)
before = journal.stat()
# Real descriptor-based flock remains held by this independent process during
# the whole dpkg upgrade/abort sequence. No forged package-session authority.
lock = Path('/run/fic/daemon.lock')
lock.parent.mkdir(mode=0o755, exist_ok=True)
with lock.open('a+') as held:
    os.fchmod(held.fileno(), 0o600)
    fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
    result = run('dpkg', '-i', package('2'), check=False)
    assert result.returncode != 0
    after = journal.stat()
    assert before.st_ino == after.st_ino and journal.read_text().startswith('read-only sentinel')
    assert (before.st_mode & 0o777) == 0o600 and (after.st_mode & 0o777) == 0o640
    assert 'OLD_POSTINST abort-upgrade 2' in trace.read_text(), trace.read_text()
    print(trace.read_text(), end='')
    print('REPRODUCED_RED: old postinst abort-upgrade changes journal-path metadata '
          '0600 -> 0640 while another process holds daemon.lock', flush=True)
