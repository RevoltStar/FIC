"""Real PM status observations under locks; disposable dummy DEBs only.

This is NOT a FIC lifecycle finalizer or a manifest/removal proof.
"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

assert os.environ.get('FIC_MAINTENANCE_NATIVE') == '1'
kind = sys.argv[1]

def run(*args, check=True):
    return subprocess.run(args, text=True, capture_output=True, check=check, timeout=30)

def observe():
    result = run('/usr/local/bin/m1-package-db', kind)
    lines = result.stdout.splitlines()
    remaining = int(lines[-1].split('\t')[1])
    assert 0 < remaining < 1024 * 1024, result
    print(result.stdout, end='', flush=True)
    return [line.split('\t') for line in lines[:-1]]

if kind == 'rpm':
    # Native RPM query format/epoch handling and lock retention. Positive FIC
    # package lifecycle cases require actual RPM fixtures separately.
    observe()
    print('PASS: native RPM database queried twice under retained record lock; no FIC lifecycle proof', flush=True)
elif kind == 'dpkg':
    root = Path(tempfile.mkdtemp(prefix='m1-native-package-db-', dir='/var/lib'))
    for name in ('fic', 'fic-runtime'):
        result = run('dpkg-query', '-W', '-f=${Status}', name, check=False)
        assert result.returncode != 0, 'fresh disposable image required'

    def package(name, version='1', broken=False):
        tree = root / (name + '-' + version)
        control = tree / 'DEBIAN'
        control.mkdir(parents=True)
        (control / 'control').write_text(f'Package: {name}\nVersion: {version}\nArchitecture: all\n'
                                        'Maintainer: FIC native fixture <fixture@example.invalid>\n'
                                        'Description: disposable database observation fixture\n')
        (control / 'postinst').write_text('#!/bin/sh\nexit ' + ('1' if broken else '0') + '\n')
        (control / 'postinst').chmod(0o755)
        target = root / (name + '-' + version + '.deb')
        run('dpkg-deb', '--build', str(tree), str(target))
        return str(target)

    run('dpkg', '--install', package('fic-runtime'))
    result = run('dpkg', '--install', package('fic', broken=True), check=False)
    assert result.returncode != 0
    rows = observe()
    assert any(row[:3] == ['fic', '2', '1'] for row in rows), rows
    assert any(row[:3] == ['fic-runtime', '3', '1'] for row in rows), rows
    run('dpkg', '--install', package('fic', version='2'))
    rows = observe()
    assert any(row[:3] == ['fic', '3', '2'] for row in rows), rows
    run('dpkg', '--remove', 'fic')
    rows = observe()
    assert not any(row[0] == 'fic' and row[1] == '3' for row in rows), rows
    run('dpkg', '--purge', 'fic', 'fic-runtime')
    print('PASS: real failed postinst remains Incomplete; configured is Installed; removal distinguished; no finalizer authority claimed', flush=True)
else:
    raise AssertionError('unknown native PM')
