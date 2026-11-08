#!/usr/bin/env python3
"""Mutate only an isolated checkout; exercise manifest AND real evidence checker."""
import importlib.util
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[3]
HERE = pathlib.Path('tests/integration/pam-dependencies')
EVIDENCE = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ROOT / 'build-pam-i6').resolve()
with tempfile.TemporaryDirectory(prefix='fic-i6-manifest-') as directory:
    clone = pathlib.Path(directory) / 'repo'
    subprocess.run(['git', 'clone', '--quiet', '--shared', str(ROOT), str(clone)], check=True)
    # Include the exact current patch, including newly tracked helper/tests.
    names = subprocess.check_output(['git', '-C', str(ROOT), 'ls-files', '-z']).decode().split('\0')
    for name in names:
        if name and name.startswith(str(HERE) + '/') and (ROOT / name).is_file():
            target = clone / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
    subprocess.run(['git', '-C', str(clone), 'add', '-f', str(HERE)], check=True)
    spec = importlib.util.spec_from_file_location('manifest', clone / HERE / 'i6-source-manifest.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    def digest():
        return module.source_manifest(clone)
    def checker():
        return subprocess.run([sys.executable, str(clone / HERE / 'check-i6-evidence.py'), str(EVIDENCE)],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode
    baseline = digest()
    assert digest() == baseline
    assert checker() == 0, 'baseline evidence must pass before mutation tests'
    cases = [
        ('fic/src/modules/identity_access/pam/AltPamFaillockTopologyManager.cpp', True),
        ('packaging/deb/pam-slots/fic-password-history', True),
        ('packaging/deb/pam-configs/fic-password-history-hook', True),
        ('fic/src/resources/pam/fic-pwhistory.conf', True),
        ('fic/src/resources/config/IDENTITY_ACCESS.conf.in', True),
        ('fic/src/resources/config/GLOBAL.conf', True),
        ('fic/src/resources/lang/ru.lang', True),
        ('fic-common/fic-core/include/fic/core/runtime/FicPathDefaults.h.in', True),
        ('packaging/rpm/lifecycle/fic.preun', True),
        (str(HERE / 'Dockerfile.functional-runtime'), True),
        (str(HERE / 'i6-source-manifest.py'), True),
        (str(HERE / 'check-i6-evidence.py'), True),
        ('docs/pam-r1-architecture-research.md', False),
        (str(HERE / 'i6-evidence/summary.json'), False),
    ]
    results = []
    for name, relevant in cases:
        path = clone / name
        original = path.read_bytes()
        try:
            path.write_bytes(original + b'\n# I6 manifest regression\n')
            assert (digest() != baseline) == relevant, name
            assert (checker() != 0) == relevant, name
            results.append({'input': name, 'invalidates_evidence': relevant, 'result': 'PASS'})
        finally:
            path.write_bytes(original)
        assert digest() == baseline
    assert checker() == 0
    print(json.dumps({'status': 'PASS', 'stable_hash': baseline, 'cases': results}, indent=2))
