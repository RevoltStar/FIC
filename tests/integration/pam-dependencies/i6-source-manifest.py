#!/usr/bin/env python3
"""Tracked I6 build/harness inputs plus extension-independent native PAM payloads."""
import hashlib
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[3]
SOURCE_SUFFIXES = {'.cpp', '.h', '.c', '.cmake', '.txt', '.py', '.sh', '.in'}
RESOURCE_ROOTS = ('packaging/deb/pam-slots/', 'packaging/deb/pam-configs/',
                  'fic/src/resources/pam/', 'fic/src/resources/config/',
                  'fic/src/resources/lang/')
# Direct inputs read by the two selected platform/PAM packaging static CTests.
STATIC_INPUTS = {
    'packaging/deb/Dockerfile.debian13',
    'packaging/deb/lifecycle/fic.postinst', 'packaging/deb/lifecycle/fic.prerm',
    'packaging/rpm/fic-pam-faillock', 'packaging/rpm/fic-trust-sync.filetrigger',
    'packaging/rpm/lifecycle/fic-dick.pre', 'packaging/rpm/lifecycle/fic.post',
    'packaging/rpm/lifecycle/fic.preun',
}
RUNTIME_RECIPE = 'tests/integration/pam-dependencies/Dockerfile.functional-runtime'


def source_manifest(root=ROOT):
    tracked = subprocess.check_output(
        ['git', '-C', str(root), 'ls-files', '-z']).decode().split('\0')
    names = sorted(name for name in tracked if name and (
        (name.startswith(('fic/', 'fic-common/', 'tests/', 'cmake/'))
         or name == 'CMakeLists.txt') and pathlib.Path(name).suffix in SOURCE_SUFFIXES
        or name.startswith(RESOURCE_ROOTS) or name == RUNTIME_RECIPE
        or name in STATIC_INPUTS
        or (name.startswith(('packaging/deb/build-fic-', 'packaging/rpm/build-fic-'))
            and name.endswith('.sh'))))
    digest = hashlib.sha256()
    for name in names:
        digest.update(name.encode() + b'\0' + hashlib.sha256((root / name).read_bytes()).digest())
    return digest.hexdigest()


if __name__ == '__main__':
    print(source_manifest())
