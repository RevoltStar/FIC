#!/usr/bin/env python3
"""Real PAM package infrastructure component gate, disposable container ONLY.
No actual FIC package lifecycle or authentication proof is claimed.
"""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys

if os.environ.get('FIC_MAINTENANCE_NATIVE') != '1' or os.environ.get('FIC_PACKAGE_PAM_HOOKS_NATIVE') != '1' or os.geteuid() != 0:
    sys.exit(77)
if not Path('/.dockerenv').exists() and not Path('/run/.containerenv').exists():
    raise RuntimeError('explicit disposable container required')
os.environ['DEBIAN_FRONTEND']='noninteractive'
src, driver, module = map(Path, sys.argv[1:4])
alt = sys.argv[4:] == ['alt']

def run(*args, expected=0):
    result = subprocess.run(list(map(str,args)), capture_output=True, text=True, timeout=40)
    print(result.stdout, result.stderr, end='', flush=True)
    assert result.returncode == expected, (args, result.returncode)

# Fresh disposable container prerequisite. Never replace existing FIC artifacts.
assert not Path('/opt/fic').exists(), 'existing FIC state; fixture refuses adoption'
modules = Path('/lib64/security') if alt else next(Path('/lib').glob('*-linux-gnu/security'))
assert not (modules/'pam_fic_access.so').exists()
shutil.copyfile(module, modules/'pam_fic_access.so')
os.chmod(modules/'pam_fic_access.so',0o644)
if alt:
    run(driver,'attach-alt-fixture')
else:
    for profile in (src/'packaging/deb/pam-configs').glob('fic-*'):
        target = Path('/usr/share/pam-configs')/profile.name
        assert not target.exists()
        shutil.copyfile(profile,target);os.chmod(target,0o644)
    for slot in (src/'packaging/deb/pam-slots').iterdir():
        target = Path('/etc/pam.d')/slot.name
        assert not target.exists()
        shutil.copyfile(slot,target);os.chmod(target,0o644)
    run('/usr/sbin/pam-auth-update','--package')
    run('/usr/sbin/pam-auth-update','--enable','fic-faillock-hook-preauth','fic-faillock-hook-authfail',
        'fic-faillock-hook-authsucc','fic-faillock-hook-account','fic-incident-access')
run(driver,'attached')
run(driver,'proof',expected=1)
run(driver,'detach')
run(driver,'proof')

def snapshot():
    values={}
    for base in (Path('/etc/pam.d'),Path('/var/lib/pam')):
        if base.exists():
            for path in base.iterdir():
                if path.is_file() and not path.is_symlink():
                    info=path.stat()
                    values[str(path)]=(info.st_ino,info.st_mode,hashlib.sha256(path.read_bytes()).hexdigest())
    return values
before=snapshot()
run(driver,'detach')
assert snapshot()==before, 'idempotent detach changed native PAM files'
print('PASS: native package infrastructure attach/detach, postconditions, exact no-op replay; not a full FIC lifecycle gate')
