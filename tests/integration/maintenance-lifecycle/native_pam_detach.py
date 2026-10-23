"""Read/fixture mutation only inside the explicitly disposable ALT container."""
import os
from pathlib import Path
import stat
import subprocess

assert os.geteuid() == 0 and os.environ.get('FIC_MAINTENANCE_NATIVE') == '1'
assert 'altlinux' in Path('/etc/os-release').read_text()
target = Path('/etc/pam.d/system-auth-common')
assert target.is_file() and not target.is_symlink()
original = target.read_bytes()
mode = stat.S_IMODE(target.stat().st_mode)
alias = Path('/etc/pam.d/fic-m1-escape-fixture')
assert not alias.exists() and not alias.is_symlink()

def prove(expected):
    result = subprocess.run(['/usr/local/bin/m1-pam-detached', '--platform-detached'],
                            text=True, capture_output=True, timeout=10)
    assert result.returncode == expected, result
    print(result.stdout.strip(), flush=True)

try:
    prove(0)
    target.write_bytes(b'account required pam_fic_access.so\n' + original)
    prove(1)
    target.write_bytes(original)
    target.chmod(0o666)
    prove(2)
    target.chmod(mode)
    alias.symlink_to(target)  # absolute links never obtain local-alias proof
    prove(2)
finally:
    if alias.is_symlink():
        alias.unlink()
    target.write_bytes(original)
    target.chmod(mode)
assert target.read_bytes() == original and stat.S_IMODE(target.stat().st_mode) == mode
prove(0)
print('PASS: native ALT stock aliases, referenced gate, unsafe mode/escaping alias refusal, exact fixture restore', flush=True)
