#!/usr/bin/env python3
"""Disposable-only: run real pre-stop preflight against virgin/corrupt provenance."""
import hashlib
import os
from pathlib import Path
import subprocess
import sys
if os.environ.get('FIC_MAINTENANCE_NATIVE') != '1' or os.geteuid() != 0:
    sys.exit(77)
root = Path('/opt/fic/db')
root.mkdir(parents=True, exist_ok=True)
journal = root / 'mutation-journal.json'
assert not journal.exists(), 'requires disposable virgin journal'

def snapshot():
    return {str(p): (p.lstat().st_mode, os.readlink(p) if p.is_symlink() else
            hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None)
            for p in Path('/opt/fic').rglob('*')}

for corrupt in (False, True):
    if corrupt:
        journal.write_bytes(b'{corrupt preflight journal\n')
    for domain in ('check-persistent', 'validate-pam-slots-before-attach'):
        before = snapshot()
        result = subprocess.run([sys.argv[1], '--maintenance', domain],
                                capture_output=True, text=True, timeout=15)
        assert result.returncode != 0, (domain, 'unproven provenance accepted')
        assert snapshot() == before, (domain, 'preflight mutated persistent state', result.stderr)
        print('PASS:', domain, 'corrupt' if corrupt else 'virgin', 'read-only refusal')
