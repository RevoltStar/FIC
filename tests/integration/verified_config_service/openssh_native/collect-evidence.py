#!/usr/bin/env python3
"""Combine only sanitized fixture results; never traverse WORK/key backups."""
import json
import hashlib
from pathlib import Path
import sys


def main():
    root, dest = map(Path, sys.argv[1:])
    result = {'base': 'd3bcba86614173d6b7143326df407794cdca8699',
              'date': '2026-10-19', 'environment_type': 'disposable Docker/systemd PID1',
              'VM_matrix': 'NOT_TESTED',
              'proof_definitions': {'A': 'caller-declared snapshot protection during activation',
                                    'B': 'new verified real sshd readiness',
                                    'C': 'full expected SSH effective configuration semantics',
                                    'C_selected': 'bounded tested fixture expectations, not full C',
                                    'persistent': 'reference bytes/manifests after cleanup; not full policy compliance'},
              'distros': {}}
    for distro in ('debian-12', 'debian-13'):
        folder = root / distro
        data = json.loads((folder / 'evidence/results.json').read_text())
        assert data['unit_bytes_unchanged'] and data['restored_sshd_t']
        assert len(data['cases']) == 29
        inspect = json.loads((folder / 'container-inspect.json').read_text())[0]
        assert inspect['HostConfig']['NetworkMode'] == 'none'
        token, = [e.split('=', 1)[1] for e in inspect['Config']['Env'] if e.startswith('FIC_OPENSSH_DISPOSABLE=')]
        assert data['run_id'] == hashlib.sha256(token.encode()).hexdigest(), 'stale evidence from another runtime container'
        data['container_image_id'] = inspect['Image']
        data['caller_ssh_unchanged'] = (folder / 'host-before.txt').read_text() == (folder / 'host-after.txt').read_text()
        assert data['caller_ssh_unchanged']
        result['distros'][distro] = data
    result['sources'] = json.loads((root / 'sources/source-evidence.json').read_text())
    result['descriptor_PGP_signature'] = 'NOT_VERIFIED: signer public key unavailable; HTTPS and declared archive SHA256s checked'
    # Data schema contains synthetic names/values, no private key material.
    serialized = json.dumps(result, indent=2) + '\n'
    assert 'BEGIN OPENSSH PRIVATE KEY' not in serialized and 'BEGIN RSA PRIVATE KEY' not in serialized
    dest.write_text(serialized)


if __name__ == '__main__': main()
