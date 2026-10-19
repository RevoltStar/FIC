#!/usr/bin/env python3
"""Combine only sanitized fixture results; never traverse WORK/key backups."""
import json
import hashlib
from pathlib import Path
import sys


def main():
    root, dest = map(Path, sys.argv[1:])
    result = {'base': '692d34a6f6b3595e088b30b35ced4193b6be77fd',
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
        assert len(data['cases']) == 30
        copied = next(c for c in data['cases'] if c['name'] == 'copyup-stock-main-and-nonempty-stock-Include')
        assert copied['mode'] == 'activate' and copied['activation']['status'] == 'Success'
        assert copied['activation']['readinessConfirmed'] and not copied['activation']['cleanupErrors']
        assert not copied['activation']['residualPaths']
        for phase in ('copyup_preflight', 'directory_copyup_preflight'):
            assert data[phase]['status'] == 'SUPPORTED'
            metadata = {p['path']: p for p in data[phase]['input_metadata']}
            for path in ('/etc/ssh/sshd_config', '/etc/ssh/sshd_config.d'):
                assert metadata[path]['xattr_list_count'] == 0
        assert '/etc/ssh/sshd_config.d' in data['input_paths']
        assert all('/fic-native-inputs' not in p for p in data['input_paths'])
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
