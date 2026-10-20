#!/usr/bin/env python3
"""Combine only sanitized fixture results; never traverse WORK/key backups."""
import json
import hashlib
from pathlib import Path
import sys


def main():
    root, dest = map(Path, sys.argv[1:])
    result = {'base': '3a6029586f96e3896093901d6f62ed923a543b65',
              'date': '2026-10-20', 'environment_type': 'disposable Docker/systemd PID1',
              'VM_matrix': 'NOT_TESTED',
              'proof_definitions': {'A': 'caller-declared snapshot protection during activation',
                                    'B': 'new verified real sshd readiness',
                                    'C': 'full expected SSH effective configuration semantics',
                                    'C_selected': 'bounded tested fixture expectations, not full C',
                                    'adapter_C': 'only request.policies in the supported grammar/launch profile; NOT full OpenSSH semantics',
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
        adapter = data['adapter_cases']
        assert len(adapter) == 30 and len({c['name'] for c in adapter}) == 30
        for case in adapter:
            verified = case['result']
            if verified['adapter_success']:
                assert verified['A'] == verified['C'] == verified['P'] == 'Proven'
                assert verified['status'] == 'Success' and verified['readinessConfirmed']
                assert not verified['cleanupErrors'] and not verified['residualPaths']
                assert verified['listener_pid_confirmed']
            if verified['adapter_status'] == 3:
                assert not verified['adapter_success'] and verified['status'] == 'Success'
                assert verified['A'] == verified['C'] == 'Proven' and verified['P'] == 'NonCompliant'
        assert sum(c['result']['adapter_success'] for c in adapter) == 5
        assert sum(c['result']['adapter_status'] == 3 for c in adapter) == 2
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
