#!/usr/bin/env python3
"""Validate the native I5 configuration/ownership report, never authenticate."""
import json
import sys
from pathlib import Path

report = json.loads(Path(sys.argv[1]).read_text())
x = report['i5']
assert report['platform'] == x['production_profile'] == 'alt-p11'
assert x['scope_narrowed'] is False
assert set(x['initial']['capabilities'][0]['services']) == {
    'login', 'sshd', 'sudo', 'su', 'sddm', 'gdm-password', 'lightdm', 'system-auth'}
assert all(a['ok'] for a in x['activate'])
baseline = x['initial']['targets']
owned = x['activated']['targets']
primary = owned['/etc/pam.d/system-auth-local-only']
secondary = owned['/etc/pam.d/system-auth-use_first_pass-local-only']
assert primary.count('# BEGIN FIC pam_faillock preauth') == 1
assert secondary.count('# BEGIN FIC pam_faillock preauth') == 1
assert primary.count('# BEGIN FIC pam_pwhistory transaction') == 1
assert '# BEGIN FIC pam_pwhistory' not in secondary
assert 'use_first_pass' in secondary
expected = {'local': [True, True], 'multi': [False, False], 'ldap': [True, True],
            'krb5': [True, True], 'krb5_ccreds': [True, True],
            'winbind': [True, True], 'pkcs11': [False, True]}
for row in x['modes']:
    mode = row['mode']
    assert row['control']['exit'] == 0, mode
    assert row['control_status']['stdout'].strip() == mode, mode
    assert row['before']['system_auth'] == 'system-auth-' + mode
    assert row['before']['use_first_pass'] == 'system-auth-use_first_pass-' + mode
    assert row['before']['system_policy'] == ('system-policy-local' if mode == 'local' else 'system-policy-remote')
    assert row['control_bytes_preserved'] and row['control_journal_preserved']
    assert row['before']['targets'] == owned
    assert [c['inspect'] for c in row['before']['capabilities']] == expected[mode]
    assert [a['ok'] for a in row['apply']] == expected[mode]
    assert row['apply_bytes_preserved'] and row['apply_journal_preserved']
    for cap in row['before']['capabilities']:
        assert cap['physical_mutation_id'] is None  # no invented causal receipt
        assert cap['active_records'] == 1
    h = row['before']['capabilities'][1]
    assert h['selected_local_proof']['ok'] == expected[mode][1]
    if mode == 'ldap':
        assert h['selected_all_proof']['ok'] is False  # do not claim domain history
    for call in row['facilities']:
        if call['action'] == 'status':
            index = 0 if call['facility'] == 'fic-pam-faillock' else 1
            assert (call['result']['exit'] == 0) == expected[mode][index]
            if expected[mode][index]: assert call['result']['stdout'].strip() == 'enabled'
        else: assert call['result']['exit'] != 0
    assert all(a['ok'] for a in row['release'])
    assert row['after_release']['targets'] == baseline
    assert row['after_release']['system_auth'] == row['before']['system_auth']
    assert all(c['active_records'] == 0 for c in row['after_release']['capabilities'])
    assert all(a['ok'] for a in row['reacquire'])
assert all(not a['ok'] for a in x['unsupported_apply'])
assert all(a['ok'] for a in x['unsupported_release'])
assert x['unsupported_after']['system_auth'] == 'i5-unsupported'
assert x['unsupported_after']['targets'] == baseline
assert all(not c['inspect'] for c in x['missing_module_before']['capabilities'])
assert all(a['ok'] for a in x['missing_module_release'])
assert x['missing_module_after']['targets'] == baseline
for row in x['journal_states']:
    should_apply = row['phase'] in {'PreparedBefore', 'PreparedAfter'}
    assert all(a['ok'] == should_apply for a in row['apply']), row['phase']
    if not should_apply:
        assert row['before']['targets'] == row['after_apply']['targets']
        assert row['before']['journal'] == row['after_apply']['journal']
    assert all(a['ok'] for a in row['release']), row['phase']
    assert row['after_release']['targets'] == baseline
assert all(not a['ok'] for a in x['orphan_apply'] + x['orphan_release'])
assert x['orphan_bytes_preserved'] and x['orphan_journal_preserved']
print('PASS I5 native ALT control/configuration proof: modes, two targets, local scope, journal, diagnostics, release; NOT authentication E2E')
