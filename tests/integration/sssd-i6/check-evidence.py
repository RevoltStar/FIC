#!/usr/bin/env python3
"""Verify the accepted historical I6 matrix, not current-HEAD compatibility."""
import gzip,hashlib,json
from pathlib import Path
ACCEPTED_COMMIT='96b88d2b40abff5cec9cd4352891401350e26719'
# SHA-256 of git show ACCEPTED_COMMIT:tests/integration/sssd-i6/evidence.json.
ACCEPTED_EVIDENCE_SHA256='6dd6fac33b0846d97202dda46f13428bed17622a489ad006b21dddc8ff305306'
# Frozen contracts.py from that commit; current native contracts are independent.
PLATFORMS=('debian-12','debian-13','ubuntu-24.04','ubuntu-26.04','alt-p11')
SCENARIOS=('positive','stopped-apply','journal-invalid','relation-conflict','domain-key-drift',
           'remaining-enabled-scope-drift','remaining-enabled-unowned','remaining-enabled-unowned-matching-foreign','acknowledgement-unowned-matching-foreign','late-foreign','foreign-relation','package-release-refusal',
           'cas-drift','cleanup-failure','wrong-registry-generation','journal-finalization-failure',
           'crash-before-save','crash-before-ack','runtime-generation-change','receipt-substitution',
           'legacy-v2-awaiting','wrong-physical-witness','legacy-upgrade-applied','legacy-upgrade-prepared','legacy-upgrade-rollback-failed')
POSITIVE=('registration-no-default','same-value','refresh-10-to-30','three-policies-multidomain',
          'active-release-survivors','no-owner-with-owned-siblings','offline-release-survivor',
          'active-last-release','re-enable-new-owner','uninstall-release-only','package-uninstall')
BASE='4717cfd4af6df9297b1a6234759258a415dcea34'
BASE_TREE='deec5ba63986ff9cd0ba875e92dda4df4e4caceb'
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
def sha(data):return hashlib.sha256(data).hexdigest()
def report(item):
    compressed=(ROOT/item['path']).read_bytes();raw=gzip.decompress(compressed)
    assert sha(compressed)==item['sha256'] and sha(raw)==item['raw_sha256']
    return json.loads(raw)
accepted=(HERE/'evidence.json').read_bytes()
assert sha(accepted)==ACCEPTED_EVIDENCE_SHA256,'accepted historical I6 evidence.json SHA-256 mismatch'
e=json.loads(accepted)
assert e['schema']=='sssd-i6-production-native-v1' and e['base']==BASE
assert e['production_daemon'] and e['real_packages']
assert set(e['profiles'])==set(PLATFORMS)
for platform,row in e['profiles'].items():
    b=report(row['build']);assert b['clean_build'] and b['exit_code']==0 and b['platform']==platform and b['source_sha256']==e['source_sha256']
    assert len(b['packages'])==3
    old=report(row['legacy_build']);assert old['base']==BASE and old['source_tree']==BASE_TREE and old['clean_build'] and old['exit_code']==0 and old['product_version']=='0.0.0-a' and len(old['packages'])==3
    assert set(row['scenarios'])==set(SCENARIOS)
    for scenario,item in row['scenarios'].items():
        container=report(item['container'])[0];h=container['HostConfig']
        assert h['NetworkMode']=='none' and h['CgroupnsMode']=='private' and not h['PidMode'] and h['IpcMode']!='host' and not h['Binds'] and not h['PortBindings']
        r=report(item);o=r['experiments'];assert item['exit_code']==0 and len(o)==item['observations']
        assert o['result']=={'status':'PASS','platform':platform,'scenario':scenario,'production_daemon':True,'real_packages':True}
        assert 'failure' not in o and o['inventory']['platform']==platform
        assert any(x.get('command',[None])[0] in ('dpkg','rpm') for x in r['commands'])
        assert any(x.get('command',[None])[0]=='/opt/fic/bin/fic-cli' for x in r['commands'])
        if scenario=='positive':
            assert all(name in o for name in POSITIVE)
            for name in POSITIVE[:-1]:
                x=o[name];active=[r for r in x['records'] if r['status']=='applied']
                if x['managed'] is None:assert not active
                else:
                    latest=max((r['undo']['ownership'].get('container') or r['undo']['ownership']['current'] for r in active),key=lambda s:s['sequence'])
                    assert latest['publication']==x['native_witness']
            assert o['package-uninstall']['status']=='PASS'
            release=o['offline-release-survivor']['records']
            account=[r for r in release if r['policy']['policy']=='sssd_account_cache_expiration'][-1]
            t=account['undo']['ownership']['transition'];assert t['version']==3 and t['release']['offline_verified'] and t['release']['runtime_receipt'] is None
            assert account['status']=='rolled_back' and t['release']['disable_generation']
        else:
            assert scenario in o
            if scenario in ('remaining-enabled-scope-drift','remaining-enabled-unowned','remaining-enabled-unowned-matching-foreign','acknowledgement-unowned-matching-foreign'):
                before=o['coverage-before-acknowledgement' if scenario.startswith('acknowledgement-') else 'coverage-before-disable'];after=o[scenario]
                assert before['records']==after['records'] and before['managed']==after['managed'] and before['native_witness']==after['native_witness'] and before['config']==after['config']
                assert before['service']['InvocationID']==after['service']['InvocationID']
                if scenario=='remaining-enabled-unowned-matching-foreign':
                    assert not o['uninstall-unowned-enabled-release-only']['managed'] and not any(r['status'] in ('applied','prepared','rollback_failed') for r in o['uninstall-unowned-enabled-release-only']['records'])
            if scenario=='remaining-enabled-scope-drift':
                proof=o['scope-drift-proof']
                assert proof['canonical_scope_changed'] and proof['foreign_sha256']==o['scope-drift-foreign-after']
                assert 'domain/provider scope changed' in proof['production_apply_refusal']['stdout']
                assert any('scope mismatch' in c.get('stdout','') and 'sssd_cache_credentials' in c.get('stdout','') for c in r['commands'])
            if scenario in ('acknowledgement-unowned-matching-foreign','cas-drift','cleanup-failure','wrong-registry-generation','journal-finalization-failure','crash-before-save','crash-before-ack','runtime-generation-change','receipt-substitution','legacy-v2-awaiting','wrong-physical-witness'):
                assert o['debugger-seam']['hit'] and o['debugger-seam']['cli']['exit_code']!=0
print(f'Historical I6 five-platform matrix PASS ({ACCEPTED_COMMIT}); does not certify current HEAD')
