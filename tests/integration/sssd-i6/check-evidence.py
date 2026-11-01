#!/usr/bin/env python3
"""Retained I6 evidence contract; ordinary CTest never starts containers."""
import gzip,hashlib,importlib.util,json
from pathlib import Path
from contracts import PLATFORMS,SCENARIOS,POSITIVE,BASE,BASE_TREE
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
spec=importlib.util.spec_from_file_location('i6_manifest',HERE/'source-manifest.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
def sha(data):return hashlib.sha256(data).hexdigest()
def report(item):
    compressed=(ROOT/item['path']).read_bytes();raw=gzip.decompress(compressed)
    assert sha(compressed)==item['sha256'] and sha(raw)==item['raw_sha256']
    return json.loads(raw)
e=json.loads((HERE/'evidence.json').read_text())
assert e['schema']=='sssd-i6-production-native-v1' and e['base']==BASE
assert e['production_daemon'] and e['real_packages']
assert e['source_sha256']==m.manifest(),'I6 production/build sources changed; fresh packages and matrix required'
assert e['harness_sha256']==m.harness_manifest(),'I6 fixture sources changed; rerun current matrix'
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
            if scenario in ('cas-drift','cleanup-failure','wrong-registry-generation','journal-finalization-failure','crash-before-save','crash-before-ack','runtime-generation-change','receipt-substitution','legacy-v2-awaiting','wrong-physical-witness'):
                assert o['debugger-seam']['hit'] and o['debugger-seam']['cli']['exit_code']!=0
print('I6 source-bound five-platform actual daemon/CLI/package matrix PASS; retained evidence only')
