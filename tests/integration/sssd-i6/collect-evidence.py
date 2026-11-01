#!/usr/bin/env python3
"""Collect only complete, current-source, actual-package native I6 matrix."""
import gzip,hashlib,importlib.util,json
from pathlib import Path
from contracts import PLATFORMS,SCENARIOS,BASE,BASE_TREE
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
spec=importlib.util.spec_from_file_location('i6_manifest',HERE/'source-manifest.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
def sha(data):return hashlib.sha256(data).hexdigest()
def retain(path,data):
    path.parent.mkdir(parents=True,exist_ok=True);compressed=gzip.compress(data,compresslevel=9,mtime=0);path.write_bytes(compressed)
    return {'path':str(path.relative_to(ROOT)),'sha256':sha(compressed),'raw_sha256':sha(data)}
e={'schema':'sssd-i6-production-native-v1','base':BASE,'source_sha256':m.manifest(),'harness_sha256':m.harness_manifest(),
   'production_daemon':True,'real_packages':True,'profiles':{}}
for platform in PLATFORMS:
    build=ROOT/'build-sssd-i6'/platform;raw=(build/'build-receipt.json').read_bytes();receipt=json.loads(raw)
    assert receipt['clean_build'] and receipt['exit_code']==0 and receipt['source_sha256']==e['source_sha256'] and receipt['platform']==platform
    row={'build':retain(HERE/'reports'/f'{platform}-build.json.gz',raw),'scenarios':{}}
    old=(ROOT/'build-sssd-i6'/('legacy-'+platform)/'legacy-build-receipt.json').read_bytes()
    previous=json.loads(old);assert previous['base']==BASE and previous['source_tree']==BASE_TREE and previous['clean_build'] and previous['exit_code']==0
    row['legacy_build']=retain(HERE/'reports'/f'{platform}-legacy-build.json.gz',old)
    for scenario in SCENARIOS:
        out=build/'native'/scenario;c=json.loads((out/'completion.json').read_text());raw=(out/'results.json').read_bytes();r=json.loads(raw)
        assert c['exit_code']==0 and c['report_sha256']==sha(raw) and c['build_receipt_sha256']==sha((build/'build-receipt.json').read_bytes())
        assert c['harness_sha256']==e['harness_sha256']
        if scenario.startswith('legacy-upgrade-'):assert c['legacy_build_receipt_sha256']==sha(old)
        result=r['experiments']['result'];assert result['status']=='PASS' and result['platform']==platform and result['scenario']==scenario
        assert result['production_daemon'] and result['real_packages'] and 'failure' not in r['experiments']
        item=retain(HERE/'reports'/f'{platform}-{scenario}.json.gz',raw)
        item.update(exit_code=0,observations=len(r['experiments']),container=retain(HERE/'reports'/f'{platform}-{scenario}-container.json.gz',(out/'container.json').read_bytes()));row['scenarios'][scenario]=item
    e['profiles'][platform]=row
(HERE/'evidence.json').write_text(json.dumps(e,indent=2)+'\n')
print('Collected complete five-platform actual daemon/CLI/package I6 matrix')
