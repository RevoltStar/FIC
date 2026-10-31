#!/usr/bin/env python3
"""Collect only completed source-bound native runs. Never fabricates PASS."""
import gzip,hashlib,importlib.util,json
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
spec=importlib.util.spec_from_file_location('i4_manifest',HERE/'source-manifest.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
source=module.manifest()
index={'schema':'sssd-i4-native-v1','base':'2e6b72ae16236a9d871f59cb4e3e845cbc275d73',
       'source_sha256':source,'profiles':{},'policy_integration':False,'verified_release':False}
(HERE/'reports').mkdir(exist_ok=True)
for platform in ('debian-12','debian-13','ubuntu-24.04','ubuntu-26.04','alt-p11'):
 build=ROOT/'build-sssd-i4'/platform
 done=json.loads((build/'native/completion.json').read_text())
 raw=(build/'native/results.json').read_bytes()
 assert done['exit_code']==0 and done['source_sha256']==source,platform
 assert hashlib.sha256(raw).hexdigest()==done['report_sha256'],platform
 assert hashlib.sha256((build/'sssd_i4_probe').read_bytes()).hexdigest()==done['probe_sha256'],platform
 report=json.loads(raw);assert report['experiments']['result']['status']=='PASS',platform
 compressed=gzip.compress(raw,compresslevel=9,mtime=0)
 target=HERE/'reports'/(platform+'.json.gz');target.write_bytes(compressed)
 index['profiles'][platform]={'status':'PASS','observations':len(report['experiments']),
    'report':str(target.relative_to(ROOT)),'report_sha256':hashlib.sha256(compressed).hexdigest(),
    'raw_sha256':done['report_sha256'],'probe_sha256':done['probe_sha256'],
    'exit_code':0,'crash_phases':report['experiments']['result']['crash_phases']}
(HERE/'evidence.json').write_text(json.dumps(index,indent=2)+'\n')
print('Collected five current-source native I4 runs')
