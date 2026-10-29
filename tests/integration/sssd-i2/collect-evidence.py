#!/usr/bin/env python3
"""Export actual I2 reports. Historical R1/R2/I1 artifacts are read-only."""
import hashlib,json
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
platforms=('debian-12','debian-13','ubuntu-24.04','ubuntu-26.04','alt-p11')
out={'schema':'sssd-i2-native-v1','base':'807538d89643be0ec2d63f5b0b9de95661610892',
 'scope':'I2 expected semantics only; not completed C or A/B/C/P, no runtime receipt',
 'environment':'Docker, real stock systemd PID1/SSSD, loopback only, no runtime host binds, WSL shared kernel',
 'profiles':{},'source_sha256':{},'historical_sha256':{}}
for p in platforms:
 raw=ROOT/'build-sssd-i2'/p/'native/results.json';data=json.loads(raw.read_text())
 assert data['experiments']['result']['status']=='PASS',p
 container=json.loads((raw.parent/'container.json').read_text())[0]
 # Full raw outputs remain in the hashed report. Export commands/codes and
 # output hashes once; relevant outputs are retained in named observations.
 data['commands']=[{**{k:v for k,v in c.items() if k not in ('stdout','stderr')},
   'stdout_sha256':hashlib.sha256(c.get('stdout','').encode()).hexdigest(),
   'stderr_sha256':hashlib.sha256(c.get('stderr','').encode()).hexdigest()} for c in data['commands']]
 out['profiles'][p]={'status':'PASS','image_id':container['Image'],'raw_sha256':digest(raw),
  'runner':['tests/integration/sssd-i2/run-native.sh',container['Config']['Image'],p],
  'runtime_receipt':False,'completed_proofs':False,'report':data}
paths=list((ROOT/'fic/src/service/sssd').glob('*'))+[ROOT/'tests/fic/service/SssdDomainSemanticsTests.cpp',
 ROOT/'fic/src/service/VerifiedConfigLaunchContract.cpp',ROOT/'fic/src/service/VerifiedConfigMountSupport.cpp',
 HERE/'Driver.cpp',HERE/'native.py',HERE/'run-native.sh',HERE/'CMakeLists.txt',HERE/'source-review.json']
for path in sorted(paths):out['source_sha256'][str(path.relative_to(ROOT))]=digest(path)
for rel in ('docs/sssd-native-research-evidence.json','docs/sssd-semantics-research-evidence.json',
            'tests/integration/sssd-research/source-r1.json','tests/integration/sssd-research/source-r2.json',
            'tests/integration/sssd-i1/evidence.json','tests/integration/sssd-i1/launch-fixtures.json'):
 out['historical_sha256'][rel]=digest(ROOT/rel)
(HERE/'evidence.json').write_text(json.dumps(out,indent=2)+'\n')
print('Exported five actual I2 native reports')
