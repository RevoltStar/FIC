#!/usr/bin/env python3
"""Export new I1 observations; never edit/upgrade historical R1/R2 evidence."""
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent
PLATFORMS=('debian-12','debian-13','ubuntu-24.04','ubuntu-26.04','alt-p11')
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
out={'schema':'sssd-i1-native-v1','base':'19a97e7e1a7ef1179b3f3be0d2d893dcd7c3f91d',
     'scope':'I1 read-only input/launch observations; not completed A/B/C/P or policy activation',
     'environment':'Docker, stock distribution SSSD/systemd PID1, network none/loopback, no runtime host binds, shared WSL kernel',
     'profiles':{},'source_sha256':{}}
fixtures={}
for platform in PLATFORMS:
 raw=ROOT/'build-sssd-i1'/platform/'native'/'results.json'
 result=json.loads(raw.read_text());e=result['experiments']
 assert e['result']['status']=='PASS',platform
 inspection=json.loads((raw.parent/'container.json').read_text())[0]
 assertions={}
 for name,v in e.items():
  if name in ('platform','typed-launch','result'):continue
  if name in ('stock-start','native-merge','absent-main-native'):
   assertions[name]={'restart':v['restart'],'state':v['state'],'configdb':v['configdb']}
  elif name=='native-source-load-log':assertions[name]=v
  else:assertions[name]={k:val for k,val in v.items() if k!='launch'}
 out['profiles'][platform]={'status':'PASS','inventory':e['platform'],
   'image_id':inspection['Image'],'raw_sha256':digest(raw),'observations':assertions,
   'command':['tests/integration/sssd-i1/run-native.sh',inspection['Config']['Image'],platform],
   'activation_status':'NOT_TESTED','runtime_receipt':False,
   'i3_limit':e['main-snippets']['activation_limit']}
 fixtures[platform]=e['typed-launch']['launch']
paths=list((ROOT/'fic/src/service/sssd').glob('*'))+[
 ROOT/'fic/src/service/VerifiedConfigLaunchContract.cpp',ROOT/'fic/src/service/VerifiedConfigLaunchContract.h',
 HERE/'Driver.cpp',HERE/'native.py',HERE/'run-native.sh',HERE/'Containerfile',HERE/'CMakeLists.txt']
for p in sorted(paths):out['source_sha256'][str(p.relative_to(ROOT))]=digest(p)
(HERE/'evidence.json').write_text(json.dumps(out,indent=2)+'\n')
(HERE/'launch-fixtures.json').write_text(json.dumps(fixtures,indent=2)+'\n')
print('Exported five new I1 native results; no R1/R2 artifacts touched')
