#!/usr/bin/env python3
"""Export new I1 observations; never edit/upgrade historical R1/R2 evidence."""
import argparse,hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent
PLATFORMS=('debian-12','debian-13','ubuntu-24.04','ubuntu-26.04','alt-p11')
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
out={'schema':'sssd-i1-native-v1','base':'a7c22005cb30ec4d92f9dad9731fd9e8f0ce6614',
     'scope':'I1 read-only input/launch observations; not completed A/B/C/P or policy activation',
     'environment':'Docker, stock distribution SSSD/systemd PID1, network none/loopback, no runtime host binds, shared WSL kernel',
     'profiles':{},'source_sha256':{}}
parser=argparse.ArgumentParser()
parser.add_argument('--update-launch-fixtures',action='store_true',help='replace measured profile fixtures only after reviewed profile facts change')
args=parser.parse_args()
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
 HERE/'Driver.cpp',HERE/'native.py',HERE/'run-native.sh',HERE/'Containerfile',HERE/'CMakeLists.txt',
 ROOT/'tests/integration/sssd-research/pam-probe.py']
for p in sorted(paths):out['source_sha256'][str(p.relative_to(ROOT))]=digest(p)
review={}
cache=ROOT/'build-sssd-research/alt-p11/source'
source=cache/'sssd-2.9.8'
r1=json.loads((ROOT/'tests/integration/sssd-research/source-r1.json').read_text())['alt-p11']
for rel,spans in {'src/monitor/monitor.c':[(830,855),(1662,1666)],
                  'src/sysv/systemd/sssd-pam.service.in':[(1,25)]}.items():
 p=source/rel
 if rel in r1['files']:assert digest(p)==r1['files'][rel]['sha256'],rel
 lines=p.read_text().splitlines()
 review[rel]={'sha256':digest(p),'excerpts':[{'line':i+1,'text':lines[i]} for a,b in spans for i in range(a-1,min(b,len(lines)))]}
review['sssd-default.conf']={'sha256':digest(cache/'sssd-default.conf'),'text':(cache/'sssd-default.conf').read_text()}
out['alt_identity_source_review']={'provenance':'unchanged source-r1.json, patched sssd-2.9.8-alt3 tree','files':review}
(HERE/'evidence.json').write_text(json.dumps(out,indent=2)+'\n')
if args.update_launch_fixtures:(HERE/'launch-fixtures.json').write_text(json.dumps(fixtures,indent=2)+'\n')
print('Exported five new I1 native results; no R1/R2 artifacts touched')
