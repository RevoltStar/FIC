#!/usr/bin/env python3
"""Copy only successful, source-bound native reports; never edits historical evidence."""
import hashlib,json,subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
platforms=('debian-12','debian-13','ubuntu-24.04','ubuntu-26.04','alt-p11')
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
current=json.loads(subprocess.check_output(['python3',str(HERE/'source-manifest.py')]))
out={'schema':'sssd-i3-native-v1','base':'ad41b954b009989cf9b12bed6fade17c1b7d2e9e','environment':'Docker; stock five distribution userlands/systemd PID1; WSL shared kernel; loopback only; no runtime host binds/ports','proof_model':'bounded source-causal; no direct memory/auth/LDAP health/cleanup execution claim','source_sha256':current,'source_review_sha256':digest(HERE/'source-review.json'),'historical_sha256':{},'profiles':{}}
for directory in ('sssd-research','sssd-i1','sssd-i2'):
 for name in ('evidence.json','source-r1.json','source-r2.json','source-review.json','launch-fixtures.json'):
  path=HERE.parent/directory/name
  if path.exists():out['historical_sha256'][str(path.relative_to(ROOT))]=digest(path)
(HERE/'reports').mkdir(exist_ok=True)
for platform in platforms:
 build=ROOT/'build-sssd-i3'/platform/'native';completion=json.loads((build/'completion.json').read_text());data=(build/'results.json').read_bytes();report=json.loads(data)
 assert completion['exit_code']==0 and completion['source_sha256']==current
 assert hashlib.sha256(data).hexdigest()==completion['report_sha256']
 assert report['experiments']['result']['status']=='PASS' and report['experiments']['ldap-functional-result']['status']=='PASS'
 path=HERE/'reports'/f'{platform}.json';path.write_bytes(data)
 container=json.loads((build/'container.json').read_text())[0];host=container['HostConfig']
 assert host['NetworkMode']=='none' and host['CgroupnsMode']=='private' and not host['Binds'] and not host['PortBindings']
 out['profiles'][platform]={'status':'PASS','report':str(path.relative_to(ROOT)),'report_sha256':digest(path),'probe_sha256':completion['probe_sha256'],'image_id':container['Image'],'runtime_isolation':{'network':host['NetworkMode'],'cgroupns':host['CgroupnsMode'],'host_binds':host['Binds'],'ports':host['PortBindings']},'observations':len(report['experiments']),'completed_proofs':['A','B','C-source-causal','P'],'policy_success':False,'policy_coverage':'NotEvaluated'}
(HERE/'evidence.json').write_text(json.dumps(out,indent=2)+'\n')
print('I3 five source-bound native reports collected; I1 regressions are collected separately')
