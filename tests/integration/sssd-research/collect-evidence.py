#!/usr/bin/env python3
"""Export measured native observations, without turning collection into support."""
from pathlib import Path
import hashlib,json
ROOT=Path(__file__).resolve().parents[3]
PROFILES=('debian-12','debian-13','ubuntu-24.04','ubuntu-26.04','alt-p11')
def load(profile,stage):
 p=ROOT/'build-sssd-research'/profile/stage/'results.json'
 data=json.loads(p.read_text());assert data['collection_complete'],str(p)
 # Commands occur in their named experiment. Omit duplicated transcript list.
 data.pop('commands',None)
 data['raw_sha256']=hashlib.sha256(p.read_bytes()).hexdigest()
 c=json.loads((p.parent/'container.json').read_text())[0]
 h=c['HostConfig'];assert not h['Binds'] and h['NetworkMode']=='none' and not h['PidMode']
 data['container']={'image':c['Image'],'network':h['NetworkMode'],'pid_namespace':'private',
                    'cgroupns':h['CgroupnsMode'],'binds':h['Binds'],'privileged':h['Privileged']}
 return data
def main():
 result={'research':'R1','base':'d1b00069aa9982fea3d7a34ea11eeaabe1c3604b',
 'engine':'Docker explicitly authorized; real systemd PID 1; shared WSL kernel',
 'scope':'research only; collection complete is not production adapter support',
 'profiles':{},'coverage':{
 'functional_auth':{'status':'NOT_TESTED','reason':'R1 proves configuration/launch only'},
 'enforcing_lsm':{'status':'NOT_TESTED','reason':'No enforcing-label environment'},
 'peer_propagation':{'status':'NOT_TESTED','reason':'Private container topology, existing engine guards retained'},
 'enumeration_race':{'status':'NOT_TESTED','reason':'Late-after-snapshot checkpoint is not concurrent enumeration'},
 'unit_mutation':{'status':'NOT_TESTED','reason':'Only environment-file mutation injected'},
 'readiness_timeout':{'status':'INCONCLUSIVE','reason':'Stopped monitor restart exceeded outer harness deadline; no bounded cleanup claim'}},
 'source_evidence':'tests/integration/sssd-research/source-r1.json'}
 for profile in PROFILES:
  stages={stage:load(profile,stage) for stage in ('R1','R1_MORE','R1_ABSENT')}
  e=stages['R1']['experiments'];m=stages['R1_MORE']['experiments']
  assert e['stock-active']['state']['ActiveState']=='active'
  assert e['stock-ro-prepared']['runtime']['state']['ActiveState']=='active'
  assert 'offline_credentials_expiration: 33' in e['lexical-precedence']['runtime']['configdb']['stdout']
  engine=e['stock-active-engine']['result']
  supported=profile in ('debian-13','ubuntu-26.04')
  assert engine['status']==('Success' if supported else 'UnsupportedConfiguration')
  claims={
   'stock_notify_configuration_start':{'status':'PASS','level':'NATIVE_RUNTIME_CONFIRMED','experiment':'R1/stock-active','limits':'offline loopback LDAP, not authentication'},
   'prepared_ro_native_restart':{'status':'PASS','level':'NATIVE_RUNTIME_CONFIRMED','experiment':'R1/stock-ro-prepared'},
   'public_engine_snapshot_notify':{'status':'PASS' if supported else 'UNSUPPORTED','level':'NATIVE_RUNTIME_CONFIRMED','experiment':'R1/stock-active-engine','diagnostic':engine['diagnostic']},
   'policy_success_from_generic_success_alone':{'status':'FAIL' if supported else 'UNSUPPORTED','level':'NATIVE_RUNTIME_CONFIRMED','reason':'No P or consumer proof; see hidden persistent drift checkpoints' if supported else 'launch rejected before publication'}}
  result['profiles'][profile]={'claims':claims,'stages':stages}
 (ROOT/'docs/sssd-native-research-evidence.json').write_text(json.dumps(result,indent=2)+'\n')
if __name__=='__main__':main()
