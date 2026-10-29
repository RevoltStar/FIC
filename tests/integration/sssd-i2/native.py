"""I2 native semantic comparison. All writes/service jobs are fixture-only."""
from common import *
import re,sys
platform=sys.argv[1]
def fixture(text=None):
 text=base(offline=0) if text is None else text
 return text.replace('[sssd]\n','[sssd]\nuser=_sssd\n') if platform=='alt-p11' else text
def probe(*args):
 r=run(['/usr/local/bin/sssd-i2-probe',*args],timeout=40)
 assert r['exit_code']==0,r
 return json.loads(r['stdout'])
def logs():
 return {p.name:'\n'.join(line for line in p.read_text(errors='replace').splitlines() if re.search(r'Conflicting|larger|EINVAL|Invalid argument|initializ|Failed|failed|cache_credentials|expiration|enabled',line,re.I))[-14000:] for p in Path('/var/log/sssd').glob('*.log')}
def assess(name,text,expected,startup=None):
 # Establish a native running baseline, then evaluate the NEW persistent graph.
 configure(fixture());ready=observe_start();assert ready['state']['ActiveState']=='active',ready
 text=fixture(text);write(MAIN,text)
 before=state();x=probe();after=state()
 assert before['MainPID']==after['MainPID'] and before['InvocationID']==after['InvocationID'],(before,after)
 observed={'configuration':text,'computed':x,'config_check':check_config('-c',str(MAIN),'-s',str(DROP)),
           'semantic_proof':'EXPECTED_PROJECTION_ONLY','functional_auth':'NOT_TESTED'}
 assert x['status']=='PROJECTED' and x['semantic_status']==expected,(name,x)
 if startup is not None:
  for p in Path('/var/log/sssd').glob('*.log'):p.unlink()
  actual=observe_start();observed['native']=actual;observed['logs']=logs()
  assert (actual['state']['ActiveState']=='active')==startup,(name,actual,observed['logs'])
 else:observed['native_status']='NOT_TESTED: no valid realm/trust/runtime claim for this scenario'
 experiment(name,observed)
 return observed
experiment('platform',{'platform':platform,'version':run(['sssd','--version']),
 'packages':run(['rpm','-q','--qf','%{NAME} %{VERSION}-%{RELEASE}\n','sssd','sssd-tools','systemd'] if platform=='alt-p11' else ['dpkg-query','-W','-f','${binary:Package} ${Version}\n','sssd-common','sssd-tools','systemd']),
 'os_release':Path('/etc/os-release').read_text(),'kernel':run(['uname','-r'])})
assess('one-ldap',base(offline=0),'Validated',True)
assess('ldap-default-auth',base(offline=0).replace('auth_provider = ldap\n',''),'Validated',True)
other='\n[domain/other]\nid_provider=ldap\nauth_provider=ldap\nldap_uri=ldap://127.0.0.1:9\nldap_search_base=dc=example,dc=test\n'
two=base(offline=0).replace('domains = test','domains = test, other')+other
r=assess('two-ldap',two,'Validated',True)
assert r['computed']['selected']==['test','other']
assess('two-ldap-one-conflict',two.replace('offline_credentials_expiration = 0','offline_credentials_expiration = 2')+'account_cache_expiration=1\n','Conflict',False)
proxy=other.replace('id_provider=ldap\nauth_provider=ldap','id_provider=proxy\nauth_provider=proxy\nproxy_lib_name=files\nproxy_pam_target=sssd-research')
assess('ldap-proxy',base(offline=0).replace('domains = test','domains = test, other')+proxy,'UnsupportedProvider',True)
r=assess('inactive-section',base(offline=0)+other+'account_cache_expiration=1\n','Validated',True)
assert r['computed']['unselected']==['other'] and r['computed']['expected_backends']==['test']
assert not any('--domain other' in p['cmd'] for p in r['native']['processes'])
assess('enabled-false',base(offline=0)+'enabled=false\n','UnsupportedConfiguration',False)
assess('enabled-true',base(offline=0)+'enabled=TRUE\n','Validated',True)
r=assess('auto-enabled-root',base(offline=0)+other+'enabled=true\n','UnsupportedConfiguration',True)
assert r['computed']['enabled']==['test','other']
assess('unknown-provider',base(offline=0).replace('id_provider = ldap','id_provider = unknown'),'UnsupportedProvider',False)
for p in ('ad','ipa'):
 r=assess('scope-'+p,base(offline=0,provider=p),'UnsupportedProvider')
 assert r['computed']['scope']['test']['dynamic_possible'] and r['computed']['scope']['test']['trusted_possible']
assess('dynamic-scope',base(offline=0)+'subdomain_inherit=cache_credentials\n','UnknownSemantics')
assess('trusted-child',base(offline=0)+'\n[domain/test/child]\nid_provider=ldap\n','UnknownSemantics')
for provider in ('ldap','proxy'):
 for offline,account in ((0,0),(0,1),(1,0),(1,1),(2,1),(1,2)):
  valid=account==0 or (offline>0 and account>=offline)
  expected=('Validated' if valid else 'Conflict') if provider=='ldap' else 'UnsupportedProvider'
  r=assess(f'relation-{provider}-{offline}-{account}',base(offline,account,provider=provider),expected,valid or provider=='proxy')
  assert r['config_check']['exit_code']==0,r
  assert f'offline_credentials_expiration: {offline}' in r['native']['configdb']['stdout'],r
  assert f'account_cache_expiration: {account}' in r['native']['configdb']['stdout'],r
  assert r['computed']['offline']['value']==offline and r['computed']['values']['test']['account']['value']==account
assess('relation-cache-false',base(0,1,cache='false'),'Conflict',False)
# Native default handling and boolean representations on each installed version.
text='\n'.join(line for line in base(offline=0).splitlines() if not line.startswith(('offline_credentials_expiration','cache_credentials','account_cache_expiration')))+'\n'
r=assess('native-defaults',text,'Validated',True)
assert r['computed']['offline']['origin']=='native-default' and r['computed']['values']['test']['cache']['value'] is False
for b in ('TRUE','False','yes'):
 assess('boolean-'+b,base(offline=0,cache=b),'UnsupportedConfiguration' if b=='yes' else 'Validated',b!='yes')
# New provider/domain/enablement/input generation invalidates the old reference.
for kind,text in [('domains',two),('provider',base(offline=0,provider='proxy')),('enabled',base(offline=0)+'enabled=false\n'),('same-scope-value',base(offline=0)+'cached_auth_timeout=12\n')]:
 configure(fixture());assert observe_start()['state']['ActiveState']=='active'
 candidate=Path('/run/i2-candidate.conf');write(candidate,fixture(text))
 x=probe('scope-change',str(candidate));experiment('scope-change-'+kind,x)
 assert x['status']=='PROJECTED' and not x['scope_unchanged'] and x['graph']!=x['next_graph'],x
experiment('result',{'status':'PASS','runtime_receipt':False,'completed_proofs':False,'scope':'I2 semantic projection; native startup/ConfigDB comparison, not consumer-generation proof'})
