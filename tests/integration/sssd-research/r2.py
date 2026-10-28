"""Native R2 semantics fixtures; all endpoints are disposable loopback only."""
from common import *
import re,sys
report.update(stage='R2',platform=sys.argv[1],r1_parent=os.environ.get('FIC_SSSD_R1_COMMIT','696a457'))
def logs():
 result={}
 for p in Path('/var/log/sssd').glob('*.log'):
  lines=p.read_text(errors='replace').splitlines()
  selected=[l for l in lines if re.search(r'Conflicting|must be larger|EINVAL|\[22\]|Invalid argument|initializ|cache_credentials|account_cache_expiration|offline_credentials_expiration|cached_auth_timeout|offline|online|domain.*enabled',l,re.I)]
  result[p.name]='\n'.join(selected[-90:])
 return result
def native(text):
 configure(text)
 for p in Path('/var/log/sssd').glob('*.log'):p.unlink()
 chk=check_config();start=ctl('start','--no-block','sssd.service')
 deadline=time.monotonic()+8
 while time.monotonic()<deadline:
  s=state()
  if s.get('ActiveState') in ('active','failed'):break
  time.sleep(.05)
 return {'config_check':chk,'start_job':start,'state':s,'configdb':configdb(),
         'domain_list':run(['sssctl','domain-list']),'processes':processes(),'logs':logs(),
         'observation':'bounded state sample; activating is not eventual failure proof'}
for provider in ('ldap','proxy'):
 for offline,account in ((0,0),(0,1),(1,0),(1,1),(2,1),(1,2)):
  experiment(f'relation-{provider}-{offline}-{account}',native(base(offline,account,provider=provider)))
experiment('relation-ldap-cache-false',native(base(0,1,cache='false')))
for field,value in (('offline',-1),('offline',3651),('offline',24856),('offline',2147483648),('offline','abc'),('account',-1),('account',2147483648),('account','abc'),('cache','invalid')):
 kw={field:value};experiment(f'range-{field}-{value}',native(base(**kw)))
text=base();text='\n'.join(l for l in text.splitlines() if not l.startswith(('offline_credentials_expiration','account_cache_expiration','cache_credentials')))+'\n'
experiment('omitted-options',native(text))
experiment('inactive-explicit-domain',native(base()+'\n[domain/inactive]\nid_provider=ldap\nldap_uri=ldap://127.0.0.1:9\nldap_search_base=dc=unused\ncache_credentials=false\naccount_cache_expiration=1\n'))
experiment('disabled-domain',native(base()+'enabled=false\n'))
mixed=base().replace('domains = test','domains = test, other')+'\n[domain/other]\nid_provider=proxy\nproxy_lib_name=files\nauth_provider=proxy\nproxy_pam_target=sssd-research\ncache_credentials=false\naccount_cache_expiration=1\n'
experiment('two-active-domains',native(mixed))
experiment('mixed-provider-domain-failure',native(mixed.replace('account_cache_expiration = 0','account_cache_expiration = 1')))
experiment('cached-auth-timeout-clamped-source-design',native(base(offline=1)+'cached_auth_timeout=172800\n'))
for provider in ('ad','ipa'):
 experiment('no-directory-'+provider,native(base(0,1,provider=provider)))
experiment('lazy-pam-before',native(base(services='nss')))
experiment('lazy-pam-socket-start',{'start':ctl('start','sssd-pam.socket','sssd-pam-priv.socket'),'state':state(),'processes':processes()})
# A nonexistent identity request can activate native PAM responder without
# claiming successful authentication. Uses a test-only PAM service, never host PAM.
write(Path('/etc/pam.d/sssd-research'),'auth required pam_sss.so\naccount required pam_sss.so\n',0o644)
experiment('lazy-pam-request',{'request':run(['python3','/usr/local/bin/pam-probe.py','absent-research-user@test'],timeout=15),'state':state(),'processes':processes()})
experiment('pam-client-libraries',run(['find','/lib','/usr/lib','/lib64','/usr/lib64','-name','libpam.so.0']))
report['collection_complete']=True;save()
print('R2 collection complete',report['platform'],flush=True)
