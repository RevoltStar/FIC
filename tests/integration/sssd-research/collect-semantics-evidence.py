#!/usr/bin/env python3
from pathlib import Path
import json,re,runpy
HERE=Path(__file__).resolve().parent
helpers=runpy.run_path(str(HERE/'collect-evidence.py'))
ROOT=helpers['ROOT'];load=helpers['load'];PROFILES=helpers['PROFILES']
result={'research':'R2','r1_commit':'696a4575e55b125617613fa212317c5b76636151',
 'scope':'research only; native installed SSSD, no production FIC changes',
 'source_evidence':'tests/integration/sssd-research/source-r2.json',
 'defaults':{'level':'SOURCE_CONFIRMED','offline_credentials_expiration':0,'cache_credentials':False,'account_cache_expiration':0,'cached_auth_timeout':0},
 'coverage':{
  'AD_IPA_functional':{'status':'NOT_TESTED','reason':'No real realm, keytab, trust directory; failed constructors do not test valid AD/IPA behavior'},
  'AD_IPA_relation':{'status':'INCONCLUSIVE','level':'SOURCE_CONFIRMED','reason':'Separate option-loading paths lack LDAP check; no valid native directory runtime'},
  'smartcard_passkey':{'status':'NOT_TESTED','level':'SOURCE_CONFIRMED','reason':'Source differences only, no hardware/real token'},
  'cleanup_days':{'status':'NOT_TESTED','level':'SOURCE_CONFIRMED','reason':'No periodic days-long account object deletion gate'},
  'cached_timeout_clamp_memory':{'status':'NOT_TESTED','level':'SOURCE_CONFIRMED','reason':'Load/start tested; domain memory not introspected'}},
 'profiles':{}}
for profile in PROFILES:
 stages={stage:load(profile,stage) for stage in ('R2','R2_AUTH','R2_LAZY')}
 if profile=='alt-p11':stages['R2_LAZY_ROOT']=load(profile,'R2_LAZY_ROOT')
 e=stages['R2']['experiments'];a=stages['R2_AUTH']['experiments'];lazy=stages['R2_LAZY']['experiments']
 matrix=[]
 for o,ac in ((0,0),(0,1),(1,0),(1,1),(2,1),(1,2)):
  valid=ac==0 or (o>0 and ac>=o)
  row={'offline':o,'account':ac,'relation_valid':valid,'providers':{}}
  for provider in ('ldap','proxy'):
   v=e[f'relation-{provider}-{o}-{ac}'];expect='active' if valid or provider=='proxy' else 'failed'
   assert v['config_check']['exit_code']==0 and v['state']['ActiveState']==expect,(profile,provider,o,ac)
   if not valid and provider=='ldap':assert re.search(r'\[22\]|Invalid argument',str(v['logs']))
   row['providers'][provider]={'status':'PASS','level':'NATIVE_RUNTIME_CONFIRMED',
    'condition':'observed native provider-specific acceptance/rejection, not functional login',
    'config_check_exit':v['config_check']['exit_code'],'state':v['state'],
    'expected_state':expect,'experiment':f'R2/relation-{provider}-{o}-{ac}'}
  matrix.append(row)
 for name in ('online-password','offline-password','aged-expiration-unlimited'):
  assert a[name]['exit_code']==0,(profile,name)
 for name in ('offline-cache-disabled-existing-db','aged-expiration-one-day','offline-wrong-password'):
  assert a[name]['exit_code']==1 and json.loads(a[name]['stdout'])['pam_authenticate']!=0
 assert a['cached-auth-while-ldap-online']['old_password_auth']['exit_code']==0
 assert a['cached-auth-while-ldap-online']['ldap_rejects_old_password']['exit_code']!=0
 after=a['cache-after-aged-offline']['stdout'];attrs=dict(re.findall(r'^(last\w+): (\d+)$',after,re.M))
 assert int(attrs['lastLogin'])-int(attrs['lastOnlineAuth'])>2*86400
 assert not any('sssd_pam' in p['cmd'] for p in lazy['monitor-ready-no-pam']['processes'])
 assert any('sssd_pam' in p['cmd'] for p in lazy['after-pam-request']['processes'])
 result['profiles'][profile]={'matrix':matrix,
  'functional_password_fixture':{'status':'PASS','level':'FUNCTIONAL_AUTH_CONFIRMED',
   'conditions':'one synthetic TLS LDAP user; real native pam_sss; aged timestamp injected only while stopped',
   'covered':['online seed','offline success','cache false rejection with existing DB','aged 1 day reject / 0 accept','online cached old password','offline lastLogin does not extend lastOnlineAuth']},
  'lazy_responder':{'status':'PASS','level':'NATIVE_RUNTIME_CONFIRMED','condition':'native unit with ALT packaged user=_sssd; nonexistent user is not authentication success'},
  'stages':stages}
(ROOT/'docs/sssd-semantics-research-evidence.json').write_text(json.dumps(result,indent=2)+'\n')
print('R2 export: five native matrices and five real LDAP/PAM fixtures validated')
