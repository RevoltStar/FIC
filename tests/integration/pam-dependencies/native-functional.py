#!/usr/bin/env python3
"""I6 disposable native consumers over the existing production driver. No host use."""
import hashlib,json,os,pathlib,re,subprocess,sys,fcntl,glob
P=pathlib.Path
assert P('/.dockerenv').exists() and os.geteuid()==0
out=P('/evidence');out.mkdir(exist_ok=True)
report={'platform':sys.argv[1],'base':os.environ['FIC_I6_BASE'],'source_sha256':os.environ.get('FIC_I6_SOURCE'),'driver_sha256':hashlib.sha256(P('/build/tests/pam_dependency_contract_tests').read_bytes()).hexdigest(),'consumer_sha256':hashlib.sha256(P('/tmp/fic-i6-probe').read_bytes()).hexdigest(),'levels':['L2 production classes','L3 Linux-PAM'],'installed_L4':'BLOCKED: no daemon/systemd lifecycle exercised','scenarios':[],'parameters':[]}
seq=0

def command(args,env=None):
 r=subprocess.run(args,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=90)
 return r

def save(): (out/'functional.json').write_text(json.dumps(report,indent=2)+'\n')
def action(label,request,expected=True):
 global seq
 seq+=1;P('/var/tmp/fic-pam-i6-request.json').write_text(json.dumps(request))
 path=out/f'action-{seq}.json';r=command(['/build/tests/pam_dependency_contract_tests','--functional-i6',str(path)])
 (out/f'action-{seq}.log').write_text(r.stdout+r.stderr)
 result=json.loads(path.read_text())['functional'] if r.returncode==0 else {'ok':False,'error':r.stderr}
 row={'name':label,'level':'L2','expected':expected,'actual':result.get('ok',False),'exit':r.returncode,'request':request,'artifact':path.name}
 row['status']='PASS' if row['actual']==expected else 'FAIL';report['scenarios'].append(row);save()
 if row['status']=='FAIL':raise RuntimeError(label+': '+str({k:v for k,v in result.items() if k not in {'config','journal'}}))
 return result

def config(statuses={},values={}):return action('configure',{'action':'configure','statuses':statuses,'values':values})
def apply(name,expected=True):return action('apply '+name,{'action':'apply','policy':name},expected)
def rollback(name):return action('rollback '+name,{'action':'rollback','policy':name})
user='fici6user';current=''
def digest():
 raw=subprocess.check_output(['getent','shadow',user])
 return hashlib.sha256(raw.split(b':')[1]).hexdigest()
def probe(label,password,expected=True,auth=False,root=False):
 global current
 before=digest();env=dict(os.environ,FIC_GATE_PW=password,FIC_GATE_CURRENT=current,LC_ALL='C')
 if auth:env['FIC_GATE_AUTH']='1';env['FIC_GATE_SERVICE']='login'
 else:env.pop('FIC_GATE_AUTH',None)
 args=['/tmp/fic-i6-probe',user]
 if not root:args=['runuser','-u',user,'--']+args
 r=command(args,env);after=digest()
 ok=(r.returncode==0)==expected and (auth or ((before!=after)==expected))
 row={'name':label,'level':'L3','service':'login' if auth else 'passwd','expected_success':expected,'exit':r.returncode,'hash_changed':before!=after,'hash_before_sha256':before,'hash_after_sha256':after,'consumer':r.stdout.strip(),'status':'PASS' if ok else 'FAIL'}
 report['scenarios'].append(row);save()
 if not ok:raise RuntimeError(label+': '+r.stdout+r.stderr)
 if not auth and expected:current=password
 return row
try:
 r=command(['/tmp/fic-i6-probe','--conversation-test']);assert r.returncode==0;r=command(['useradd','-m','-c','RainbowExample',user]);assert r.returncode==0,r.stderr
 current='Orchard!29#InitialQz'
 r=subprocess.run(['chpasswd'],input=user+':'+current+'\n',text=True,capture_output=True);assert r.returncode==0,r.stderr
 # Preserve the installed baseline: never synthesize a stock service.
 report['os_release']=P('/etc/os-release').read_text()
 report['services']={p:P('/etc/pam.d/'+p).exists() for p in ['passwd','login','sshd','sudo','su','sddm','gdm-password','lightdm']}
 for name in ['passwd','login']:
  if not report['services'][name]:raise RuntimeError('BLOCKED missing installed service '+name)
 action('bootstrap',{'action':'bootstrap'})
 audit=command(['/build/tests/pam_dependency_contract_tests','--audit',str(out/'audit.json')]);assert audit.returncode==0,audit.stderr
 policies=json.loads((out/'audit.json').read_text())['policies'];names=[p['name'] for p in policies if p['registered']]
 caps=['enable_password_quality','enable_password_history','enable_authentication_lockout']
 config({n:'DISABLE' for n in names+caps})
 probe('baseline password change','Harbor!48#BaselineZq')
 probe('baseline correct authentication',current,auth=True)
 probe('baseline incorrect authentication','Wrong!39#CredentialQz',False,auth=True)
 first_quality=next(p['name'] for p in policies if p['registered'] and p['activation']==caps[0])
 config({first_quality:'ENABLE'})
 apply(first_quality,False)  # real Required Disabled suppression
 config({caps[0]:'ENABLE'})
 module='pam_passwdqc.so' if report['platform']=='alt-p11' else 'pam_pwquality.so'
 candidates=glob.glob('/lib*/security/'+module)+glob.glob('/lib/*/security/'+module)+glob.glob('/usr/lib*/security/'+module)
 if not candidates:raise RuntimeError('BLOCKED provider module absent before negative control')
 module_path=P(candidates[0]).resolve();hidden=P(str(module_path)+'.i6-hidden')
 module_path.rename(hidden)
 try:apply(first_quality,False)  # Failed activation suppresses parameter
 finally:hidden.rename(module_path)
 config({first_quality:'DISABLE'})
 apply(caps[0]);apply(caps[0])
 values={'password_min_length':'14','password_min_classes':'3','password_min_changed_characters':'1','password_min_lowercase':'1','password_min_uppercase':'1','password_min_digits':'1','password_min_other':'1','password_check_username':'yes','password_check_gecos':'yes','password_quality_enforce_for_root':'yes','password_history_depth':'2','password_history_enforce_for_root':'yes','failed_authentication_attempts':'3','failed_authentication_counting_period':'60','failed_authentication_unlock_time':'60','failed_authentication_enforce_for_root':'no','passwdqc_strength_thresholds':'disabled,24,16,14,14','passwdqc_passphrase_words':'3','passwdqc_match_length':'4','passwdqc_similar_password':'deny','passwdqc_retry_count':'1'}
 alternatives={n:('no' if v=='yes' else 'yes' if v=='no' else str(int(v)+1) if v.isdigit() else 'permit' if v=='deny' else 'disabled,26,18,16,16') for n,v in values.items()}
 def parameter(n):
  config({n:'ENABLE'},{n:values[n]});apply(n);apply(n)
  config({n:'ENABLE'},{n:alternatives[n]});apply(n)
  config({n:'ENABLE'},{n:values[n]});apply(n)
  report['parameters'].append(n)
 qnames=[p['name'] for p in policies if p['registered'] and p['activation']==caps[0]]
 for n in qnames:
  parameter(n)
 probe('quality positive','Cascade!72#QuantumVx')
 probe('quality weak rejected','abc',False)
 if report['platform']!='alt-p11':
  credits=['password_min_lowercase','password_min_uppercase','password_min_digits','password_min_other']
  for n in credits:config({n:'ENABLE'},{n:'0'});apply(n)
  config({'password_min_classes':'ENABLE'},{'password_min_classes':'4'});apply('password_min_classes')
  probe('quality classes rejected','XqvMnp!RtzWkb#Lsf',False)
  config({'password_min_classes':'ENABLE'},{'password_min_classes':'3'});apply('password_min_classes')
  probe('quality classes relaxed accepted','XqvMnp!RtzWkb#Lsf')
  for n in credits:config({n:'ENABLE'},{n:'1'});apply(n)
  probe('quality credits positive','Helix!47#ZqvMntR')
  probe('quality missing digit rejected','Distant!Mountain#Sky',False)
  probe('quality username rejected','fici6user!74#SkylarkV',False)
  probe('quality gecos rejected','RainbowExample!74#Rv',False)
  config({'password_min_changed_characters':'ENABLE'},{'password_min_changed_characters':'8'});apply('password_min_changed_characters')
  probe('quality difok small edit rejected',current[:-1]+'Y',False)
  config({'password_min_changed_characters':'ENABLE'},{'password_min_changed_characters':'1'});apply('password_min_changed_characters')
 else:
  probe('passwdqc similar-match rejected',current[:-1]+'Y',False)
 # Root real UID differential: same weak token is permitted only while
 # production root enforcement is disabled. Target user is never root.
 config({'password_quality_enforce_for_root':'ENABLE'},{'password_quality_enforce_for_root':'no'});apply('password_quality_enforce_for_root')
 probe('quality root bypass positive','abc',root=True)
 config({'password_quality_enforce_for_root':'ENABLE'},{'password_quality_enforce_for_root':'yes'});apply('password_quality_enforce_for_root')
 probe('quality root enforce negative','xyz',False,root=True)
 probe('quality root restore strong token','Nebula!92#GoldMosaic',root=True)
 # A min-length refresh must change a real consumer outcome, not just text.
 target='passwdqc_strength_thresholds' if report['platform']=='alt-p11' else 'password_min_length'
 config({target:'ENABLE'},{target:'disabled,32,28,28,28' if target.startswith('passwdqc') else '28'});apply(target)
 probe('quality refresh short candidate rejected','Zephyr!91#NewAx',False)
 config({target:'ENABLE'},{target:values[target]});apply(target)
 probe('quality refresh relaxed candidate accepted','Zephyr!91#NewAx')
 config({caps[1]:'ENABLE'});apply(caps[1])
 for n in ['password_history_depth','password_history_enforce_for_root']:
  parameter(n)
 a='Meadow!51#PurpleJv';b='Volcano!83#SilverKx'
 probe('quality+history first change',a);probe('quality+history second change',b)
 probe('quality+history reuse rejected',a,False)
 config({'password_history_depth':'ENABLE'},{'password_history_depth':'3'});apply('password_history_depth')
 for token in ['Lagoon!69#QuartzBx','Tempest!34#RubyNq','Canyon!95#VioletPx','Boreal!23#JasperZv']:
  probe('history refreshed window advance',token)
 probe('history token beyond refreshed window accepted',a)
 recent='Boreal!23#JasperZv'
 probe('history root enforced positive-control rejection',recent,False,root=True)
 config({'password_history_enforce_for_root':'ENABLE'},{'password_history_enforce_for_root':'no'});apply('password_history_enforce_for_root')
 probe('history root bypass reuse',recent,root=True)
 config({'password_history_enforce_for_root':'ENABLE'},{'password_history_enforce_for_root':'yes'});apply('password_history_enforce_for_root')
 prior_root=current
 probe('history root fresh positive control','Marble!61#IvoryQz',root=True)
 probe('history root enforce reuse rejected',prior_root,False,root=True)
 if report['platform']=='alt-p11':
  with open('/var/lib/fic-pwhistory/.lock','r+') as lock:
   fcntl.lockf(lock,fcntl.LOCK_EX)
   probe('ALT pwtxn locked rejection','Monsoon!73#OpalYz',False)
  probe('ALT pwtxn after unlock','Monsoon!73#OpalYz')
 # Semantic release of quality while history survives (C2 consumer→initial).
 for n in qnames:rollback(n);config({n:'DISABLE'})
 rollback(caps[0]);config({caps[0]:'DISABLE'})
 prior_history=current
 probe('history-only new token','Glacier!46#AmberNx')
 probe('history-only reuse rejected',prior_history,False)
 config({caps[0]:'ENABLE'});apply(caps[0]);apply('password_history_depth')
 config({caps[2]:'ENABLE'});apply(caps[2])
 for n in ['failed_authentication_attempts','failed_authentication_counting_period','failed_authentication_unlock_time','failed_authentication_enforce_for_root']:
  parameter(n)
 probe('combined correct authentication',current,auth=True)
 for i in range(3):probe('combined wrong authentication '+str(i),'Incorrect!42#TokenVx',False,auth=True)
 counter=command(['faillock','--user',user]);(out/'faillock-before-reset.txt').write_text(counter.stdout+counter.stderr)
 assert counter.returncode==0 and user in counter.stdout
 probe('combined correct password blocked',current,False,auth=True)
 reset=command(['faillock','--user',user,'--reset']);assert reset.returncode==0
 probe('combined after explicit reset',current,auth=True)
 if report['platform']=='alt-p11':
  config({caps[2]:'ENABLE'},{caps[2]:'preauth_requisite'});apply(caps[2])
  probe('ALT requisite correct authentication',current,auth=True)
  for i in range(3):probe('ALT requisite wrong '+str(i),'Incorrect!42#TokenVx',False,auth=True)
  probe('ALT requisite correct blocked',current,False,auth=True)
  assert command(['faillock','--user',user,'--reset']).returncode==0
  probe('ALT requisite after reset',current,auth=True)
 prior=current
 probe('combined new password','Aurora!57#CopperTz')
 probe('combined weak password rejected','abc',False)
 probe('combined recent password rejected',prior,False)
 rollback(caps[0]);config({caps[0]:'DISABLE'})
 probe('history+lockout authentication',current,auth=True)
 prior=current;probe('history+lockout new password','Granite!38#EmeraldKy')
 probe('history+lockout reuse rejected',prior,False)
 for n in ['password_history_depth','password_history_enforce_for_root']:
  rollback(n);config({n:'DISABLE'})
 rollback(caps[1]);config({caps[1]:'DISABLE'})
 config({caps[0]:'ENABLE'});apply(caps[0])
 probe('quality+lockout authentication',current,auth=True)
 probe('quality+lockout new password','Tundra!64#BronzeWv')
 probe('quality+lockout weak rejected','a',False)

 # Rollback parameters before activation; disable intent only after release.
 for n in reversed(report['parameters']):
  if n in qnames:continue
  rollback(n);config({n:'DISABLE'})
 for c in [caps[2],caps[1],caps[0]]:
  rollback(c);config({c:'DISABLE'});rollback(c)
 probe('post-release password change','Summit!68#NativeGw')
 probe('post-release authentication',current,auth=True)
 if report['platform']!='alt-p11':
  native=command(['pam-auth-update','--enable','pwquality']);assert native.returncode==0
  foreign=P('/etc/pam.d/common-password').read_bytes()
  config({caps[0]:'ENABLE'});observed=apply(caps[0])
  records=json.loads(observed['journal'])['records']
  assert not any(r['policy']['policy']==caps[0] and r['status'] in ['applied','prepared','rollback_failed'] for r in records)
  rollback(caps[0]);config({caps[0]:'DISABLE'})
  assert P('/etc/pam.d/common-password').read_bytes()==foreign
  probe('foreign quality remains enforced after release','a',False)
 report['status']='PASS measured scenarios only'
except Exception as e:
 report['status']='FAIL';report['error']=str(e);save();print(str(e),file=sys.stderr);sys.exit(1)
finally:save()
