"""Disposable-container research helpers; no FIC production mutation."""
import hashlib,json,os,signal,subprocess,time
from pathlib import Path
OUT=Path('/run/sssd-research-out');MAIN=Path('/etc/sssd/sssd.conf');DROP=MAIN.parent/'conf.d'
assert os.environ.get('FIC_SSSD_RESEARCH')=='1' and Path('/.dockerenv').exists()
assert Path('/proc/1/comm').read_text().strip()=='systemd'
assert os.stat('/proc/self/ns/mnt').st_ino!=int(os.environ['FIC_SSSD_HOST_MNT'])
assert {p.name for p in Path('/sys/class/net').iterdir()}=={'lo'}
OUT.mkdir(exist_ok=True)
report={'commands':[],'experiments':{}}
def save(): (OUT/'results.json').write_text(json.dumps(report,indent=2))
def run(args,timeout=30,input=None):
 try:
  p=subprocess.run(args,input=input,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
  r={'command':args,'exit_code':p.returncode,'stdout':p.stdout[-48000:],'stderr':p.stderr[-24000:]}
 except subprocess.TimeoutExpired as e:
  r={'command':args,'exit_code':None,'timed_out':True,'stdout':str(e.stdout or '')[-1000:],'stderr':str(e.stderr or '')[-1000:]}
 report['commands'].append(r);save();return r

def ctl(*args,**kw):return run(['systemctl',*args],**kw)
def state():
 r=ctl('show','sssd.service','-p','Id','-p','ActiveState','-p','SubState','-p','Result','-p','MainPID','-p','InvocationID','-p','Job','-p','ActiveEnterTimestampMonotonic','-p','ExecMainStartTimestampMonotonic')
 return dict(line.split('=',1) for line in r['stdout'].splitlines() if '=' in line)
def write(p,text,mode=0o600):
 p=Path(p);p.parent.mkdir(exist_ok=True,parents=True);p.write_text(text);p.chmod(mode)
def base(offline=30,account=0,cache='true',services='nss, pam',provider='ldap'):
 domain=f'id_provider = {provider}\n'
 if provider=='ldap':domain+='auth_provider = ldap\nldap_uri = ldap://127.0.0.1:9\nldap_search_base = dc=example,dc=test\n'
 elif provider=='ad':domain+='ad_domain = example.test\nkrb5_realm = EXAMPLE.TEST\n'
 elif provider=='ipa':domain+='ipa_domain = example.test\nipa_server = 127.0.0.1\nipa_hostname = client.example.test\n'
 elif provider=='proxy':domain+='proxy_lib_name = files\nauth_provider = proxy\nproxy_pam_target = sssd-research\n'
 return f'[sssd]\nservices = {services}\ndomains = test\ndebug_level = 9\n[pam]\noffline_credentials_expiration = {offline}\ndebug_level = 9\n[domain/test]\n{domain}cache_credentials = {cache}\naccount_cache_expiration = {account}\ndebug_level = 9\n'
def configure(text=None):
 ctl('stop','sssd.service',timeout=35)
 ctl('reset-failed','sssd.service') # fixture isolation only; never a proposed production action
 # Stop only native SSSD responder socket units inside the disposable fixture.
 sockets=run(['systemctl','list-unit-files','--no-legend','sssd*.socket'])['stdout']
 for line in sockets.splitlines():
  if line.split() and line.split()[0].endswith('.socket'):ctl('stop',line.split()[0])
 DROP.mkdir(exist_ok=True,parents=True)
 for p in DROP.iterdir():
  if p.is_file() or p.is_symlink():p.unlink()
 write(MAIN,base() if text is None else text)
def configdb():
 p=Path('/var/lib/sss/db/config.ldb')
 return run(['ldbsearch','-H',str(p),'-b','cn=config']) if p.exists() else {'absent':True}
def processes():
 rows=[]
 for p in Path('/proc').iterdir():
  if not p.name.isdigit():continue
  try:
   cmd=(p/'cmdline').read_bytes().replace(b'\0',b' ').decode(errors='replace')
   if '/sssd' in cmd and int(p.name)!=os.getpid():rows.append({'pid':int(p.name),'cmd':cmd,'mount_ns':os.readlink(p/'ns/mnt')})
  except (OSError,PermissionError):pass
 return rows
def observe_start():
 started=ctl('restart','sssd.service',timeout=40)
 return {'restart':started,'state':state(),'configdb':configdb(),'processes':processes()}
def experiment(name,observation):
 report['experiments'][name]=observation;save();print(name,flush=True)
def check_config(*args):return run(['sssctl','config-check',*args])
def generic(**options):
 paths=[]
 for p in (MAIN,DROP,Path("/etc/sysconfig/sssd") if Path("/etc/altlinux-release").exists() else Path("/etc/default/sssd")):
  if not p.exists():continue
  if p.is_dir():paths.append({'path':str(p),'directory':True,'manifest':{str(q.relative_to(p)):hashlib.sha256(q.read_bytes()).hexdigest() for q in p.rglob('*') if q.is_file()}})
  else:paths.append({'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()})
 request={'paths':paths,**options}
 req=OUT/'engine-request.json';req.write_text(json.dumps(request))
 r=run(['/usr/local/bin/sssd-engine-probe',str(req)],timeout=20)
 r['request']=request
 try:r['result']=json.loads(r['stdout'])
 except ValueError:pass
 return r
