#!/usr/bin/env python3
"""ALT stock package research, not production policy acceptance."""
import hashlib,json,os,re,socket,subprocess,time
from pathlib import Path
ROOT=Path('/run/fic-alt-ssh-research');OUT=ROOT/'results'
MAIN=Path('/etc/openssh/sshd_config');ENV=Path('/etc/sysconfig/sshd')

def run(args,check=True):
 p=subprocess.run(args,text=True,capture_output=True,timeout=45)
 if check and p.returncode:raise RuntimeError(str(args[:2])+': '+p.stderr[:1000]+p.stdout[-1000:])
 return p

def ctl(*args,check=True):
 # Fixture-only reset between independent experiments; never proposed for FIC.
 if args and args[0] in ('start','restart'):run(['systemctl','reset-failed','sshd.service'],False)
 return run(['systemctl',*args],check)
def props():
 wanted=['Id','Names','UnitFileState','Type','NotifyAccess','ExecStart','ExecStartPre','ExecReload','PIDFile','EnvironmentFiles','Environment','Restart','KillMode','MainPID','InvocationID','ActiveState','SubState','Job','Result','FragmentPath','DropInPaths','TriggeredBy','StartLimitIntervalUSec','StartLimitBurst','ControlGroup']
 out={}
 for line in ctl('show','sshd.service','--property='+','.join(wanted)).stdout.splitlines():
  if '=' not in line:continue
  key,value=line.split('=',1)
  if key.startswith('Exec'):out.setdefault(key,[]).append(value)
  else:out[key]=value
 return out
def listeners():
 out=[]
 for name,family in [('tcp',socket.AF_INET),('tcp6',socket.AF_INET6)]:
  for line in Path('/proc/net/'+name).read_text().splitlines()[1:]:
   f=line.split()
   if f[3]!='0A':continue
   h,p=f[1].split(':');b=bytes.fromhex(h);b=b[::-1] if family==socket.AF_INET else b''.join(b[i:i+4][::-1] for i in range(0,16,4))
   out.append({'address':socket.inet_ntop(family,b),'port':int(p,16),'inode':int(f[9])})
 return out

def fds(pid):
 out=[]
 for p in Path('/proc/'+str(pid)+'/fd').glob('*'):
  try:link=os.readlink(p)
  except FileNotFoundError:continue
  m=re.fullmatch(r'socket:\[(\d+)\]',link)
  if m:out.append(int(m[1]))
 return out

def snap():
 p=props();return {'service':p,'listeners':listeners(),'sshd_fd_inodes':fds(p['MainPID']),'pid1_fd_inodes':fds(1),'process_exe':os.readlink('/proc/'+p['MainPID']+'/exe') if p['MainPID']!='0' else None}
def effective(*args):
 p=run(['/usr/sbin/sshd','-T',*args],False)
 keys={'port','listenaddress','permitrootlogin','pubkeyauthentication','usepam','maxauthtries','hostkey','pidfile','authorizedkeysfile','kbdinteractiveauthentication','pamservicename','printmotd'}
 return {'rc':p.returncode,'stderr':p.stderr[:1000],'values':[line for line in p.stdout.splitlines() if line.split(' ',1)[0] in keys]}
def connect(port,family=socket.AF_INET):
 with socket.socket(family) as s:
  s.settimeout(4);s.connect(('127.0.0.1' if family==socket.AF_INET else '::1',port));banner=s.recv(256);assert banner.startswith(b'SSH-2.0-');return banner.decode().strip()
def wait(port):
 deadline=time.monotonic()+10
 while time.monotonic()<deadline:
  s=props()
  if s['ActiveState']=='active' and s['SubState']=='running' and not s['Job']:
   try:return connect(port)
   except (OSError,AssertionError):pass
  time.sleep(.03)
 raise RuntimeError('stock readiness not confirmed')
def guard():
 assert os.geteuid()==0 and os.environ.get('FIC_ALT_RESEARCH') and Path('/.dockerenv').exists()
 assert Path('/proc/1/comm').read_text()=='systemd\n'
 a=os.stat('/proc/self/ns/mnt');b=os.stat('/proc/1/ns/mnt');r=os.stat('/')
 assert (a.st_dev,a.st_ino)==(b.st_dev,b.st_ino) and f'{a.st_dev}:{a.st_ino}'!=os.environ['FIC_ALT_HOST_NS']
 assert f'{r.st_dev}:{r.st_ino}'!=os.environ['FIC_ALT_HOST_ROOT']
 assert sorted(p.name for p in Path('/sys/class/net').iterdir())==['lo']
def main():
 guard();OUT.mkdir(parents=True)
 report={'cases':{},'kernel':os.uname().release,'os_release':Path('/etc/os-release').read_text()}
 def save():(OUT/'report.json').write_text(json.dumps(report,indent=2))
 def record(name,value):report['cases'][name]=value;save()
 stock=MAIN.read_text();stockenv=ENV.read_text()
 report['packages']=run(['rpm','-q','openssh-server','openssh-common','openssh-clients','systemd']).stdout
 report['rpm_verify']=run(['rpm','-V','openssh-server','openssh-common']).stdout
 report['package_owners']=run(['rpm','-qf','/usr/sbin/sshd','/usr/bin/ssh-keygen','/usr/lib/systemd/system/sshd.service',str(MAIN),str(ENV)]).stdout
 report['unit']=Path('/usr/lib/systemd/system/sshd.service').read_text();report['stock_config']=stock;report['stock_environment']=stockenv
 report['binary_sha256']={p:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in ['/usr/sbin/sshd','/usr/bin/ssh-keygen']}
 report['libraries']=run(['ldd','/usr/sbin/sshd']).stdout
 report['source_rpm']=run(['rpm','-q','--qf','%{SOURCERPM}\n','openssh-server']).stdout
 report['changelog']=run(['rpm','-q','--changelog','openssh-server']).stdout[:7000]
 report['socket_units']=[str(p) for p in Path('/usr/lib/systemd/system').glob('*ssh*.socket')]
 # Existing audit image had unowned empty .d fixture dirs. Record and remove,
 # rather than misrepresent them as package defaults or create them for ALT.
 report['unowned_server_directory']={'rpm_query':run(['rpm','-qf',str(MAIN.parent/'sshd_config.d')],False).stdout,
  'entries':{str(p):os.readlink(p) if p.is_symlink() else 'regular/directory' for p in (MAIN.parent/'sshd_config.d').iterdir()}}
 report['systemd_sshd_extension']=run(['rpm','-qf','/etc/openssh/sshd_config.d/20-systemd-userdb.conf','/usr/lib/systemd/sshd_config.d/20-systemd-userdb.conf'],False).stdout
 ctl('stop','sshd.service',check=False);ctl('enable','sshd.service')
 try:
  record('before-first-start',{'effective':effective(),'syntax_rc':run(['/usr/sbin/sshd','-t'],False).returncode})
  ctl('start','sshd.service');wait(22)
  record('stock-enabled-active',snap());assert props()['Type']=='simple' and props()['NotifyAccess']=='none'
  record('stock-effective',effective());record('stock-connection-context',effective('-C','user=root,host=localhost,addr=127.0.0.1'))
  report['host_keys']=[{'path':str(p),'mode':oct(p.stat().st_mode&0o777),'uid':p.stat().st_uid,'gid':p.stat().st_gid} for p in sorted(MAIN.parent.glob('ssh_host_*_key*'))]
  assert len(report['host_keys'])>=6
  old=snap();record('stock-restart-before',old);ctl('restart','sshd.service');wait(22);new=snap();record('stock-restart-after',new)
  assert old['service']['InvocationID']!=new['service']['InvocationID'] and old['service']['MainPID']!=new['service']['MainPID']
  assert not {i['inode'] for i in old['listeners']}&{i['inode'] for i in new['listeners']}
  assert {i['inode'] for i in new['listeners']}<=set(new['sshd_fd_inodes']) and not set(new['sshd_fd_inodes'])&set(new['pid1_fd_inodes'])
  assignments=[('PermitRootLogin','no'),('PubkeyAuthentication','yes'),('UsePAM','yes'),('MaxAuthTries','3'),('Port','2244')]
  for keyword,value in assignments:
   MAIN.write_text(keyword+' '+value+'\n'+stock);ctl('restart','sshd.service');port=2244 if keyword=='Port' else 22;wait(port)
   record('native-policy-'+keyword,{'effective':effective(),'runtime':snap(),'banner':connect(port)})
   assert {i['port'] for i in listeners()}=={port}
  # Native Include mechanism, optional administrator-created directory, never
  # represented as a shipped ALT .d convention.
  admin=MAIN.parent/'sshd_config.local.d';admin.mkdir();(admin/'nested').mkdir()
  (admin/'10.conf').write_text('Include /etc/openssh/sshd_config.local.d/nested/leaf.inc\n');(admin/'nested/leaf.inc').write_text('Port 2255\n')
  MAIN.write_text('Include /etc/openssh/sshd_config.local.d/*.conf\n'+stock);ctl('restart','sshd.service');wait(2255)
  record('administrator-recursive-Include',{'effective':effective(),'runtime':snap()})
  MAIN.write_text('Include sshd_config.local.d/*.conf\n'+stock)
  record('relative-Include-base',effective());assert 'port 2255' in effective()['values']
  MAIN.write_text('PermitRootLogin no\nMatch User root\n PermitRootLogin yes\n')
  record('Match-global',effective());record('Match-root',effective('-C','user=root,host=localhost,addr=127.0.0.1'))
  assert 'permitrootlogin yes' in effective('-C','user=root,host=localhost,addr=127.0.0.1')['values']
  MAIN.write_text(stock)
  for opts in ['','-p 2266','-o PermitRootLogin=yes','-f /etc/openssh/sshd_config.local.d/alternate.conf']:
   (admin/'alternate.conf').write_text('Port 2277\n');ENV.write_text('EXTRAOPTIONS='+opts+'\n');ctl('restart','sshd.service');port=2266 if opts.startswith('-p') else 2277 if opts.startswith('-f') else 22;wait(port)
   record('EXTRAOPTIONS-'+(opts or 'empty'),snap())
  ENV.write_text(stockenv);MAIN.write_text(stock);ctl('restart','sshd.service');wait(22)
  # A single-file research RO bind demonstrates visibility of the same path;
  # it is deliberately not a second production snapshot engine.
  ctl('stop','sshd.service');MAIN.write_text('Port 2288\n'+stock)
  fd=os.open(MAIN,os.O_RDWR);snapshot=ROOT/'ro';snapshot.mkdir();run(['mount','-t','tmpfs','-o','size=1m,mode=0700','fic-alt-research',str(snapshot)])
  (snapshot/'main').write_bytes(MAIN.read_bytes());run(['mount','-o','remount,ro',str(snapshot)]);run(['mount','--bind',str(snapshot/'main'),str(MAIN)])
  try:
   os.ftruncate(fd,0);os.write(fd,('Port 2299\n'+stock).encode());ctl('start','sshd.service');wait(2288);record('protected-main-old-fd-persistent-change',{'effective':effective(),'runtime':snap()});assert {i['port'] for i in listeners()}=={2288}
  finally:run(['umount',str(MAIN)]);os.close(fd);run(['umount',str(snapshot)])
  assert 'Port 2299' in MAIN.read_text();record('after-cleanup-persistent-change',{'effective':effective(),'runtime':snap()})
  ctl('stop','sshd.service');MAIN.write_text(stock);record('enabled-inactive',props())
  MAIN.write_text('InvalidFicResearchDirective yes\n');ctl('start','sshd.service',check=False);record('start-invalid-configuration',props());ctl('stop','sshd.service',check=False)
  MAIN.write_text(stock);ctl('reset-failed','sshd.service');ctl('start','sshd.service');wait(22);ctl('disable','sshd.service');record('disabled-active',snap());assert props()['UnitFileState']=='disabled'
  ctl('stop','sshd.service');ctl('mask','sshd.service');record('masked',props());ctl('unmask','sshd.service');ctl('enable','sshd.service')
  # Observe the real pending stop/restart using a ptrace event-stop barrier.
  import ctypes,signal
  ctl('start','sshd.service');wait(22);old_pid=int(props()['MainPID']);libc=ctypes.CDLL(None,use_errno=True)
  assert libc.ptrace(0x4206,old_pid,None,None)==0
  assert libc.ptrace(0x4207,old_pid,None,None)==0
  assert os.WIFSTOPPED(os.waitpid(old_pid,0x40000000)[1])
  try:
   ctl('restart','--no-block','sshd.service');deadline=time.monotonic()+5
   while props()['ActiveState']!='deactivating':
    assert time.monotonic()<deadline;time.sleep(.01)
   record('pending-restart-barrier',props())
  finally:assert libc.ptrace(17,old_pid,None,signal.SIGTERM)==0
  wait(22);record('pending-restart-recovered',snap())
  MAIN.write_text('InvalidFicResearchDirective yes\n');ctl('stop','sshd.service');ctl('start','sshd.service',check=False)
  observed=[];deadline=time.monotonic()+3
  while time.monotonic()<deadline:
   state=props();observed.append({k:state[k] for k in ('ActiveState','SubState','Job','Result')})
   if state['SubState']=='auto-restart':break
   time.sleep(.005)
  record('auto-restart-invalid-configuration',observed);assert any(s['SubState']=='auto-restart' for s in observed)
  ctl('stop','sshd.service');MAIN.write_text(stock)
  report['result']='PASS';save();print(json.dumps({'result':'PASS','cases':len(report['cases'])}))
 finally:
  (OUT/'sshd-journal.log').write_text(run(['journalctl','-u','sshd.service','-n','160','--no-pager'],False).stdout);save()
if __name__=='__main__':
 import sys
 if sys.argv[1:]==['--self-test']:
  try:guard()
  except AssertionError:print('ALT research rejects non-fixture environment PASS')
  else:raise RuntimeError('guard unexpectedly admitted self-test')
 else:main()
