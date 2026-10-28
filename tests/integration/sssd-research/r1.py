#!/usr/bin/env python3
"""R1: native stock units + explicitly separated controlled configuration fixtures."""
from common import *
import sys,shutil
report.update(stage='R1',platform=sys.argv[1],engine='Docker (user authorized instead of Podman)',os_release=Path('/etc/os-release').read_text())
alt=Path('/etc/altlinux-release').exists()
experiment('inventory',{
 'packages':run(['rpm','-qa','--qf','%{NAME} %{VERSION}-%{RELEASE}\n'] if alt else ['dpkg-query','-W','-f','${binary:Package} ${Version}\n','sssd*','libsss*','libpam-sss','libnss-sss','systemd','libini-config*','libldb*']),
 'sssd_version':run(['/usr/sbin/sssd','--version']),'sssd_help':run(['/usr/sbin/sssd','--help']),
 'sssctl_help':run(['sssctl','--help']),'config_check_help':run(['sssctl','config-check','--help']),
 'unit_sources':ctl('cat','sssd.service'),'all_unit_properties':ctl('show','sssd.service','--all'),
 'units':ctl('list-unit-files','--no-legend','sssd*'),'initial_state':state(),
 'vendor_files':run(['rpm','-ql','sssd'] if alt else ['dpkg-query','-L','sssd-common']),
 'stock_config_tree':run(['find','/etc/sssd','-maxdepth','3','-ls']),
 'vendor_config_candidates':run(['find','/usr/lib/sssd','/usr/share/sssd','-maxdepth','3','-type','f'])})
configure();experiment('installed-stopped-engine',{'state':state(),'engine':generic()})
experiment('stock-active',observe_start());experiment('stock-active-engine',generic())
# Capture source file changes vs ConfigDB and unchanged process generation.
before=state();write(DROP/'zzzz-fic.conf','[pam]\noffline_credentials_expiration = 37\n')
experiment('file-change-without-restart',{'before':before,'after':state(),'check':check_config(),'configdb':configdb()})
experiment('reload',{'command':ctl('reload','sssd.service'),'state':state(),'configdb':configdb()})
experiment('sighup',{'command':ctl('kill','--kill-whom=main','--signal=HUP','sssd.service'),'state':state(),'configdb':configdb()})
experiment('restart-loads-snippet',observe_start())
for name,files in [
 ('lexical-precedence',{'10-first.conf':'[pam]\noffline_credentials_expiration=11\n','zzzz-fic.conf':'[pam]\noffline_credentials_expiration=22\n','zzzzz-local.conf':'[pam]\noffline_credentials_expiration=33\n'}),
 ('duplicate-in-file',{'zzzz-fic.conf':'[pam]\noffline_credentials_expiration=21\noffline_credentials_expiration=34\n'}),
 ('ignored-hidden-suffix', {'.hidden.conf':'[pam]\noffline_credentials_expiration=40\n','late.conf.bak':'[pam]\noffline_credentials_expiration=41\n'})]:
 configure()
 for filename,content in files.items():write(DROP/filename,content)
 experiment(name,{'config_check':check_config(),'runtime':observe_start()})
for name,kind in [('symlink','symlink'),('hardlink','hardlink'),('world-readable-snippet','mode'),('foreign-owner-snippet','owner')]:
 configure();p=DROP/'zzzz-fic.conf';content='[pam]\noffline_credentials_expiration=43\n'
 if kind in ('symlink','hardlink'):
  target=MAIN.parent/'research-linked.conf';write(target,content)
  (p.symlink_to(target) if kind=='symlink' else os.link(target,p))
 else:
  write(p,content)
  if kind=='mode':p.chmod(0o644)
  else:os.chown(p,65534,65534)
 experiment(name,{'config_check':check_config(),'runtime':observe_start()})
configure();MAIN.unlink();write(DROP/'zzzz-fic.conf',base(offline=44))
experiment('missing-main-snippets-present',{'config_check':check_config(),'runtime':observe_start()})
configure();write(MAIN,base()+'\nFicInvalidSyntax\n');experiment('invalid-restart',{'check':check_config(),'runtime':observe_start(),'engine':generic()})
# Explicit alternate path: foreground SSSD is a controlled fixture, NOT a stock unit.
configure();custom=Path('/run/sssd-alt/sssd.conf');write(custom,base(offline=51));write(custom.parent/'conf.d'/'late.conf','[pam]\noffline_credentials_expiration=53\n')
write(DROP/'zzzzz-global.conf','[pam]\noffline_credentials_expiration=52\n')
experiment('alternate-check-paths',{'default':check_config('-c',str(custom)), 'explicit_custom_snippets':check_config('-c',str(custom),'-s',str(custom.parent/'conf.d'))})
trace=OUT/'alternate-trace';command=['strace','-ff','-o',str(trace),'-e','trace=%file,sendmsg','/usr/sbin/sssd','-i','-c',str(custom),'--logger=stderr']
with (OUT/'foreground.log').open('w') as log:
 proc=subprocess.Popen(command,stdout=log,stderr=log,start_new_session=True)
 deadline=time.monotonic()+20;observed={}
 while time.monotonic()<deadline and proc.poll() is None:
  db=configdb();text=db.get('stdout','')
  if 'offline_credentials_expiration: 5' in text:observed=db;break
  time.sleep(.05)
 experiment('alternate-daemon-input-graph',{'fixture':'foreground sssd -c, stock unit stopped','command':command,'configdb':observed,'processes':processes()})
 os.killpg(proc.pid,signal.SIGTERM)
 try:proc.wait(timeout=10)
 except subprocess.TimeoutExpired:os.killpg(proc.pid,signal.SIGKILL);proc.wait()
 report['experiments']['alternate-daemon-input-graph']['exit_code']=proc.returncode;save()
# Foreground monitor can change its process group. Quiesce ONLY SSSD fixture
# executables in this guarded container; do not let leftovers contaminate stock RO runs.
left=[]
for procpath in Path('/proc').iterdir():
 if not procpath.name.isdigit():continue
 try:
  exe=os.readlink(procpath/'exe')
  if Path(exe).name in ('sssd','sssd_be','sssd_pam','sssd_nss'):left.append(int(procpath.name))
 except OSError:pass
for pid in left:
 try:os.kill(pid,signal.SIGTERM)
 except ProcessLookupError:pass
deadline=time.monotonic()+10
while time.monotonic()<deadline and any(Path('/proc',str(pid)).exists() for pid in left):time.sleep(.05)
for pid in left:
 try:os.kill(pid,signal.SIGKILL)
 except ProcessLookupError:pass
experiment('foreground-cleanup',{'fixture_pids':left})
# RO fixture, first unprepared root:0600, then metadata prepared by native unit.
before_hash=hashlib.sha256(ctl('cat','sssd.service')['stdout'].encode()).hexdigest()
for prepared in (False,True):
 configure()
 if prepared:experiment('prepare-native-metadata',observe_start());ctl('stop','sssd.service')
 mounts=[]
 try:
  for p in (MAIN.parent,):
   assert run(['mount','--bind',str(p),str(p)])['exit_code']==0
   assert run(['mount','--make-private',str(p)])['exit_code']==0;mounts.append(p)
  for p in (MAIN,DROP):
   assert run(['mount','--bind',str(p),str(p)])['exit_code']==0;mounts.append(p)
   assert run(['mount','-o','remount,bind,ro',str(p)])['exit_code']==0
  experiment('stock-ro-'+('prepared' if prepared else 'unprepared'),{
   'fixture':'manual bind RO, not generic copied-snapshot proof','mountinfo':Path('/proc/self/mountinfo').read_text(),
   'metadata':run(['stat','-c','%n %u %g %a %i %h',str(MAIN),str(DROP)]),
   'runtime':observe_start(),'engine':generic(),'write_attempt':run(['touch',str(DROP/'late.conf')])})
 finally:
  ctl('stop','sssd.service',timeout=45)
  for p in reversed(mounts):assert run(['umount',str(p)])['exit_code']==0
assert before_hash==hashlib.sha256(ctl('cat','sssd.service')['stdout'].encode()).hexdigest(),'stock unit changed'
# File lifecycle barriers: file change takes place ONLY after stock READY or
# while monitor is demonstrably stopped (T); no sleep establishes positive proof.
configure();experiment('barrier-initial',observe_start());pid=int(state()['MainPID'])
os.kill(pid,signal.SIGSTOP)
deadline=time.monotonic()+5
while time.monotonic()<deadline:
 status=Path('/proc',str(pid),'status').read_text()
 if 'State:\tT' in status:break
 time.sleep(.01)
else:raise RuntimeError('SIGSTOP barrier not reached')
old_inode=MAIN.stat().st_ino;new=MAIN.with_suffix('.replacement');write(new,MAIN.read_text());os.replace(new,MAIN)
write(DROP/'zzzzz-after-ready.conf','[pam]\noffline_credentials_expiration=61\n')
experiment('same-bytes-inode-and-late-snippet',{'barrier':'monitor SIGSTOP after READY', 'before_inode':old_inode,'after_inode':MAIN.stat().st_ino,'state':state(),'configdb':configdb(),'engine':generic()})
os.kill(pid,signal.SIGCONT);experiment('restart-after-barrier',observe_start())
experiment('final-state',{'state':state(),'journal':run(['journalctl','-u','sssd.service','-n','160','--no-pager'])})
report['collection_complete']=True;save()
print('R1 collection complete',report['platform'],flush=True)
