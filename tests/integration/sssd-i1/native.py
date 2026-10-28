"""Production I1 read-only gates; all writes/restarts are disposable fixtures."""
from common import *
import sys
platform=sys.argv[1]
def probe(action='capture'):
 r=run(['/usr/local/bin/sssd-i1-probe',action],timeout=40)
 assert r['exit_code']==0,r
 x=json.loads(r['stdout']);return x
def native_check_ok(r):
 if r['exit_code']==0:return True
 # ALT libini reports ignored hidden/suffix files as merge messages and exits 1.
 # Recognize that exact warning set, never a generic exit-1 success fallback.
 return (platform=='alt-p11' and r['exit_code']==1 and
         'Issues identified by validators: 0' in r['stdout'] and
         'Messages generated during configuration merging: 2' in r['stdout'] and
         all(f'File {DROP / name} did not match provided patterns. Skipping.' in r['stdout']
             for name in ('.hidden.conf','zzzzz-ignored.txt')))
experiment('platform',{'platform':platform,'version':run(['sssd','--version']),'packages':run(['rpm','-q','--qf','%{NAME} %{VERSION}-%{RELEASE}\n','sssd','sssd-tools','systemd'] if platform=='alt-p11' else ['dpkg-query','-W','-f','${binary:Package} ${Version}\n','sssd-common','sssd-tools','systemd']),'os_release':Path('/etc/os-release').read_text(),'kernel':run(['uname','-r']), 'unit':ctl('cat','sssd.service')})
ctl('show','sssd.service','-p','LoadState')
configure()
experiment('stopped',probe())
assert report['experiments']['stopped']['status']!='CAPTURED'
if platform=='alt-p11':write(MAIN,base().replace('[sssd]\n','[sssd]\nuser = _sssd\n'))
start=observe_start();experiment('stock-start',start)
if start['state']['ActiveState']!='active':
 experiment('startup-failure-diagnostic',{'journal':run(['journalctl','-b','-u','sssd.service','--no-pager','-n','100']),'monitor':Path('/var/log/sssd/sssd.log').read_text(errors='replace')[-18000:] if Path('/var/log/sssd/sssd.log').exists() else '', 'metadata':{str(p):{'uid':p.stat().st_uid,'gid':p.stat().st_gid,'mode':oct(p.stat().st_mode)} for p in [MAIN,MAIN.parent,DROP,Path('/var/lib/sss'),Path('/var/lib/sss/db')]}})
assert start['state']['ActiveState']=='active',start
experiment('typed-launch',probe('launch'))
before=state();x=probe();after=state();experiment('main-snippets',x)
assert before['InvocationID']==after['InvocationID'] and before['MainPID']==after['MainPID'],(before,after)
assert x['status']=='CAPTURED',x
# Native graph order/ConfigDB: native logs record ordered merge and final value.
for p,text in [('10-first.conf','[pam]\noffline_credentials_expiration=11\n'),('50-race.conf','[pam]\ndebug_level=7\n'),('90-last.conf','[pam]\noffline_credentials_expiration=22\noffline_credentials_expiration=23\n')]:write(DROP/p,text)
write(DROP/'.hidden.conf','[pam]\noffline_credentials_expiration=66\n')
write(DROP/'zzzzz-ignored.txt','[pam]\noffline_credentials_expiration=77\n')
x=probe();experiment('ordered-duplicates-hidden',x);assert x['status']=='CAPTURED',x
assert x['projection']['pam']['offline_credentials_expiration']['value']=='23'
assert x['order']==[str(MAIN),str(DROP/'10-first.conf'),str(DROP/'50-race.conf'),str(DROP/'90-last.conf')]
start=observe_start();experiment('native-merge',start)
assert 'offline_credentials_expiration: 23' in start['configdb']['stdout'],start
check=check_config('-c',str(MAIN),'-s',str(DROP));experiment('native-check-explicit',check)
assert native_check_ok(check) and [v for v in check['stdout'].splitlines() if v.startswith(str(DROP)+'/')]==x['order'][1:],check
log=Path('/var/log/sssd/sssd.log')
experiment('native-source-load-log',{'lines':[line for line in log.read_text(errors='replace').splitlines() if 'conf.d/' in line or 'sssd.conf' in line][-80:] if log.exists() else [],'note':'monitor log plus ConfigDB; config-check is separate, not runtime semantics proof'})
write(DROP/'zzzz-fic.conf','[pam]\noffline_credentials_expiration=23\n')
for kind,content in [('matching','[pam]\noffline_credentials_expiration=23\n'),('conflicting','[pam]\noffline_credentials_expiration=99\n'),('unrelated','[pam]\ndebug_level=8\n')]:
 write(DROP/'zzzzz-foreign.conf',content);x=probe();experiment('late-'+kind,x)
 assert x['status']=='CAPTURED' and x['fic_named_file_observed'] and x['apply_conflict'] and x['later']==[str(DROP/'zzzzz-foreign.conf')],x
 (DROP/'zzzzz-foreign.conf').unlink()
for kind in ('create','delete','inode','bytes','metadata','restore'):
 write(DROP/'50-race.conf','[pam]\ndebug_level=7\n')
 x=probe('race-'+kind);experiment('race-'+kind,x);assert x['status']=='InterferenceDetected',x
 (DROP/'51-new.conf').unlink(missing_ok=True)
write(DROP/'50-race.conf','[pam]\ndebug_level=7\n')
# Link/mode/owner/nested-directory negatives use the same production scanner.
for kind in ('symlink','hardlink','mode','owner','directory'):
 p=DROP/'40-unsafe.conf'
 if kind=='symlink':p.symlink_to(DROP/'50-race.conf')
 elif kind=='hardlink':os.link(DROP/'50-race.conf',p)
 elif kind=='directory':p.mkdir()
 else:
  write(p,'[pam]\ndebug_level=7\n')
  if kind=='mode':p.chmod(0o666)
  else:os.chown(p,65534,65534)
 x=probe();experiment('unsafe-'+kind,x);assert x['status']!='CAPTURED',x
 if p.is_dir():p.rmdir()
 else:p.unlink()
# Older native parsers have stricter mode admission; never claim their skipped
# group-readable file as a merged source. Newer unit precommands set g+r.
p=DROP/'40-group.conf';write(p,'[pam]\ndebug_level=7\n',0o640)
x=probe();experiment('profile-group-mode',x)
assert x['status']==('CAPTURED' if platform in ('debian-13','ubuntu-26.04') else 'UnsupportedConfiguration'),x
experiment('native-group-mode-check',check_config('-c',str(MAIN),'-s',str(DROP)))
p.unlink()
# Nested mount is unsupported even when all bytes would match.
mount=DROP/'nested-mount';mount.mkdir()
m=run(['mount','-t','tmpfs','tmpfs',str(mount)]);assert m['exit_code']==0,m
try:
 x=probe();experiment('nested-mount',x);assert x['status']=='UnsupportedConfiguration',x
finally:
 u=run(['umount',str(mount)]);assert u['exit_code']==0,u
 mount.rmdir()
# Revalidate environment bytes / optional absence independently of D-Bus path.
env=Path('/etc/sysconfig/sssd' if platform=='alt-p11' else '/etc/default/sssd')
old=env.read_bytes() if env.exists() else None
x=probe('source-change');experiment('launch-environment-change',x);assert x['status']=='InterferenceDetected',x
if old is None:env.unlink()
else:env.write_bytes(old)
# Optional absence and hostile environment are distinct, revalidated states.
env.unlink(missing_ok=True)
x=probe();experiment('optional-environment-absent',x);assert x['status']=='CAPTURED' and str(env) in x['absent'],x
write(env,'LD_PRELOAD=/untrusted.so\n')
x=probe();experiment('unsupported-environment-variable',x);assert x['status']=='UnsupportedConfiguration',x
if old is None:env.unlink()
else:env.write_bytes(old)
# Unknown drop-in appears between reference capture and revalidation, no reload.
x=probe('dropin-change');experiment('launch-dropin-change',x);assert x['status']=='InterferenceDetected',x
Path('/etc/systemd/system/sssd.service.d/i1.conf').unlink();Path('/etc/systemd/system/sssd.service.d').rmdir();ctl('daemon-reload')
# Main absent + full configuration in snippets: no fabricated file.
ctl('stop','sssd.service');text=MAIN.read_text();MAIN.unlink();write(DROP/'00-complete.conf',text)
start=observe_start();experiment('absent-main-native',start);assert start['state']['ActiveState']=='active',start
x=probe();experiment('absent-main',x);assert x['status']=='CAPTURED' and str(MAIN) in x['absent'] and x['engine_negative_gap'],x
# -c/-s mismatch remains a native diagnostic, not C=Semantics proof.
alt=Path('/run/sssd-alt/sssd.conf');write(alt,text)
default=check_config('-c',str(alt));explicit=check_config('-c',str(alt),'-s',str(DROP))
experiment('alternate-check-default',default);experiment('alternate-check-explicit',explicit)
assert str(DROP/'00-complete.conf') not in default['stdout'] and str(DROP/'00-complete.conf') in explicit['stdout'] and native_check_ok(explicit)
# Neither source remains acceptable merely because old monitor is running.
ctl('stop','sssd.service')
for p in DROP.iterdir():p.unlink()
write(MAIN,text);observe_start();MAIN.unlink()
x=probe();experiment('absent-all',x);assert x['status']!='CAPTURED',x
write(MAIN,text);observe_start()
fragment=Path(json.loads(probe('launch')['launch']['launch.FragmentPath'])['value']);raw=fragment.read_bytes()
x=probe('unit-change');experiment('launch-unit-source-change',x);assert x['status']=='InterferenceDetected',x
fragment.write_bytes(raw)
experiment('result',{'status':'PASS','scope':'I1 read-only capture/revalidation only; no activation proofs','native_activation_tested':False})
