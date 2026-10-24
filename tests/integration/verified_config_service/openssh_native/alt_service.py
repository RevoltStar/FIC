#!/usr/bin/env python3
"""ALT real policy/journal/service gate. Only via guarded disposable runner."""
import importlib.util,json,shutil,socket,os,time,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('native','/usr/local/bin/fic-openssh-harness.py');h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
h.MAIN=Path('/etc/openssh/sshd_config');h.ENV=Path('/etc/sysconfig/sshd');h.DROP=Path('/etc/openssh/sshd_config.local.d');h.KEY=Path('/etc/openssh/ssh_host_ed25519_key')

def ctl(*args,check=True):return h.run(['systemctl',*args],check=check)
def state():return dict(line.split('=',1) for line in ctl('show','sshd.service','--property=Id,UnitFileState,ActiveState,SubState,Job,InvocationID,MainPID').stdout.splitlines() if '=' in line)
def request():
 targets=[{'path':str(p),'sha256':h.sha(p)} for p in [h.MAIN,h.ENV,*sorted(h.MAIN.parent.glob('ssh_host_*_key*'))] if p.is_file()]
 if h.DROP.exists():targets.append({'path':str(h.DROP),'directory':True,'manifest':{str(p.relative_to(h.DROP)):h.sha(p) for p in h.DROP.rglob('*') if p.is_file()}})
 return {'paths':targets,'timeout_ms':15000,'glob_dir':str(h.DROP)}

def wait(port,family="any"):
 deadline=time.monotonic()+10
 while time.monotonic()<deadline:
  try:
   if family!='inet6':return h.handshake(port)
   with socket.create_connection(('::1',port),timeout=1) as client:
    assert client.recv(256).startswith(b'SSH-2.0-');return

  except (OSError,AssertionError):
   if state()['ActiveState']=='failed':raise
   time.sleep(.02)
 raise RuntimeError('fixture ALT readiness deadline')

def main():
 h.guard();phase=sys.argv[1] if len(sys.argv)>1 else 'all';assert phase in ('all','rollback','activation');Path('/run/fic').mkdir(exist_ok=True);report={'phase':phase,'cases':[]};stock=h.MAIN.read_text();stockenv=h.ENV.read_text()
 def save():(h.OUT/'results.json').write_text(json.dumps(report,indent=2))
 def case(name,operations,success=True):
  req=request();req['operations']=operations;data=h.drive('module',req);report['cases'].append({'name':name,'result':data});save();rows=data['module']
  assert len(rows)==len(operations) and all(row['applied']==success for row in rows),(name,data)
  return rows
 try:
  ctl('stop','sshd.service',check=False);ctl('enable','sshd.service');ctl('start','sshd.service');wait(22)
  report['environment']={'packages':h.run(['rpm','-q','openssh-server','systemd']).stdout,'kernel':os.uname().release,'unit':state()}
  assert not h.DROP.exists(),'production must not create ALT Include directory'
  selected=[{'policy':p,'value':v} for p,v in [('ssh_root_login','no'),('ssh_pubkey_auth','yes'),('ssh_use_pam','yes'),('ssh_max_auth_tries','3'),('ssh_port','2244')]]
  if phase=='all':
   raw=request();before=h.sha(h.MAIN);default=h.drive('activate',raw);report['cases'].append({'name':'public-generic-rejects-stock-simple','result':default});save()
   assert default['status']=='UnsupportedConfiguration' and not default['readinessConfirmed'] and default['residual_count_before_admin_cleanup']==0 and h.sha(h.MAIN)==before,default
   rows=case('stock-config-five-policies-and-receipt',selected*3)
   assert len(rows[-1]['records'])==3 and all(r['main_unchanged'] and r['before_invocation']==r['after_invocation'] for r in rows[-5:]),rows
   assert not h.DROP.exists()
   h.handshake(2244)
   print('ALT stock real five-policy gate PASS',flush=True)
  keys=h.WORK/'key-backup';keys.mkdir()
  for key in h.MAIN.parent.glob('ssh_host_*_key*'):shutil.copy2(key,keys/key.name)
  def reset(extra='',family='any'):
   ctl('stop','sshd.service',check=False);h.drive('cleanup',{'paths':[]})
   ctl('unset-environment','FIC_OPENSSH_TEST_CHANGE');ctl('unmask','sshd.service',check=False);ctl('enable','sshd.service')
   shutil.rmtree('/etc/systemd/system/sshd.service.d',ignore_errors=True);shutil.rmtree(h.DROP,ignore_errors=True)
   for key in keys.iterdir():shutil.copy2(key,h.MAIN.parent/key.name)
   addresses='ListenAddress 127.0.0.1\nListenAddress ::1\n' if family=='any' else 'ListenAddress 127.0.0.1\n' if family=='inet' else 'ListenAddress ::1\n'
   h.MAIN.write_text('Port 2222\nAddressFamily '+family+'\n'+addresses+'PermitRootLogin yes\nPubkeyAuthentication no\nUsePAM no\nMaxAuthTries 6\n'+stock+extra)
   h.MAIN.chmod(0o600);h.ENV.write_text(stockenv);h.ENV.chmod(0o644)
   shutil.rmtree(h.WORK/'module-state',ignore_errors=True)
   ctl('daemon-reload');ctl('reset-failed','sshd.service');ctl('start','sshd.service');wait(2222,family)
  def listeners():
   result={}
   for file,family in [('tcp',socket.AF_INET),('tcp6',socket.AF_INET6)]:
    for line in Path('/proc/net/'+file).read_text().splitlines()[1:]:
     v=line.split()
     if v[3]!='0A':continue
     raw,port=v[1].split(':');data=bytes.fromhex(raw);data=data[::-1] if family==socket.AF_INET else b''.join(data[i:i+4][::-1] for i in range(0,16,4))
     result[(socket.inet_ntop(family,data),int(port,16))]=int(v[9])
   return result
  def fds(pid):
   result=set()
   for p in Path('/proc/'+str(pid)+'/fd').iterdir():
    try:link=os.readlink(p)
    except FileNotFoundError:continue
    if link.startswith('socket:['):result.add(int(link[8:-1]))
   return result
  if phase=='rollback':
   reset();case('rollback-owned-apply',[{'policy':'ssh_port','value':'2244'}])
   row=case('active-rollback-refusal',[{'policy':'ssh_port','value':'2244','rollback':True}],False)[0];assert row['main_unchanged'] and row['records']
   row=case('offline-ownership-only-release',[{'policy':'ssh_port','value':'2244','rollback':True,'offline':True}])[0];assert not row['main_unchanged'] and 'runtime NOT activated' in row['release_message']
   report['result']='PASS';print(json.dumps({'result':'PASS','phase':phase,'groups':len(report['cases'])}));return
  if phase=='all':
   reset();old=listeners()
   rows=case('fresh-five-policies-and-receipt',selected*3);new=listeners()
   assert len(rows[-1]['records'])==5 and all(r['main_unchanged'] and r['before_invocation']==r['after_invocation'] for r in rows[-5:]),rows
   assert {p for a,p in new}=={2244} and not set(old.values())&set(new.values())
   assert set(new.values())<=fds(rows[-1]['after_pid']) and not set(new.values())&fds(1)
   effective=dict(line.split(' ',1) for line in h.run(['/usr/sbin/sshd','-T']).stdout.splitlines())
   for k,v in {'permitrootlogin':'no','pubkeyauthentication':'yes','usepam':'yes','maxauthtries':'3','port':'2244'}.items():assert effective[k]==v
   report['runtime_proof']={'old':[{'address':a,'port':p,'inode':i} for (a,p),i in old.items()],'new':[{'address':a,'port':p,'inode':i} for (a,p),i in new.items()],'mainpid':rows[-1]['after_pid'],'sshd_fd_inodes':sorted(fds(rows[-1]['after_pid'])),'pid1_fd_inodes':sorted(fds(1))}
   for family in ('inet','inet6'):
    reset(family=family);old=listeners();case('Port-'+family,[{'policy':'ssh_port','value':'2244'}]);assert {p for a,p in listeners()}=={2244} and not set(old.values())&set(listeners().values())
   reset();h.MAIN.write_text(h.MAIN.read_text().replace('PermitRootLogin yes','PermitRootLogin no'))
   rows=case('foreign-compliant-no-enrollment',[{'policy':'ssh_root_login','value':'no'}]*2)
   assert all(r['main_unchanged'] and not r['records'] for r in rows) and rows[-1]['before_invocation']==rows[-1]['after_invocation']
   for change in ('restart','main-comment'):
    reset();rows=case('receipt-invalidated-'+change,[{'policy':'ssh_root_login','value':'no'},{'policy':'ssh_root_login','value':'no','before':change},{'policy':'ssh_root_login','value':'no'}])
    assert rows[1]['before_invocation']!=rows[1]['after_invocation'] and rows[2]['before_invocation']==rows[2]['after_invocation']
   reset(extra='Match User nobody\n X11Forwarding no\n');h.DROP.mkdir();(h.DROP/'sub').mkdir();(h.DROP/'10.conf').write_text('Include /etc/openssh/sshd_config.local.d/sub/leaf.inc\n');(h.DROP/'sub/leaf.inc').write_text('LogLevel VERBOSE\n');h.MAIN.write_text('Include sshd_config.local.d/*.conf\n'+h.MAIN.read_text())
   case('recursive-Include-and-unrelated-Match',[{'policy':'ssh_root_login','value':'no'}])
   for name,extra in [('external-empty-glob','Include /run/fic-openssh-work/nope-*.conf\n'),('systemd-external-symlink','Include /etc/openssh/sshd_config.d/*.conf\n'),('conditional-selected','Match User root\n PermitRootLogin yes\n')]:
    reset(extra=extra);row=case(name,[{'policy':'ssh_root_login','value':'no'}],False)[0];assert row['main_unchanged'] and not row['records']
   for kind in ('symlink','recursion','Port','ListenAddress'):
    reset();h.DROP.mkdir();h.MAIN.write_text('Include sshd_config.local.d/*.conf\n'+h.MAIN.read_text())
    if kind=='symlink':(h.DROP/'10.conf').symlink_to(h.ENV)
    else:(h.DROP/'10.conf').write_text('Include /etc/openssh/sshd_config.local.d/10.conf\n' if kind=='recursion' else 'Port 2277\n' if kind=='Port' else 'ListenAddress 127.0.0.1:2277\n')
    row=case('unsupported-Include-'+kind,[{'policy':'ssh_port','value':'2244'}],False)[0];assert row['main_unchanged'] and not row['records']
   for options in ('EXTRAOPTIONS=-p2266\n','EXTRAOPTIONS=-oUsePAM=no\n','EXTRAOPTIONS=-f/other\n','EXTRAOPTIONS=\nOTHER=1\n'):
    reset();h.ENV.write_text(options);row=case('unsafe-environment-'+options.strip(),[{'policy':'ssh_use_pam','value':'yes'}],False)[0];assert row['main_unchanged'] and not row['records']
   for mode in ('disabled-active','enabled-inactive','failed','masked','missing-env','missing-key','unsafe-key'):
    reset()
    if mode=='disabled-active':ctl('disable','sshd.service')
    if mode=='enabled-inactive':ctl('stop','sshd.service')
    if mode=='masked':ctl('mask','sshd.service')
    if mode=='missing-env':h.ENV.unlink()
    if mode=='missing-key':(h.MAIN.parent/'ssh_host_rsa_key').unlink()
    if mode=='unsafe-key':h.KEY.chmod(0o644)
    if mode=='failed':
     ctl('stop','sshd.service');h.MAIN.write_text('InvalidFicDirective yes\n');ctl('start','sshd.service',check=False)
    row=case(mode,[{'policy':'ssh_root_login','value':'no'}],False)[0];assert row['main_unchanged'] and not row['records']
    if mode=='missing-key':assert not (h.MAIN.parent/'ssh_host_rsa_key').exists()
   for override in ('ExecStart=\nExecStart=/usr/sbin/sshd -D -f /other','ExecStart=\nExecStart=/usr/sbin/sshd -D -oUsePAM=no','ExecStart=\nExecStart=/usr/sbin/sshd -D -p2277','Environment=EXTRAOPTIONS=-p2277','Type=notify'):
    reset();directory=Path('/etc/systemd/system/sshd.service.d');directory.mkdir();(directory/'bad.conf').write_text('[Service]\n'+override+'\n');ctl('daemon-reload')
    row=case('unsupported-dropin-'+override,[{'policy':'ssh_root_login','value':'no'}],False)[0];assert row['main_unchanged'] and not row['records']
   reset();directory=Path('/etc/systemd/system/sshd.service.d');directory.mkdir();(directory/'safe.conf').write_text('[Unit]\nDescription=Safe ALT administrator description\n[Service]\nCPUWeight=100\n');ctl('daemon-reload')
   case('compatible-administrative-dropin',[{'policy':'ssh_root_login','value':'no'}])
   for fault in ('main-cas','foreign-input','disable','after-save-stop','after-save-disable','after-save-input','after-save-main','durability','unknown-writer','journal-commit'):
    reset();h.DROP.mkdir()
    row=case('module-fault-'+fault,[{'policy':'ssh_use_pam','value':'yes','fault':fault}],False)[0]
    if fault.startswith('after-') or fault in ('durability','unknown-writer','journal-commit'):assert not row['main_unchanged'] and (row['records'] or row['journal_unusable'])
   reset();rows=case('unresolved-Prepared',[{'policy':'ssh_use_pam','value':'yes','fault':'durability'},{'policy':'ssh_root_login','value':'no'}],False);assert rows[1]['main_unchanged'] and rows[1]['journal_unchanged']
   reset();case('rollback-owned-apply',[{'policy':'ssh_port','value':'2244'}]);row=case('active-rollback-refusal',[{'policy':'ssh_port','value':'2244','rollback':True}],False)[0];assert row['main_unchanged'] and row['records']
   row=case('offline-ownership-only-release',[{'policy':'ssh_port','value':'2244','rollback':True,'offline':True}])[0];assert not row['main_unchanged'] and 'runtime NOT activated' in row['release_message']
  for fault in ('ro-write','busy','original-write','new-glob','contract-before','contract-after','ready-stop','ready-disable','ready-foreign-restart','final-disable','final-restart','alt-no-ready','pending-ready','pending-timeout','pending-failed'):
   reset();h.DROP.mkdir();h.MAIN.write_text(h.MAIN.read_text().replace('PermitRootLogin yes','PermitRootLogin no'));(h.WORK/'mutation.conf').write_text(h.MAIN.read_text()+'# foreign persistent edit\n')
   req=request();req['policies']={'ssh_root_login':'no'}
   data=h.drive('adapter-'+fault,req);report['cases'].append({'name':'adapter-'+fault,'result':data});save();assert data.get('adapter_success')==(fault in ('ro-write','pending-ready')),(fault,data)
   if fault.startswith('pending-'):assert data.get('admission_wait_observed'),data
   if fault=='alt-no-ready':assert data.get('readiness_barrier_observed'),data
  reset();blockers=[]
  for family,address in [(socket.AF_INET,'127.0.0.1'),(socket.AF_INET6,'::1')]:
   blocker=socket.socket(family);blocker.bind((address,2244));blocker.listen();blockers.append(blocker)
  try:
   row=case('foreign-listener-bind-failure',[{'policy':'ssh_port','value':'2244'}],False)[0];assert not row['main_unchanged'] and row['records']
  finally:
   for blocker in blockers:blocker.close()
  reset();raw=request();raw['untrusted_keygen']=True;raw['operations']=[{'policy':'ssh_root_login','value':'no'}]
  data=h.drive('module',raw);report['cases'].append({'name':'untrusted-keygen-before-save','result':data});save()
  assert len(data['module'])==1 and not data['module'][0]['applied'] and data['module'][0]['main_unchanged'] and not data['module'][0]['records'],data
  report['result']='PASS'

 finally:save();(h.OUT/'sshd-journal.log').write_text(h.run(['journalctl','-u','sshd.service','--no-pager','-n','140'],check=False).stdout)
 print(json.dumps({'result':report['result'],'alt_groups':len(report['cases'])}))
if __name__=='__main__':main()
