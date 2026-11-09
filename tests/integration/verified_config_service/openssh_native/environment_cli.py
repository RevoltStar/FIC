#!/usr/bin/env python3
"""Real installed production daemon/CLI I1 gate; CMake payload, not DEB lifecycle proof."""
import importlib.util
import json
import re
from pathlib import Path
spec=importlib.util.spec_from_file_location('native','/usr/local/bin/fic-openssh-harness.py')
h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h);h.guard()
report={'deployment':'current-build production CMake install; no package-manager install claim','commands':[],'cases':[]}
def save():(h.OUT/'environment-cli-results.json').write_text(json.dumps(report,indent=2))
def run(args,timeout=120):
 p=h.run(args,check=False,timeout=timeout);report['commands'].append({'argv':args,'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr});save()
 assert p.returncode==0,(args,p.stdout,p.stderr)
 return p.stdout
ctl=lambda *a:run(['systemctl',*a])
fic='/opt/fic/bin/fic';cli='/opt/fic/bin/fic-cli'
run(['groupadd','--system','fic'])
for p in ['/opt/fic','/opt/fic/bin','/opt/fic/db','/opt/fic/log','/opt/fic/notify']:
 Path(p).mkdir(exist_ok=True);run(['chown','root:fic',p]);run(['chmod','2750',p])
ctl('daemon-reload');run(['/opt/fic/bin/fic-package-infrastructure','prepare-install'])
run([fic,'--maintenance','ensure-config-first-install'])
# Explicit native fixture administrative baseline: only GLOBAL controls and NET
# are relevant. Do not exercise unrelated OS policies during daemon startup.
for p in Path('/opt/fic/config').glob('*.conf'):
 if p.name=='GLOBAL.conf':continue
 p.write_text(re.sub(r'(?m)^(\w+\.status)=ENABLE$',r'\1=DISABLE',p.read_text()))
run([fic,'--maintenance','incident-init']);run([fic,'--maintenance','initialize-journal'])
run(['/opt/fic/bin/fic-dick','--maintenance','initialize-db'])
run([fic,'--trust-sync-platform']);run([fic,'--maintenance','bootstrap-pam-password-slots'])
run([fic,'--maintenance','validate-pam-slots-before-attach'])
run(['/usr/sbin/pam-auth-update','--package'])
run(['/usr/sbin/pam-auth-update','--enable','fic-faillock-hook-preauth','fic-faillock-hook-authfail','fic-faillock-hook-authsucc','fic-faillock-hook-account','fic-incident-access'])
run([fic,'--maintenance','complete-install'])
run(['systemd-tmpfiles','--create','/usr/lib/tmpfiles.d/fic.conf'])
ctl('stop','ssh.service','ssh.socket')
for parent in (h.MAIN.parent,h.ENV.parent):
 run(['mount','--bind',str(parent),str(parent)]);run(['mount','--make-private',str(parent)])
run(['ssh-keygen','-A']);h.DROP.mkdir(exist_ok=True)
for p in h.DROP.iterdir():p.unlink()
h.MAIN.write_text(f'Port 2222\nListenAddress 127.0.0.1\nHostKey {h.KEY}\nUsePAM no\nPasswordAuthentication no\nPubkeyAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin no\n')
h.MAIN.chmod(0o644);h.ENV.write_text('SSHD_OPTS=\n');h.ENV.chmod(0o644)
ctl('enable','ssh.socket');ctl('daemon-reload');ctl('start','ssh.socket')
environment=['LANG=ru_RU.UTF-8','PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/snap/bin']+[x+'=ru_RU.UTF-8' for x in ['LC_ADDRESS','LC_IDENTIFICATION','LC_MEASUREMENT','LC_MONETARY','LC_NAME','LC_NUMERIC','LC_PAPER','LC_TELEPHONE','LC_TIME']]
ctl('set-environment',*environment);ctl('start','fic.service');run([fic,'--maintenance','wait-daemon','30'])
state=lambda:dict(x.split('=',1) for x in ctl('show','ssh.service','-p','MainPID','-p','InvocationID').splitlines())
journal=lambda:json.loads(Path('/opt/fic/db/mutation-journal.json').read_text())
for label,xdg in [('r1-baseline',None),('reported-xdg','/var/lib/flatpak/exports/share:/usr/local/share/:/usr/share/')]:
 if xdg:ctl('set-environment','XDG_DATA_DIRS='+xdg)
 before=state();original=h.MAIN.read_bytes()
 run([cli,'policy','enable','NET','ssh_use_pam'])
 applied=run([cli,'policy','apply','NET','ssh_use_pam'])
 assert '#@FIC_POLICY_BEGIN name=ssh_use_pam@' in h.MAIN.read_text()
 records=[r for r in journal()['records'] if r['policy']['policy']=='ssh_use_pam' and r['status']=='applied'];assert len(records)==1
 owned=h.MAIN.read_bytes();provenance=journal();active=state()
 effective=run(['/usr/sbin/sshd','-T']);run(['/usr/sbin/sshd','-t']);assert 'usepam yes\n' in effective
 assert before['InvocationID']!=active['InvocationID'] and active['MainPID']!='0'
 # Kernel listening sockets must be retained by both systemd and this sshd.
 def fds(pid):
  import os
  result=set()
  for p in Path('/proc/'+str(pid)+'/fd').iterdir():
   try:link=os.readlink(p)
   except FileNotFoundError:continue
   if link.startswith('socket:['):result.add(int(link[8:-1]))
  return result
 listeners={int(line.split()[9]) for line in Path('/proc/net/tcp').read_text().splitlines()[1:] if line.split()[3]=='0A' and line.split()[1].endswith(':08AE')}
 assert listeners and listeners<=fds(1)&fds(active['MainPID'])
 run([cli,'policy','apply','NET','ssh_use_pam']);assert h.MAIN.read_bytes()==owned and journal()==provenance and state()==active
 disabled=run([cli,'policy','disable','NET','ssh_use_pam'])
 assert 'RuntimeVerified' in disabled and h.MAIN.read_bytes()==original,disabled
 assert not any(r['status'] in ['prepared','applied','rollback_failed'] for r in journal()['records'] if r['policy']['policy']=='ssh_use_pam')
 assert 'usepam no\n' in run(['/usr/sbin/sshd','-T']);run(['/usr/sbin/sshd','-t'])
 report['cases'].append({'name':label,'apply_stdout':applied,'disable_stdout':disabled,'journal_record':records[0], 'before':before,'active':active,'listeners':sorted(listeners),'repeat_no_change':True,'persistent_restored_exactly':True,'status':'PASS'});save()
report['status']='PASS';save();print('PASS installed production fic-cli policy apply NET ssh_use_pam; both environments, repeat and RuntimeVerified disable')
