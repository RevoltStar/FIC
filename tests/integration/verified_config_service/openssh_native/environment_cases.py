#!/usr/bin/env python3
"""I1: real SSH adapter/module environment proofs, only guarded disposable Ubuntu."""
import importlib.util
import json
import shutil
from pathlib import Path
spec=importlib.util.spec_from_file_location('native','/usr/local/bin/fic-openssh-harness.py')
h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h);h.guard()
ctl=lambda *a,**kw:h.run(['systemctl',*a],**kw)
keys=['LANG','LC_ALL','PATH','XDG_DATA_DIRS','FIC_ENV_I1_UNKNOWN']
locales=['LC_ADDRESS','LC_IDENTIFICATION','LC_MEASUREMENT','LC_MONETARY','LC_NAME','LC_NUMERIC','LC_PAPER','LC_TELEPHONE','LC_TIME']
keys+=locales
baseline=['LANG=ru_RU.UTF-8','PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/snap/bin']+[k+'=ru_RU.UTF-8' for k in locales]
xdg='XDG_DATA_DIRS=/var/lib/flatpak/exports/share:/usr/local/share/:/usr/share/'
report={'cases':[],'scope':'actual adapter/module, not daemon CLI; daemon CLI gate recorded separately'}
def save():(h.OUT/'environment-results.json').write_text(json.dumps(report,indent=2))
for parent in (h.MAIN.parent,h.ENV.parent):
 h.run(['mount','--bind',str(parent),str(parent)]);h.run(['mount','--make-private',str(parent)])
h.DROP.mkdir(exist_ok=True);h.run(['ssh-keygen','-A']);Path('/run/sshd').mkdir(exist_ok=True);Path('/run/fic').mkdir(exist_ok=True)
def reset(environment=baseline):
 ctl('stop','ssh.service','ssh.socket',check=False);h.drive('cleanup',{'paths':[]})
 ctl('unset-environment',*keys);ctl('set-environment',*environment)
 for p in h.DROP.iterdir():
  if p.is_dir():shutil.rmtree(p)
  else:p.unlink()
 h.MAIN.write_text(h.config(extra='MaxAuthTries 3\n').replace('PubkeyAuthentication no','PubkeyAuthentication yes').replace('UsePAM no','UsePAM yes'))
 h.MAIN.chmod(0o644);h.ENV.write_text('SSHD_OPTS=\n');h.ENV.chmod(0o644)
 shutil.rmtree(h.WORK/'module-state',ignore_errors=True)
 ctl('disable','ssh.service',check=False);ctl('enable','ssh.socket');ctl('daemon-reload');ctl('reset-failed','ssh.service','ssh.socket',check=False);ctl('start','ssh.socket')
 # Ensure the same supported stable service profile for post-restart fault hooks.
 h.handshake(2222)
for name,environment in [('r1-baseline',baseline),('reported-xdg',baseline+[xdg]),('snap-exports',baseline+['XDG_DATA_DIRS=/usr/share:/var/lib/snapd/desktop/:/usr/local/share/'])]:
 reset(environment);req=h.request();before=h.state();data=h.drive('adapter',req);after=h.state()
 report['cases'].append({'name':name,'result':data,'before':before,'after':after});save()
 assert data['adapter_success'] and data['A']==data['C']==data['P']=='Proven' and data['readinessConfirmed'],data
 assert before['InvocationID']!=after['InvocationID'] and h.reference_matches(req)
mutations=[('supported-value',['LANG=en_US.UTF-8'],[]),('unsupported-value',['LANG=bad/path'],[]),
 ('addition',['LC_ALL=C'],[]),('removal',[],['LANG']),('path',['PATH=/usr/sbin:/usr/bin:/sbin:/bin'],[]),
 ('xdg',['XDG_DATA_DIRS=/usr/share:/usr/local/share'],[]),('same-keys',['LC_TIME=de_DE.UTF-8'],[])]
for stage in ['before','watching','after']:
 for name,assignments,removed in mutations:
  reset(baseline+[xdg]);req=h.request();req.update(manager_set=assignments,manager_unset=removed)
  before=h.state();data=h.drive('adapter-manager-'+stage,req);after=h.state()
  report['cases'].append({'name':name+'-'+stage,'result':data});save()
  assert not data['adapter_success'] and data['status']=='InterferenceDetected',(name,stage,data)
  assert h.reference_matches(req),(name,stage,'persistent input drift')
  if stage!='after':assert before['InvocationID']==after['InvocationID'],data
reset(baseline+['FIC_ENV_I1_UNKNOWN=PRIVATE_VALUE'])
before=h.MAIN.read_bytes();req=h.request();req['operations']=[{'policy':'ssh_use_pam','value':'yes'}]
data=h.drive('module',req);report['cases'].append({'name':'unknown-before-policy-save','result':data});save()
assert not data['module'][0]['applied'] and h.MAIN.read_bytes()==before,data
assert not data['module'][0]['records'] and not data['module'][0]['journal_after']['records'],data
assert 'PRIVATE_VALUE' not in json.dumps(data),data
ctl('unset-environment',*keys);report['status']='PASS';save()
print('PASS I1 manager environment native proofs: 3 positives, 21 interference barriers, pre-save refusal')
