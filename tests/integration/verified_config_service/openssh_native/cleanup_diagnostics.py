#!/usr/bin/env python3
"""Bounded real SSH apply/error Logger→journald and release/snapshot diagnostics."""
import importlib.util
import json
import os
import shutil
import sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('h','/usr/local/bin/fic-openssh-harness.py')
h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h);h.guard()
assert os.statvfs('/sys').f_flag & os.ST_RDONLY
assert os.statvfs('/proc/sys').f_flag & os.ST_RDONLY
assert sys.argv[1]=='debian-12', 'this focused fixture uses the measured Debian12 profile'
ctl=lambda *args,**kw:h.run(['systemctl',*args],**kw)
for parent in (h.MAIN.parent,h.ENV.parent):
    h.run(['mount','--bind',str(parent),str(parent)]);h.run(['mount','--make-private',str(parent)])
h.DROP.mkdir(exist_ok=True);h.run(['ssh-keygen','-A']);Path('/run/sshd').mkdir(exist_ok=True)
report={'platform':sys.argv[1],'cases':[]}
def save():(h.OUT/'cleanup-diagnostics.json').write_text(json.dumps(report,indent=2))
def reset():
    ctl('stop','ssh.service')
    h.drive('cleanup',{'paths':[]})
    shutil.rmtree(h.WORK/'module-state',ignore_errors=True)
    for p in h.DROP.iterdir():
        if p.is_dir():shutil.rmtree(p)
        else:p.unlink()
    h.MAIN.write_text(h.config(extra='MaxAuthTries 3\n'));h.MAIN.chmod(0o644)
    h.ENV.write_text('SSHD_OPTS=\n');h.ENV.chmod(0o644)
    ctl('enable','ssh.service');ctl('daemon-reload');ctl('start','ssh.service')
def req(operations):
    r=h.request();r.update(policies={'ssh_use_pam':'yes'},operations=operations);return r
reset()
# Invoke the actual policy in a transient unit with ordinary Logger stdout→journal.
p=h.WORK/'request.json';p.write_text(json.dumps(req([dict(policy='ssh_use_pam',value='yes',fault='cleanup')])))
args=['systemd-run','--unit=fic-cleanup-logging','--wait','--property=StandardOutput=journal','--property=StandardError=journal']
for name in ('FIC_OPENSSH_DISPOSABLE','FIC_OPENSSH_HOST_MNT','FIC_OPENSSH_HOST_ROOT'):
    args+=['--setenv='+name+'='+os.environ[name]]
h.run(args+[h.DRIVER,'module',str(p)],timeout=240)
r=json.loads((h.WORK/'last-output.json').read_text());row=r['module'][0]
assert not row['applied'] and any(x['status']=='prepared' for x in row['journal_after']['records']),row
errors=[x['message'] for x in row['logs'] if x['level']=='ERROR' and 'status=CleanupFailed' in x['message']]
assert len(errors)==1,row
message=errors[0]
assert 'primaryStatus=Success' in message and 'stage=umount2' in message and 'errno=16 (' in message,message
assert 'cleanup target='+str(h.MAIN) in message,message
h.run(['journalctl','--sync'])
journal=h.run(['journalctl','--no-pager','-u','fic-cleanup-logging.service','-o','cat']).stdout
assert '[ERROR] '+message in journal,journal
report['cases'].append({'name':'policy-error-reaches-journald','row':row,'journal_error':message});save()
reset()
r=h.drive('module',req([dict(policy='ssh_use_pam',value='yes')]))
assert r['module'][0]['applied'] and not any('status=CleanupFailed' in x['message'] for x in r['module'][0]['logs']),r
report['cases'].append({'name':'success-no-cleanup-errors','result':r});save()
r=h.drive('module',req([dict(policy='ssh_use_pam',value='yes',rollback=True,fault='release-cleanup')]))
row=r['module'][0];assert not row['applied'],r
assert 'primaryStatus=Success status=CleanupFailed' in row['release_message'] and 'stage=umount2' in row['release_message'] and 'errno=16 (' in row['release_message'],r
report['cases'].append({'name':'verified-release-cleanup-detail','result':r});save()
reset()
r=h.request();r.update(planned_main=h.MAIN.read_text(),policies={},cleanup_fault=True)
r=h.drive('plan-release',r)
assert r.get('validated') is False and r['status']=='CleanupFailed' and r['main_unchanged'] and r['service_unchanged'],r
assert 'primaryStatus=Success status=CleanupFailed' in r['diagnostic'] and 'stage=umount2' in r['diagnostic'] and 'errno=16 (' in r['diagnostic'],r
report['cases'].append({'name':'snapshot-validation-cleanup-detail','result':r});save()
h.drive('cleanup',{'paths':[]});ctl('stop','ssh.service')
report['status']='PASS';save();print('PASS real SSH cleanup diagnostics, ERROR journald, active release and snapshot')
