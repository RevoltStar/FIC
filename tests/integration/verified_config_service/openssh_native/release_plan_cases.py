#!/usr/bin/env python3
"""Native planned-main validation under the common pinned snapshot engine."""
import importlib.util
import json
import sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('h','/usr/local/bin/fic-openssh-harness.py')
h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h);h.guard()
platform=sys.argv[1];alt=platform=='alt-p11';ubuntu=platform.startswith('ubuntu-')
if alt:
    h.MAIN=Path('/etc/openssh/sshd_config');h.ENV=Path('/etc/sysconfig/sshd')
    h.DROP=Path('/etc/openssh/sshd_config.local.d');h.KEY=Path('/etc/openssh/ssh_host_ed25519_key')
unit='sshd.service' if alt else 'ssh.service'
ctl=lambda *args,**kw:h.run(['systemctl',*args],**kw)
Path('/run/fic').mkdir(exist_ok=True)
for parent in (h.MAIN.parent,h.ENV.parent):
    h.run(['mount','--bind',str(parent),str(parent)]);h.run(['mount','--make-private',str(parent)])
h.DROP.mkdir(exist_ok=True);h.run(['ssh-keygen','-A']);Path('/run/sshd').mkdir(exist_ok=True)
base=f'Port 2222\nListenAddress 127.0.0.1\nHostKey {h.KEY}\nPermitRootLogin no\nPubkeyAuthentication yes\nUsePAM yes\nMaxAuthTries 3\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n'
h.MAIN.write_text(base);h.MAIN.chmod(0o600 if alt else 0o644)
h.ENV.write_text('EXTRAOPTIONS=\n' if alt else 'SSHD_OPTS=\n');h.ENV.chmod(0o644)
ctl('enable','ssh.socket' if ubuntu else unit);ctl('daemon-reload');ctl('start','ssh.socket' if ubuntu else unit)
report={'platform':platform,'cases':[]}
def case(name,planned,policies,expected=True):
    req=h.request();req.update(planned_main=planned,policies=policies)
    data=h.drive('plan-release',req)
    report['cases'].append({'name':name,'result':data});(h.OUT/'release-plan-results.json').write_text(json.dumps(report,indent=2))
    assert data['validated']==expected,(name,data)
    assert data['main_unchanged'] and data['service_unchanged'] and not data['readinessConfirmed'],(name,data)
relaxed=base.replace('PermitRootLogin no','PermitRootLogin yes')
case('last-selection-released',relaxed,{})
case('remaining-selection-preserved',relaxed,{'ssh_max_auth_tries':'3'})
case('remaining-selection-violation',relaxed.replace('MaxAuthTries 3','MaxAuthTries 4'),{'ssh_max_auth_tries':'3'},False)
case('invalid-resulting-syntax',relaxed+'FicInvalidDirective yes\n',{},False)
case('unsupported-resulting-include',relaxed+'Include /opt/foreign.conf\n',{},False)
case('safe-planned-match',relaxed+'Match User root\nMaxAuthTries 2\n',{'ssh_max_auth_tries':'3'})
case('weak-planned-match',relaxed+'Match User root\nMaxAuthTries 4\n',{'ssh_max_auth_tries':'3'},False)
ctl('stop',unit,'ssh.socket',check=False)
ctl('disable','ssh.socket' if ubuntu else unit)
case('stopped-disabled-no-start',relaxed,{'ssh_max_auth_tries':'3'})
assert report['cases'][-1]['result']['offline']
report['status']='PASS';(h.OUT/'release-plan-results.json').write_text(json.dumps(report,indent=2))
print(json.dumps({'platform':platform,'status':'PASS','cases':len(report['cases'])}))
