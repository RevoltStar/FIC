#!/usr/bin/env python3
"""Native Match + verified activation; only via guarded disposable runner."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import time
spec=importlib.util.spec_from_file_location('h','/usr/local/bin/fic-openssh-harness.py')
h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
h.guard(); platform=sys.argv[1];alt=platform=='alt-p11';ubuntu=platform.startswith('ubuntu-')
if alt:
    h.MAIN=Path('/etc/openssh/sshd_config');h.ENV=Path('/etc/sysconfig/sshd')
    h.DROP=Path('/etc/openssh/sshd_config.local.d');h.KEY=Path('/etc/openssh/ssh_host_ed25519_key')
unit='sshd.service' if alt else 'ssh.service'
ctl=lambda *args,**kw:h.run(['systemctl',*args],**kw)
Path('/run/fic').mkdir(exist_ok=True);Path('/run/sshd').mkdir(exist_ok=True)
# Isolated test provisioning of private publication boundaries; never product
# topology changes or changes to the host/root mount's propagation.
for parent in (h.MAIN.parent,h.ENV.parent):
    h.run(['mount','--bind',str(parent),str(parent)]);h.run(['mount','--make-private',str(parent)])
h.DROP.mkdir(exist_ok=True)  # explicit test provisioning, not production behavior
h.run(['ssh-keygen','-A'])
original_main=h.MAIN.read_bytes();original_env=h.ENV.read_bytes() if h.ENV.exists() else None
fragment=ctl('show',unit,'-p','FragmentPath','--value').stdout.strip()
vendor_sha=h.sha(fragment)
results=[]
intervals=[]
for target in (unit,'ssh.socket') if ubuntu else (unit,):
    object_name=target.replace('_','_5f').replace('.','_2e').replace('-','_2d')
    value=h.run(['busctl','get-property','org.freedesktop.systemd1',
        '/org/freedesktop/systemd1/unit/'+object_name,'org.freedesktop.systemd1.Unit','StartLimitIntervalUSec']).stdout.split()
    assert len(value)==2 and value[0]=='t' and value[1].isdigit(),value
    intervals.append(int(value[1])/1000000)
assert max(intervals)<=60,intervals
try:
    ctl('stop',unit,'ssh.socket',check=False)
    ctl('enable','ssh.socket' if ubuntu else unit)
    for p in h.DROP.iterdir():
        if p.is_dir():shutil.rmtree(p)
        else:p.unlink()
    base=(f'Port 2222\nListenAddress 127.0.0.1\nHostKey {h.KEY}\n'
          'MaxAuthTries 3\nPermitRootLogin prohibit-password\nPubkeyAuthentication yes\nUsePAM yes\n'
          'PasswordAuthentication no\nKbdInteractiveAuthentication no\n')
    cases=[('max-stricter','Match User root\nMaxAuthTries 2\n',{'ssh_max_auth_tries':'3'},True),
           ('max-weaker','Match User root\nMaxAuthTries 4\n',{'ssh_max_auth_tries':'3'},False),
           ('root-stricter','Match User root\nPermitRootLogin no\n',{'ssh_root_login':'prohibit-password'},True),
           ('root-weaker','Match User root\nPermitRootLogin yes\n',{'ssh_root_login':'prohibit-password'},False),
           ('root-synonym','Match User root\nPermitRootLogin without-password\n',{'ssh_root_login':'prohibit-password'},True),
           ('pubkey-weaker','Match User root\nPubkeyAuthentication no\n',{'ssh_pubkey_auth':'yes'},False),
           ('nested-safe',f'Include {h.DROP}/outer.inc\n',{'ssh_max_auth_tries':'3'},True),
           ('include-return',f'Include {h.DROP}/outer.inc\nMaxAuthTries 4\n',{'ssh_max_auth_tries':'3'},True),
           ('outside', 'Include /opt/custom/ssh.conf\n',{'ssh_max_auth_tries':'3'},False),
           ('unknown-criterion','Match User root exec /bin/true\nMaxAuthTries 2\n',{'ssh_max_auth_tries':'3'},False),
           ('usepam-match','Match User root\nUsePAM yes\n',{'ssh_use_pam':'yes'},False),
           ('port-match','Match all\nPort 2222\n',{'ssh_port':'2222'},False)]
    for name,extra,policies,expected in cases:
        # Independent fixtures must age out their own starts. Never reset or
        # weaken vendor start limits to make activation succeed.
        time.sleep(max(intervals)+0.05)
        ctl('stop',unit,'ssh.socket',check=False)
        for p in h.DROP.iterdir():p.unlink()
        h.MAIN.write_text(base);h.MAIN.chmod(0o600 if alt else 0o644)
        h.ENV.write_text('EXTRAOPTIONS=\n' if alt else 'SSHD_OPTS=\n');h.ENV.chmod(0o644)
        Path('/run/sshd').mkdir(exist_ok=True)
        ctl('daemon-reload');ctl('start','ssh.socket' if ubuntu else unit)
        if name in ('nested-safe','include-return'):
            (h.DROP/'outer.inc').write_text(f'Include {h.DROP}/inner.inc\n')
            (h.DROP/'inner.inc').write_text('Match User root\nMaxAuthTries 2\n')
        if name=='outside':
            Path('/opt/custom').mkdir(exist_ok=True);Path('/opt/custom/ssh.conf').write_text('MaxAuthTries 2\n')
        h.MAIN.write_text(base+extra)
        syntax=h.run([str(Path('/usr/sbin/sshd')), '-t','-f',str(h.MAIN)],check=False)
        effective=h.run(['/usr/sbin/sshd','-T','-f',str(h.MAIN),'-C','user=root,host=localhost,addr=127.0.0.1'],check=False)
        files=[h.MAIN,h.ENV,*sorted(h.MAIN.parent.glob('ssh_host_*_key*'))]
        req={'timeout_ms':15000,'policies':policies,'paths':[{'path':str(p),'sha256':h.sha(p)} for p in files if p.is_file()]}
        req['paths'].append({'path':str(h.DROP),'directory':True,'manifest':{str(p.relative_to(h.DROP)):h.sha(p) for p in h.DROP.rglob('*') if p.is_file()}})
        before=h.sha(h.MAIN);data=h.drive('adapter',req)
        assert data['adapter_success']==expected,(name,data)
        assert h.sha(h.MAIN)==before and h.sha(fragment)==vendor_sha,(name,'persistent/vendor mutation')
        if expected:
            assert syntax.returncode==effective.returncode==0,(name,syntax.stderr,effective.stderr)
            assert data['A']==data['C']==data['P']=='Proven' and data['readinessConfirmed'],(name,data)
            assert h.handshake(2222).startswith('SSH-2.0-')
        else:assert not data['activation_invoked'],(name,data)
        results.append(dict(name=name,result=data,syntax_exit=syntax.returncode,conditional_effective=effective.stdout))
        (h.OUT/'match-results.json').write_text(json.dumps(dict(platform=platform,cases=results),indent=2))
    (h.OUT/'match-results.json').write_text(json.dumps(dict(status='PASS',platform=platform,cases=results,vendor_sha256=vendor_sha),indent=2))
finally:
    (h.OUT/'match-journal.log').write_text(h.run(['journalctl','-u',unit,'-n','60','--no-pager'],check=False).stdout)
    ctl('stop',unit,'ssh.socket',check=False)
    h.MAIN.write_bytes(original_main)
    if original_env is not None:h.ENV.write_bytes(original_env)
print(json.dumps(dict(status='PASS',cases=len(results),platform=platform)))
