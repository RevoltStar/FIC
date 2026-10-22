import os
from pathlib import Path
import subprocess
assert os.environ.get('FIC_FINALIZER_RESEARCH')=='1'
r=Path('/var/lib/m1-rpm-research');r.mkdir(parents=True,exist_ok=True)
def run(args):
 p=subprocess.run(args,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=90)
 print(p.stdout,flush=True);return p
probe=r/'lock.py'
probe.write_text('''import fcntl
f=open('/var/lib/rpm/.rpm.lock','r+')
try:
 fcntl.lockf(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
 print('RPM_TRANSACTION_LOCK=FREE')
except BlockingIOError: print('RPM_TRANSACTION_LOCK=HELD')
''')
(r/'fail').unlink(missing_ok=True)
trigger=Path('/usr/lib/rpm/m1-research.filetrigger')
trigger.write_text("#!/bin/sh\nprintf 'INSIDE_FILETRIGGER: '\nrpm -q fic-m1-status-probe || true\npython3 /var/lib/m1-rpm-research/lock.py\n")
trigger.chmod(0o755)
for release in (1,2):
 spec=r/'probe.spec'
 spec.write_text('''Name: fic-m1-status-probe
Version: 1
Release: %d
Summary: isolated lifecycle research
License: MIT
Group: Development/Other
BuildArch: noarch
AutoReqProv: no
%%description
Research only
%%install
mkdir -p %%buildroot/usr/share/fic-m1-status-probe
echo fixture > %%buildroot/usr/share/fic-m1-status-probe/data
%%post
printf 'INSIDE_POST: '
rpm -q --qf '%%%%{VERSION}-%%%%{RELEASE}\\n' fic-m1-status-probe
python3 /var/lib/m1-rpm-research/lock.py
if [ -f /var/lib/m1-rpm-research/fail ]; then exit 1; fi
%%files
/usr/share/fic-m1-status-probe/data
''' % release)
 run(['chown','-R','m1builder:m1builder',str(r)])
 assert run(['runuser','-u','m1builder','--','rpmbuild','--define','_topdir '+str(r/'build'),'-bb',str(spec)]).returncode==0
 packages=list((r/'build/RPMS').rglob('fic-m1-status-probe-1-'+str(release)+'*.rpm'))
 assert len(packages)==1, packages
 if release==2:(r/'fail').touch()
 result=run(['rpm','-Uvh',str(packages[0])]);print('TRANSACTION_EXIT:',result.returncode)
 print('AFTER_TRANSACTION:',flush=True)
 assert run(['rpm','-q','fic-m1-status-probe']).returncode==0
 assert run(['python3',str(probe)]).returncode==0
print('PASS: native RPM install/upgrade/post failure visibility, filetrigger and transaction lock research')
