"""Run ONLY in disposable containers; no FIC package or security hooks installed."""
import os
from pathlib import Path
import subprocess
import tempfile
assert os.environ.get('FIC_FINALIZER_RESEARCH') == '1', 'explicit disposable research opt-in required'
r=Path('/var/lib/m1-dpkg-research');r.mkdir(parents=True)
pkg=r/'package';(pkg/'DEBIAN').mkdir(parents=True)
(pkg/'DEBIAN/control').write_text('Package: fic-m1-status-probe\nVersion: 1\nArchitecture: all\nMaintainer: Test <test@example.invalid>\nDescription: isolated status research\n')
(pkg/'DEBIAN/triggers').write_text('interest-noawait m1-research-trigger\n')
(pkg/'DEBIAN/postinst').write_text('''#!/bin/sh
set -e
if [ "$1" = triggered ]; then
 printf 'INSIDE_TRIGGER: '
 dpkg-query -W -f='${Status}\\n' fic-m1-status-probe
 exit 0
fi
printf 'INSIDE_POSTINST: '
dpkg-query -W -f='${Status}\\n' fic-m1-status-probe
if [ -f /var/lib/m1-dpkg-research/fail ]; then exit 1; fi
dpkg-trigger --no-await m1-research-trigger
''')
(pkg/'DEBIAN/postinst').chmod(0o755)
def run(args):
 p=subprocess.run(args,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=60)
 print(p.stdout,flush=True);return p
assert run(['dpkg-deb','--build',str(pkg),str(r/'probe.deb')]).returncode==0
(r/'lock_probe.py').write_text("""import fcntl,subprocess
print('POST_INVOKE_STATE:',subprocess.check_output(['dpkg-query','-W','-f=${Status}','fic-m1-status-probe'],text=True))
for path in ('/var/lib/dpkg/lock','/var/lib/dpkg/lock-frontend'):
 f=open(path,'r+')
 try:
  fcntl.lockf(f,fcntl.LOCK_EX|fcntl.LOCK_NB);print(path,'FREE');fcntl.lockf(f,fcntl.LOCK_UN)
 except BlockingIOError:print(path,'HELD')
""")
post='--post-invoke=python3 '+str(r/'lock_probe.py')
(r/'fail').touch()
assert run(['dpkg',post,'-i',str(r/'probe.deb')]).returncode!=0
p=run(['dpkg-query','-W','-f=${Status}\n','fic-m1-status-probe'])
assert p.stdout.strip()=='install ok half-configured'
(r/'fail').unlink()
assert run(['dpkg',post,'--configure','-a']).returncode==0
p=run(['dpkg-query','-W','-f=${Status}\n','fic-m1-status-probe'])
assert p.stdout.strip()=='install ok installed'
assert run(['apt-get','-o','DPkg::Post-Invoke::=python3 '+str(r/'lock_probe.py'),'-y','--reinstall','install',str(r/'probe.deb')]).returncode==0
print('PASS: failed postinst → half-configured → dpkg --configure -a → installed; apt reinstall')
