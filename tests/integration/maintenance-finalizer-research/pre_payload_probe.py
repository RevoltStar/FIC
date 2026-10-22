"""Native bootstrap availability probe, dummy payload only; disposable opt-in."""
import os
assert os.environ.get('FIC_FINALIZER_RESEARCH') == '1'
from pathlib import Path
import subprocess
import sys
r=Path('/var/lib/m1-pre-payload');r.mkdir(parents=True)
helper='/usr/libexec/fic-m1-payload-helper'
phase='''printf 'PRE_PAYLOAD_HELPER='
if [ -x /usr/libexec/fic-m1-payload-helper ]; then /usr/libexec/fic-m1-payload-helper; else echo absent; fi
'''
def run(args):
    p=subprocess.run(args,capture_output=True,text=True,timeout=90)
    print(p.stdout+p.stderr,flush=True)
    assert p.returncode==0,(args,p.returncode)
    return p.stdout+p.stderr
for version in (1,2):
    if sys.argv[1]=='deb':
        pkg=r/str(version);(pkg/'DEBIAN').mkdir(parents=True)
        target=pkg/helper.lstrip('/');target.parent.mkdir(parents=True)
        target.write_text('#!/bin/sh\necho '+str(version)+'\n');target.chmod(0o755)
        (pkg/'DEBIAN/control').write_text('Package: fic-m1-payload-probe\nVersion: '+str(version)+'\nArchitecture: all\nMaintainer: Test <test@example.invalid>\nDescription: isolated bootstrap availability\n')
        (pkg/'DEBIAN/preinst').write_text('#!/bin/sh\nset -e\n'+phase)
        (pkg/'DEBIAN/preinst').chmod(0o755)
        (pkg/'DEBIAN/postinst').write_text('#!/bin/sh\nprintf "POST_PAYLOAD_HELPER="\n'+helper+'\n')
        (pkg/'DEBIAN/postinst').chmod(0o755)
        archive=r/(str(version)+'.deb');run(['dpkg-deb','--build',str(pkg),str(archive)])
        output=run(['dpkg','-i',str(archive)])
    else:
        spec=r/'probe.spec'
        spec.write_text('''Name: fic-m1-payload-probe
Version: %d
Release: 1
Summary: isolated bootstrap availability
License: MIT
Group: Development/Other
BuildArch: noarch
AutoReqProv: no
%%description
Research only
%%install
mkdir -p %%buildroot/usr/libexec
printf '#!/bin/sh\\necho %d\\n' > %%buildroot/usr/libexec/fic-m1-payload-helper
chmod 755 %%buildroot/usr/libexec/fic-m1-payload-helper
%%pre
%s
%%post
printf 'POST_PAYLOAD_HELPER='
/usr/libexec/fic-m1-payload-helper
%%files
/usr/libexec/fic-m1-payload-helper
''' % (version,version,phase))
        run(['chown','-R','m1builder:m1builder',str(r)])
        run(['runuser','-u','m1builder','--','rpmbuild','--define','_topdir '+str(r/'build'),'-bb',str(spec)])
        archives=list((r/'build/RPMS').rglob('fic-m1-payload-probe-'+str(version)+'-1*.rpm'))
        assert len(archives)==1
        output=run(['rpm','-Uvh',str(archives[0])])
    assert 'PRE_PAYLOAD_HELPER='+('absent' if version==1 else '1') in output
    assert 'POST_PAYLOAD_HELPER='+str(version) in output
print('PASS: first pre-script has no helper; upgrade pre-script sees only OLD helper; new helper appears after payload',flush=True)
