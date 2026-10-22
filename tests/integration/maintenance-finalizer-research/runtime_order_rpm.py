"""Real ALT RPM ordering; dummy packages only, no FIC security proofs."""
import os
assert os.environ.get('FIC_FINALIZER_RESEARCH')=='1'
from pathlib import Path
import subprocess
import sys
gated="--retention-gate" in sys.argv
r=Path('/var/lib/m1-runtime-order-rpm-gated' if gated else '/var/lib/m1-runtime-order-rpm');r.mkdir(parents=True)
helper='/usr/libexec/fic-m1-rpm-runtime-probe';log=r/'phases'
def run(args,success=True):
    p=subprocess.run(args,text=True,capture_output=True,timeout=90)
    print(p.stdout+p.stderr,flush=True)
    if success:assert p.returncode==0,(args,p.returncode)
    return p

def build(kind,version):
    deps=('Provides: fic-m1-lifecycle-abi = 1\n' if kind=='runtime' else
          'Requires: fic-m1-rpm-runtime-probe = '+str(version)+'\nRequires(pre): fic-m1-rpm-runtime-probe = '+str(version)+'\nRequires(preun,postun): fic-m1-lifecycle-abi = 1\n')
    text=f'''Name: fic-m1-rpm-{kind}-probe
Version: {version}
Release: 1
Summary: isolated runtime ordering
License: MIT
Group: Development/Other
BuildArch: noarch
AutoReqProv: no
{deps}%description
Research only
%install
'''
    if kind=='runtime':text+='mkdir -p %buildroot/usr/libexec\nprintf \'#!/bin/sh\\necho '+str(version)+'\\n\' > %buildroot'+helper+'\nchmod 755 %buildroot'+helper+'\n'
    else:text+='mkdir -p %buildroot/usr/share/fic-m1-rpm-main\necho data > %buildroot/usr/share/fic-m1-rpm-main/data\n'
    for phase in ('pre','post','preun','postun'):
        text+='\n%'+phase+'\nprintf "'+kind+str(version)+' '+phase+' $1 helper=" >> '+str(log)+'\n'
        text+='if [ -x '+helper+' ]; then '+helper+' >> '+str(log)+'; else echo absent >> '+str(log)+'; fi\n'
        if kind=='main' and phase=='pre':text+='test "$('+helper+')" = '+str(version)+' || exit 1\n'
        if kind=='main' and phase=='preun':text+='if [ "$1" = 0 ] && [ -f '+str(r/'fail-remove')+' ]; then exit 1; fi\n'
        if gated and kind=='runtime' and phase=='preun':text+='if [ "$1" = 0 ] && [ ! -f '+str(r/'removal-finalized')+' ]; then echo "RETENTION: earlier transaction final proof required" >&2; exit 1; fi\n'
    text+='\n%files\n'+(helper if kind=='runtime' else '/usr/share/fic-m1-rpm-main/data')+'\n'
    spec=r/(kind+str(version)+'.spec');spec.write_text(text)
    run(['chown','-R','m1builder:m1builder',str(r)])
    run(['runuser','-u','m1builder','--','rpmbuild','--define','_topdir '+str(r/'build'),'-bb',str(spec)])
    archives=list((r/'build/RPMS').rglob('fic-m1-rpm-'+kind+'-probe-'+str(version)+'-1*.rpm'))
    assert len(archives)==1;return archives[0]
rt1=build('runtime',1);main1=build('main',1);rt2=build('runtime',2);main2=build('main',2)
p=run(['rpm','-Uvh',str(main1)],False);assert p.returncode!=0 and not log.exists()
run(['rpm','-Uvh',str(main1),str(rt1)])
assert 'main1 pre 1 helper=1' in log.read_text()
before=log.read_text();p=run(['rpm','-Uvh',str(main2)],False);assert p.returncode!=0 and log.read_text()==before
run(['rpm','-Uvh',str(main2),str(rt2)])
assert 'main2 pre 2 helper=2' in log.read_text()
run(['rpm','-Uvh','--oldpackage',str(main1),str(rt1)])
assert 'main1 pre 2 helper=1' in log.read_text()
(r/'fail-remove').touch();p=run(['rpm','-e','fic-m1-rpm-main-probe'],False);assert p.returncode!=0
run(['rpm','-q','fic-m1-rpm-main-probe']);assert Path(helper).exists()
(r/'fail-remove').unlink()
result=run(['rpm','-e','fic-m1-rpm-runtime-probe','fic-m1-rpm-main-probe'],not gated)
if gated:
    assert result.returncode!=0 and Path(helper).exists()
    assert run(['rpm','-q','fic-m1-rpm-main-probe'],False).returncode!=0
    # Models completed external proof, not an actual FIC verifier.
    (r/'removal-finalized').touch()
    run(['rpm','-e','fic-m1-rpm-runtime-probe'])
lines=log.read_text().splitlines();print('PHASES:\n'+'\n'.join(lines))
assert 'main1 postun 0 helper=1' in lines
assert 'runtime1 postun 0 helper=absent' in lines
print('PASS: native Requires(pre)/erase ABI ordering, fresh/upgrade/downgrade/incompatible refusal/failed erase')
if gated:print('PASS retention prototype: runtime retained through main erase and until modeled post-transaction proof')
print('RED reproduced: runtime own postun cannot execute its payload; package lock still held before transaction return')
