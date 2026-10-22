"""Real dpkg/apt ordering/availability; dummy runtime, NOT FIC security proofs."""
import os
assert os.environ.get('FIC_FINALIZER_RESEARCH')=='1'
from pathlib import Path
import subprocess
import sys
gated="--retention-gate" in sys.argv
r=Path('/var/lib/m1-runtime-order');r.mkdir(parents=True)
helper='/usr/libexec/fic-m1-runtime-probe'
log=r/'phases'

def run(args, success=True):
    p=subprocess.run(args,text=True,capture_output=True,timeout=90)
    print(p.stdout+p.stderr,flush=True)
    if success:assert p.returncode==0,(args,p.returncode)
    return p

def build(kind,version):
    name='fic-m1-'+kind+'-probe';root=r/(kind+str(version));(root/'DEBIAN').mkdir(parents=True)
    control='Package: '+name+'\nVersion: '+str(version)+'\nArchitecture: all\nMaintainer: Test <test@example.invalid>\nDescription: isolated runtime ordering\n'
    if kind=='main':control+='Pre-Depends: fic-m1-runtime-probe (= '+str(version)+')\n'
    (root/'DEBIAN/control').write_text(control)
    if kind=='runtime':
        target=root/helper.lstrip('/');target.parent.mkdir(parents=True)
        target.write_text('#!/bin/sh\necho '+str(version)+'\n');target.chmod(0o755)
    else:
        data=root/'usr/share/fic-m1-order/data';data.parent.mkdir(parents=True);data.write_text(str(version))
    for phase in ('preinst','postinst','prerm','postrm'):
        body='#!/bin/sh\nset -e\nprintf "'+kind+str(version)+' '+phase+' $1 helper=" >> '+str(log)+'\n'
        body+='if [ -x '+helper+' ]; then '+helper+' >> '+str(log)+'; else echo absent >> '+str(log)+'; fi\n'
        if kind=='main' and phase=='preinst':body+='test "$('+helper+')" = '+str(version)+'\n'
        if kind=='main' and phase=='postinst':body+='if [ "$1" = configure ] && [ -f '+str(r/'fail-configure')+' ]; then exit 1; fi\n'
        if kind=='main' and phase=='prerm':body+='if [ "$1" = remove ] && [ -f '+str(r/'fail-remove')+' ]; then exit 1; fi\n'
        if gated and kind=='runtime' and phase=='prerm':
            body+='if [ "$1" = remove ] && [ ! -f '+str(r/'removal-finalized')+' ]; then echo "RETENTION: final proof required in earlier completed transaction" >&2; exit 1; fi\n'
        p=root/'DEBIAN'/phase;p.write_text(body);p.chmod(0o755)
    archive=r/(kind+str(version)+'.deb');run(['dpkg-deb','--build',str(root),str(archive)]);return archive

runtime1=build('runtime',1);main1=build('main',1)
runtime2=build('runtime',2);main2=build('main',2)
# Missing/mismatched prerequisites refuse before main preinst runs.
p=run(['dpkg','-i',str(main1)],False);assert p.returncode!=0
assert not log.exists()
run(['apt-get','-y','install',str(main1),str(runtime1)])
assert 'main1 preinst install helper=1' in log.read_text()
before=log.read_text();p=run(['dpkg','-i',str(main2)],False)
assert p.returncode!=0 and log.read_text()==before
run(['apt-get','-y','install',str(main2),str(runtime2)])
assert 'main2 preinst upgrade helper=2' in log.read_text()
run(['apt-get','-y','--allow-downgrades','install',str(main1),str(runtime1)])
assert 'main1 preinst upgrade helper=1' in log.read_text()
# Failed configure is honestly half-configured, configure-a repairs package state.
(r/'fail-configure').touch()
p=run(['dpkg','-i',str(main1)],False);assert p.returncode!=0
assert 'half-configured' in run(['dpkg-query','-W','-f=${Status}','fic-m1-main-probe']).stdout
(r/'fail-configure').unlink();run(['dpkg','--configure','-a'])
# Aborted remove must keep helper available to main postinst abort-remove.
(r/'fail-remove').touch();p=run(['dpkg','--remove','fic-m1-main-probe'],False);assert p.returncode!=0
assert 'main1 postinst abort-remove helper=1' in log.read_text()
(r/'fail-remove').unlink()
# Test actual resolver ordering, not a handwritten assumed sequence.
result=run(['apt-get','-y','purge','fic-m1-main-probe','fic-m1-runtime-probe'],not gated)
if gated:
    assert result.returncode!=0 and Path(helper).exists()
    # Finish main purge while the runtime is still retained. Real production
    # finalizer will need full proofs; this marker only models delivery ordering.
    run(['dpkg','--purge','fic-m1-main-probe'])
    q=run(['dpkg-query','-W','-f=${Status}','fic-m1-main-probe'],False)
    assert q.returncode!=0 or 'not-installed' in q.stdout
    (r/'removal-finalized').touch()
    run(['apt-get','-y','purge','fic-m1-runtime-probe'])
lines=log.read_text().splitlines();print('PHASES:\n'+'\n'.join(lines))
assert 'main1 postrm remove helper=1' in lines
if gated:
    assert 'main1 postrm purge helper=1' in lines
    print('PASS retention prototype: joint purge refused before helper loss; main purge sees runtime; later runtime purge permitted')
else:
    assert 'main1 postrm purge helper=absent' in lines
    print('PASS transport prerequisites: fresh/upgrade/downgrade, incompatible refusal, configure failure/abort')
    print('RED reproduced: Pre-Depends does NOT retain runtime through main postrm purge in joint apt purge')
assert any(x.startswith('runtime1 postrm remove helper=absent') for x in lines)
print('RED reproduced: runtime own postrm cannot execute its payload; retained tombstone/proof prerequisite is necessary')
