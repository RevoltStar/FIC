#!/usr/bin/env python3
"""Build tiny packaging fixtures with production generators; never install them.

Native lifecycle gates separately exercise real FIC payloads and systemd.
"""
from pathlib import Path
import os
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[3]
UNIT = 'fic_get_device_info.service'


def run(args, **kwargs):
    result = subprocess.run(args, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, **kwargs)
    assert result.returncode == 0, f'{args}: exit {result.returncode}\n{result.stdout}\n{result.stderr}'
    return result.stdout


def function(source, name):
    found = re.search(r'^' + name + r'\(\) \{.*?^\}', source, re.M | re.S)
    assert found, name
    return found.group(0)


def check_script(script, temp):
    assert script.index('--maintenance initialize-db') < script.index('--maintenance complete-install')
    enables = [line for line in script.splitlines() if line.startswith('systemctl enable ')]
    assert any(UNIT in line.split() for line in enables), enables
    assert script.index('--maintenance complete-install') < script.index(enables[0])
    assert 'restart ' + UNIT not in script
    # Execute the actual packaged startup tail with command doubles, including
    # failure injection. No absolute product executable or host write is run.
    tail = script[script.index('/opt/fic/bin/fic --maintenance complete-install'):]
    tail = tail.replace('/opt/fic/bin/fic --maintenance', 'fic --maintenance')
    bindir = temp / 'mock-bin'
    bindir.mkdir(exist_ok=True)
    mock = '''#!/bin/sh
name=${0##*/}
echo "$name $*" >> "$EVENTS"
case "$name $*" in
  'fic --maintenance complete-install') exit "$ADMISSION_STATUS" ;;
  'systemctl start fic_get_device_info.service') exit "$COLLECTOR_STATUS" ;;
esac
exit 0
'''
    for name in ('fic', 'systemctl', 'systemd-tmpfiles', 'ln'):
        path = bindir / name
        path.write_text(mock)
        path.chmod(0o755)
    for admission, collector in ((0, 0), (0, 1), (1, 0)):
        events = temp / 'events'
        events.write_text('')
        result = subprocess.run(['/bin/sh', '-eu', '-c', tail], text=True, capture_output=True,
                                env=dict(os.environ, PATH=str(bindir), EVENTS=str(events),
                                         ADMISSION_STATUS=str(admission), COLLECTOR_STATUS=str(collector)))
        commands = events.read_text().splitlines()
        if admission:
            assert result.returncode != 0 and len(commands) == 1, (commands, result)
        else:
            assert result.returncode == 0, result.stderr
            assert commands.count('systemctl start ' + UNIT) == 1, commands
            assert ('WARNING: CPU/board/memory collection failed' in result.stderr) == bool(collector)


def main():
    checked = []
    with tempfile.TemporaryDirectory(prefix='fic-inventory-packaging-') as directory:
        temp = Path(directory)
        deb = (ROOT / 'packaging/deb/build-fic-debian12-deb.sh').read_text()
        rpm = (ROOT / 'packaging/rpm/build-fic-alt-p11-rpm.sh').read_text()
        assert 'write_system_integration_symlink_postinst ' in function(deb, 'build_fic_package')
        assert '"$(system_integration_symlink_post_script)"' in function(rpm, 'build_fic_package')
        if shutil.which('dpkg-deb'):
            for platform in ('debian-12', 'debian-13'):
                deb_temp = temp / platform
                stage = deb_temp / 'deb'
                (stage / 'DEBIAN').mkdir(parents=True)
                (stage / 'DEBIAN/control').write_text('Package: fic\nVersion: 0.1\nArchitecture: all\n'
                                                    'Maintainer: FIC tests <fic@example.invalid>\n'
                                                    'Description: packaging contract fixture\n')
                run(['bash', '-eu', '-c', function(deb, 'write_system_integration_symlink_postinst') +
                     '\nROOT_DIR=$1\nwrite_system_integration_symlink_postinst "$2"',
                     'bash', str(ROOT), str(stage)],
                     env=dict(os.environ, FIC_PACKAGING_TARGET_PLATFORM=platform))
                archive = deb_temp / 'fic.deb'
                run(['dpkg-deb', '--build', str(stage), str(archive)])
                control = deb_temp / 'control'
                run(['dpkg-deb', '--control', str(archive), str(control)])
                script = (control / 'postinst').read_text()
                d13_hook = 'yes' if platform == 'debian-13' else 'no'
                assert f"if [ '{d13_hook}' = yes ]; then" in script, platform
                check_script(script, deb_temp)
                checked.append(f'DEB ({platform})')
        if shutil.which('rpmbuild') and shutil.which('rpm'):
            for name in ('BUILD', 'BUILDROOT', 'RPMS', 'SOURCES', 'SPECS', 'SRPMS'):
                (temp / name).mkdir()
            payload = temp / 'payload'
            payload.mkdir()
            (payload / 'fic-inventory-packaging-fixture').write_text('packaging contract fixture\n')
            run(['tar', '-C', str(payload), '-czf', str(temp / 'SOURCES/fixture.tar.gz'), '.'])
            (temp / 'SOURCES/fixture.files').write_text('/fic-inventory-packaging-fixture\n')
            spec = temp / 'SPECS/fic.spec'
            run(['bash', '-eu', '-c', function(rpm, 'write_spec_file') + '\n' +
                 function(rpm, 'system_integration_symlink_post_script') +
                 '\nROOT_DIR=$1\nPACKAGE_VERSION=0.1\nRPM_RELEASE=1\nARCH=noarch\n'
                 'write_spec_file "$2" fic fixture fixture "" fixture.tar.gz fixture.files "" '
                 '"$(system_integration_symlink_post_script)" ""', 'bash', str(ROOT), str(spec)])
            run(['bash', '-eu', '-c', function(rpm, 'run_rpmbuild') +
                 '\nRPM_TOPDIR=$1\nRPM_ALLOW_ROOT_BUILD=1\nrun_rpmbuild "$2"',
                 'bash', str(temp), str(spec)])
            archives = list((temp / 'RPMS').rglob('*.rpm'))
            assert len(archives) == 1, archives
            script = run(['rpm', '-qp', '--qf', '%{POSTIN}', str(archives[0])])
            check_script(script, temp)
            checked.append('RPM')
        if not checked:
            print('SKIP: no native package builder available')
            return 77
    unit = (ROOT / 'fic/src/resources/service' / (UNIT + '.in')).read_text()
    assert 'Type=oneshot' in unit and 'RemainAfterExit=yes' in unit and 'WantedBy=multi-user.target' in unit
    print('PASS: ' + ', '.join(checked) + ' archive scripts: admission, enable/start and nonfatal collector failure')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
