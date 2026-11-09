"""Native client package permissions gate; no daemon/policy/IPC claims."""
import errno
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile

assert os.geteuid() == 0 and (Path('/run/.containerenv').exists() or Path('/.dockerenv').exists())
kind, directory, row = sys.argv[1:]
packages = Path(directory)
results = Path('/out')
results.mkdir(exist_ok=True)
events = []

def run(args, ok=True):
    p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=120)
    events.append(dict(command=args, status=p.returncode, output=p.stdout))
    (results/'access-events.json').write_text(json.dumps(events, indent=2))
    print(p.returncode, ' '.join(args), p.stdout[-500:], flush=True)
    if ok:
        assert p.returncode == 0, p.stdout
    return p

def native_package(name, upgrade=False):
    pattern = name+'_*.deb' if kind == 'deb' else name+'-*.rpm'
    found = list((packages/'upgrades' if upgrade else packages).glob(pattern))
    assert len(found) == 1, found
    return str(found[0])

clients = [Path('/opt/fic/bin')/name for name in ('fic-cli', 'fic-gui', 'fic-gui.real')]

def archive_metadata():
    for upgrade in (False, True):
        for name in ('fic-cli', 'fic-gui'):
            package = native_package(name, upgrade)
            expected = ['fic-cli'] if name == 'fic-cli' else ['fic-gui', 'fic-gui.real']
            if kind == 'deb':
                data = subprocess.check_output(['dpkg-deb', '--fsys-tarfile', package])
                with tarfile.open(fileobj=io.BytesIO(data)) as archive:
                    for client in expected:
                        entry = archive.getmember('./opt/fic/bin/'+client)
                        assert (entry.uid, entry.gid, entry.mode) == (0, 0, 0o750), entry
                # Archive IDs are deliberately root:root. Native configure must
                # establish root:fic; both facts are recorded, never conflated.
                run(['dpkg-deb', '-c', package])
            else:
                text = run(['rpm', '-qp', '--qf', '[%{FILENAMES}\t%{FILEUSERNAME}\t%{FILEGROUPNAME}\t%{FILEMODES:perms}\n]', package]).stdout
                entries = {line.split('\t')[0]: line.split('\t')[1:] for line in text.splitlines() if line.startswith('/')}
                for client in expected:
                    assert entries['/opt/fic/bin/'+client] == ['root', 'fic', '-rwxr-x---'], entries
                assert entries['/opt/fic/bin'] == ['root', 'fic', 'drwxr-s---'], entries
    events.append(dict(archive_metadata='PASS', deb_ids='root:root' if kind == 'deb' else None))

run(['groupadd', '-r', 'fic'])
run(['useradd', '-m', '-G', 'fic', 'ficmember'])
run(['useradd', '-m', 'ficoutsider'])
run(['id', 'ficmember'])
run(['id', 'ficoutsider'])
run(['install', '-d', '-o', 'root', '-g', 'fic', '-m', '2750', '/opt/fic'])
# Persistent sentinels deliberately use differing permissions/groups. Only
# client packages are installed; unrelated daemon lifecycle is not simulated.
for name in ('config', 'db', 'log', 'notify'):
    directory_path = Path('/opt/fic')/name
    directory_path.mkdir(mode=0o700)
    sentinel = directory_path/'client-permissions-sentinel'
    sentinel.write_text('preserve owner/group/mode/ctime/content')
    sentinel.chmod(0o640)
    names = {'config': ('GLOBAL.conf',),
             'db': ('devices.db', 'mutation-journal.json', 'mutation-journal.json.initialized', 'incident-state.json'),
             'log': ('fic.log',), 'notify': ('pending-message',)}[name]
    for filename in names:
        path = directory_path/filename
        path.write_text('metadata-only fixture; daemon is not run')
        path.chmod(0o600)

def persistent_metadata():
    output = {}
    for name in ('config', 'db', 'log', 'notify'):
        base = Path('/opt/fic')/name
        for path in [base, *base.iterdir()]:
            info = path.stat()
            output[str(path)] = [info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_ino,
                                 info.st_mtime_ns, info.st_ctime_ns,
                                 path.read_text() if path.is_file() else None]
    return output

original = persistent_metadata()
os_release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
os_release = {key: value.strip('"') for key, value in os_release.items()}
expected = {'debian12': ('debian', '12'), 'debian13': ('debian', '13'),
            'ubuntu2404': ('ubuntu', '24.04'), 'ubuntu2604': ('ubuntu', '26.04'),
            'altp11': ('altlinux', '11')}
assert (os_release['ID'], os_release['VERSION_ID']) == expected[row], os_release
if row == 'altp11':
    assert os_release['ALT_BRANCH_ID'] == 'p11'
events.append(dict(os_release=os_release))
run(['dpkg', '--version'] if kind == 'deb' else ['rpm', '--version'])
archive_metadata()

def validate_metadata(payload):
    for path, mode in [(Path('/opt/fic'), 0o2750), (Path('/opt/fic/bin'), 0o2750), *[(p, 0o750) for p in payload]]:
        info = path.lstat()
        assert not path.is_symlink() and info.st_uid == 0
        import grp
        assert info.st_gid == grp.getgrnam('fic').gr_gid and stat.S_IMODE(info.st_mode) == mode, (path, info)
        run(['stat', '-c', '%U:%G %a %n', str(path)])
    assert persistent_metadata() == original, 'persistent metadata changed'

def validate(stage):
    validate_metadata(clients)
    run(['runuser', '-u', 'ficmember', '--', 'python3', '-c', 'import os; assert os.geteuid()!=0; assert not os.access("/opt/fic/bin",os.W_OK)'])
    run(['runuser', '-u', 'ficmember', '--', '/opt/fic/bin/fic-cli', '--version'])
    for path in clients[1:]:
        command = ['runuser', '-u', 'ficmember', '--', 'xvfb-run', '-a', 'env',
                   'QT_QPA_PLATFORM=xcb', 'LD_LIBRARY_PATH=/opt/fic/qt/lib',
                   'QT_PLUGIN_PATH=/opt/fic/qt/plugins',
                   'QT_QPA_PLATFORM_PLUGIN_PATH=/opt/fic/qt/plugins/platforms', str(path), '--gui-smoke-test']
        p = run(command)
        assert 'qpa-platform=xcb' in p.stdout and 'jpeg-plugin=ok' in p.stdout and 'qt-core-path=/opt/fic/qt/' in p.stdout
    for path in clients:
        run(['runuser', '-u', 'ficmember', '--', 'python3', '-c',
             'import os,sys; assert not os.access(sys.argv[1],os.W_OK)', str(path)])
        # Prove a kernel EACCES under the real outsider UID, not an error in
        # runuser, a missing library, CLI admission, or a root-only test -x.
        script = ('import os,sys,subprocess,errno; assert os.geteuid()!=0; '
                  'p=sys.argv[1]; '
                  '\ntry: subprocess.run([p,"--version"],check=False)'
                  '\nexcept PermissionError as e: assert e.errno==errno.EACCES'
                  '\nelse: raise AssertionError("outsider executed private client")')
        run(['runuser', '-u', 'ficoutsider', '--', 'python3', '-c', script, str(path)])
    events.append(dict(stage=stage, result='PASS', persistent_metadata=original))

try:
    for stage, upgrade in [('install', False), ('reinstall', False), ('upgrade', True)]:
        # Independently install/update each client. Never rerun fic.postinst.
        for name in ('fic-cli', 'fic-gui'):
            package = native_package(name, upgrade)
            if kind == 'deb':
                run(['dpkg', '--force-depends', '-i', package])
            else:
                run(['rpm', '-Uvh', '--nodeps', '--replacepkgs', package])
            validate_metadata([clients[0]] if name == 'fic-cli' else clients[1:])
            if name == 'fic-cli':
                run(['runuser', '-u', 'ficmember', '--', str(clients[0]), '--version'])
            assert persistent_metadata() == original
        validate(stage)
    if kind == 'deb':
        # Exercise current generated postinst against unsafe object types.
        script = Path('/var/lib/dpkg/info/fic-gui.postinst')
        real = clients[-1]
        real.rename(real.with_name('fic-gui.saved'))
        victim = Path('/opt/fic/db/client-permissions-sentinel')
        real.symlink_to(victim)
        before = persistent_metadata()
        assert run(['sh', str(script), 'configure'], ok=False).returncode != 0
        assert persistent_metadata() == before
        real.unlink()
        hardlink_victim = Path('/tmp/fic-client-hardlink-victim')
        hardlink_victim.write_text('foreign hardlink target')
        os.link(hardlink_victim, real)
        before = persistent_metadata()
        hardlink_metadata = hardlink_victim.stat()
        assert run(['sh', str(script), 'configure'], ok=False).returncode != 0
        assert persistent_metadata() == before and hardlink_victim.stat() == hardlink_metadata
        real.unlink()
        real.mkdir()
        assert run(['sh', str(script), 'configure'], ok=False).returncode != 0
        real.rmdir()
        real.with_name('fic-gui.saved').rename(real)
        # Parent symlink and writable/non-root parents must also fail closed.
        bindir = Path('/opt/fic/bin')
        bindir.rename('/opt/fic/bin.saved')
        bindir.symlink_to('/opt/fic/bin.saved', target_is_directory=True)
        assert run(['sh', str(script), 'configure'], ok=False).returncode != 0
        bindir.unlink()
        Path('/opt/fic/bin.saved').rename(bindir)
        bindir.chmod(0o2770)
        assert run(['sh', str(script), 'configure'], ok=False).returncode != 0
        bindir.chmod(0o2750)
        uid = __import__('pwd').getpwnam('ficmember').pw_uid
        os.chown(real, uid, -1)
        assert run(['sh', str(script), 'configure'], ok=False).returncode != 0
        os.chown(real, 0, -1)
        real.chmod(0o770)
        assert run(['sh', str(script), 'configure'], ok=False).returncode != 0
        real.chmod(0o750)
        assert run(['sh', str(script), 'abort-upgrade']).returncode == 0
        assert persistent_metadata() == original
        events.append(dict(unsafe_paths='PASS symlink/hardlink/directory/parent-symlink/writable-parent/nonroot-owner'))
    (results/'result.json').write_text(json.dumps(dict(row=row, status='PASS', stages=3, gui='Xvfb/xcb/JPEG/private Qt under non-root UID',
        scope='real client packages; package dependency admission intentionally bypassed, no daemon/full-stack installation claim',
        events=len(events), os_release=os_release), indent=2))
finally:
    (results/'access-events.json').write_text(json.dumps(events, indent=2))
