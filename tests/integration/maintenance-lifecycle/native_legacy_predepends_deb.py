"""Native dependency/admission ordering, NOT the production FIC controller.

Requires a fresh disposable container. Dummy DEBs use a fixed, read-only model
runtime gate that refuses ANY installed old product and records actual version
and script digest. fic-dick's old mutating body is frozen from 2c9e69c. Protected
fixtures are sentinels, not valid FIC journal/config/fence authority. RED results
must not be reported as a safe legacy lifecycle or successful native FIC test.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

if os.environ.get('FIC_LEGACY_PACKAGE_ORDER_NATIVE') != '1':
    sys.exit(77)
assert os.environ.get('FIC_MAINTENANCE_NATIVE') == '1'
assert os.geteuid() == 0 and Path('/.dockerenv').exists()
assert not Path('/opt/fic').exists(), 'fresh disposable fixture required'
mode = sys.argv[2]
assert mode in ('missing', 'first-refusal', 'configure-a', 'previous-refusal',
                'already-configured', 'apt-upgrade', 'joint-upgrade')
root = Path(tempfile.mkdtemp(prefix='fic-predepends-', dir='/var/lib'))
root.chmod(0o755)
trace = root / 'trace'
legacy = Path(sys.argv[1]) / 'tests/integration/maintenance-lifecycle/legacy-deb-fixture'
print('MODE=' + mode, flush=True)


def run(*args, check=True):
    result = subprocess.run(args, text=True, capture_output=True, timeout=90)
    print('COMMAND=' + json.dumps(args) + ' RC=' + str(result.returncode), flush=True)
    print(result.stdout + result.stderr, end='', flush=True)
    if check:
        assert result.returncode == 0, args
    return result


def instrument(name, version, phase, body=''):
    return '#!/bin/sh\nprintf "%s\\n" "' + name + version + ' ' + phase + ' $*" >> ' + str(trace) + '\n' + body


# This deliberately simple gate grants no compatibility to old packages. It
# demonstrates that even a rejecting read-only gate cannot control dpkg's
# interpretation of an already-configured same-version prerequisite.
gate = root / 'gate.py'
gate.write_text('''import hashlib,subprocess,sys
from pathlib import Path
refused=False
for name in ('fic','fic-dick'):
 p=subprocess.run(['dpkg-query','-W','-f=${Version}\\t${Status}',name],capture_output=True,text=True)
 if p.returncode==0:
  refused=True
  print('GATE_REFUSED_INSTALLED',name,p.stdout,flush=True)
  for phase in ('preinst','postinst','prerm','postrm'):
   f=Path('/var/lib/dpkg/info')/(name+'.'+phase)
   if f.exists(): print('SCRIPT_SHA256',str(f),hashlib.sha256(f.read_bytes()).hexdigest(),flush=True)
sys.exit(1 if refused else 0)
''')


def package(name, version):
    tree = root / (name + version)
    control = tree / 'DEBIAN'
    control.mkdir(parents=True)
    metadata = f'Package: {name}\nVersion: {version}\nArchitecture: all\nMaintainer: FIC test\nDescription: native ordering fixture only\n'
    if name != 'fic-runtime' and version == '2':
        metadata += 'Pre-Depends: fic-runtime (= 2)\n'
    (control / 'control').write_text(metadata)
    for phase in ('preinst', 'postinst', 'prerm', 'postrm'):
        body = ''
        if name == 'fic-runtime' and phase == 'postinst':
            body = '/usr/bin/python3 ' + str(gate) + '\n'
        if name != 'fic-runtime' and version == '2' and phase == 'preinst':
            body = '/usr/bin/python3 ' + str(gate) + '\n'
        if name == 'fic-dick' and version == '1' and phase in ('postinst', 'prerm'):
            body = (legacy / ('fic-dick.' + phase)).read_text()
        script = control / phase
        script.write_text(instrument(name, version, phase, body))
        script.chmod(0o755)
    archive = root / (name + version + '.deb')
    run('dpkg-deb', '--build', str(tree), str(archive))
    return archive


def snapshot():
    result = {}
    for directory in (Path('/opt/fic'), Path('/etc/pam.d'), Path('/var/lib/fic-lifecycle')):
        for path in (directory, *sorted(directory.rglob('*'))):
            if not os.path.lexists(path):
                result[str(path)] = None
                continue
            stat = path.lstat()
            identity = os.readlink(path) if path.is_symlink() else (
                hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else 'directory')
            result[str(path)] = (stat.st_mode, stat.st_uid, stat.st_gid, stat.st_ino, identity, stat.st_mtime_ns, stat.st_ctime_ns)
    return result


for name in ('fic', 'fic-dick', 'fic-runtime'):
    assert run('dpkg-query', '-s', name, check=False).returncode != 0
runtime = package('fic-runtime', '2')
old = package('fic-dick', '1')
new = package('fic-dick', '2')
previously_configured = mode in ('previous-refusal', 'already-configured', 'apt-upgrade', 'joint-upgrade')
if previously_configured:
    run('dpkg', '-i', str(runtime))  # genuine earlier fresh configuration
run('dpkg', '-i', str(old))
if mode == 'joint-upgrade':
    run('dpkg', '-i', str(package('fic', '1')))
# Seed only after old initial configure so refusal mutations are distinguishable.
for name, contents, permissions in (
        ('/opt/fic/config/GLOBAL.conf', 'fixture recovery settings\n', 0o640),
        ('/opt/fic/lockstatus', 'fixture incident state\n', 0o640),
        ('/opt/fic/db/mutation-journal.json', 'fixture journal sentinel\n', 0o600),
        ('/etc/pam.d/fic-m1-probe', '# fixture PAM sentinel\n', 0o644),
        ('/var/lib/fic-lifecycle/state.json', 'fixture fence sentinel; NOT valid lifecycle state\n', 0o600)):
    path = Path(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents)
    path.chmod(permissions)
initial = snapshot()
if mode in ('first-refusal', 'configure-a', 'previous-refusal', 'joint-upgrade'):
    assert run('dpkg', '-i', str(runtime), check=False).returncode != 0
    assert snapshot() == initial, 'rejecting runtime gate mutated protected sentinels'
    print('RUNTIME_STATUS=' + run('dpkg-query', '-W', '-f=${Version} ${Status}', 'fic-runtime').stdout, flush=True)
if mode in ('configure-a', 'previous-refusal'):
    assert run('dpkg', '--configure', '-a', check=False).returncode != 0
    assert snapshot() == initial, 'configure-a refusal changed protected sentinels'
start = trace.read_text()
if mode == 'apt-upgrade':
    # Offline flat local repository: actual apt upgrade, not apt install args
    # pretending to exercise the upgrade resolver.
    repo = root / 'repo'
    repo.mkdir()
    target = repo / new.name
    target.write_bytes(new.read_bytes())
    metadata = run('dpkg-deb', '-f', str(new)).stdout
    (repo / 'Packages').write_text(metadata + f'Filename: ./{target.name}\nSize: {target.stat().st_size}\nSHA256: {hashlib.sha256(target.read_bytes()).hexdigest()}\n\n')
    sources = root / 'sources.list'
    sources.write_text(f'deb [trusted=yes] file:{repo} ./\n')
    lists = root / 'lists'
    lists.mkdir()
    options = ('-o', 'Dir::Etc::sourcelist=' + str(sources), '-o', 'Dir::Etc::sourceparts=-',
               '-o', 'Dir::State::lists=' + str(lists), '-o', 'Acquire::Languages=none')
    run('apt-get', *options, 'update')
    result = run('apt-get', *options, '-y', 'upgrade', check=False)
elif mode == 'joint-upgrade':
    result = run('dpkg', '-i', str(package('fic', '2')), str(new), check=False)
else:
    result = run('dpkg', '-i', str(new), check=False)
assert result.returncode != 0
new_events = trace.read_text()[len(start):]
print('TRANSITION_EVENTS:\n' + new_events, flush=True)
after = snapshot()
changed = [name for name in sorted(set(initial) | set(after)) if initial.get(name) != after.get(name)]
print('PROTECTED_DIFF=' + json.dumps(changed), flush=True)
if not previously_configured:
    assert not new_events and not changed, 'first prerequisite rejection ran old product scripts or changed protected files'
    print('PASS_ORDERING_ONLY: absent/never-configured runtime blocks old transitions; sentinels unchanged', flush=True)
else:
    assert 'fic-dick1 prerm upgrade 2' in new_events
    assert 'fic-dick2 preinst upgrade 1 2' in new_events
    assert 'fic-dick1 postinst abort-upgrade 2' in new_events
    journal = '/opt/fic/db/mutation-journal.json'
    assert journal in changed and (after[journal][0] & 0o777) == 0o640
    assert '/opt/fic/config/GLOBAL.conf' not in changed
    assert '/opt/fic/lockstatus' not in changed
    assert '/var/lib/fic-lifecycle/state.json' not in changed
    assert not any(name.startswith('/etc/pam.d') for name in changed)
    print('REPRODUCED_RED: exact Pre-Depends accepts prior configuration; old abort script mutates protected metadata despite gate refusal', flush=True)
