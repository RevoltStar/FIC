"""ALT RPM prerequisite success semantics; dummy scriptlets only, NOT FIC.

A failing runtime %post is a read-only refusal model. Observe whether RPM still
invokes the new product %pre. Its independent refusal must retain the old product
and avoid old %preun. Does not certify actual FIC lifecycle or compatibility.
"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

if os.environ.get('FIC_LEGACY_PACKAGE_ORDER_NATIVE') != '1':
    sys.exit(77)
assert os.environ.get('FIC_MAINTENANCE_NATIVE') == '1'
assert os.geteuid() == 0 and Path('/.dockerenv').exists()
root = Path(tempfile.mkdtemp(prefix='fic-admission-rpm-', dir='/var/lib'))
root.chmod(0o755)
trace = root / 'trace'
sentinel = root / 'protected-sentinel'
sentinel.write_text('original\n')
sentinel.chmod(0o600)


def run(*args, check=True):
    result = subprocess.run(args, text=True, capture_output=True, timeout=90)
    print('COMMAND=' + repr(args) + ' RC=' + str(result.returncode), flush=True)
    print(result.stdout + result.stderr, end='', flush=True)
    if check:
        assert result.returncode == 0, args
    return result


builder = 'm1-admission-builder'
run('useradd', '--system', '--no-create-home', builder)
for name in ('fic-m1-runtime-admission-probe', 'fic-m1-main-admission-probe'):
    assert run('rpm', '-q', name, check=False).returncode != 0


def package(kind, version):
    name = 'fic-m1-' + kind + '-admission-probe'
    work = root / (kind + str(version))
    work.mkdir()
    text = f'''Name: {name}
Version: {version}
Release: alt1
Summary: isolated prerequisite success semantics
License: MIT
Group: Development/Other
BuildArch: noarch
AutoReqProv: no
'''
    if kind == 'main' and version == 2:
        text += 'Requires(pre): fic-m1-runtime-admission-probe = 2-alt1\n'
    text += '%description\nTest data only. No FIC infrastructure.\n%install\n'
    text += f'mkdir -p %{{buildroot}}/usr/share/{name}\necho fixture > %{{buildroot}}/usr/share/{name}/payload\n'
    for phase in ('pre', 'post', 'preun', 'postun'):
        text += f'\n%{phase}\nprintf "{kind}{version} {phase} $1\\n" >> {trace}\n'
        if kind == 'runtime' and phase == 'post':
            text += 'echo MODEL_RUNTIME_GATE_REFUSED\nexit 1\n'
        if kind == 'main' and version == 2 and phase == 'pre':
            text += 'echo MODEL_NEW_MAIN_GATE_REFUSED\nexit 1\n'
        if kind == 'main' and version == 1 and phase == 'preun':
            text += f'chmod 0640 {sentinel}\n'
    text += f'\n%files\n/usr/share/{name}/payload\n'
    spec = work / 'fixture.spec'
    spec.write_text(text)
    for folder in ('BUILD', 'RPMS', 'SOURCES', 'SPECS', 'SRPMS'):
        (work / 'build' / folder).mkdir(parents=True)
    run('chown', '-R', builder, str(work))
    run('runuser', '-u', builder, '--', 'rpmbuild', '--define', '_topdir ' + str(work / 'build'), '-bb', str(spec))
    archives = list((work / 'build/RPMS').rglob('*.rpm'))
    assert len(archives) == 1
    return str(archives[0])


old = package('main', 1)
runtime = package('runtime', 2)
new = package('main', 2)
run('rpm', '-Uvh', old)
before = trace.read_text()
result = run('rpm', '-Uvh', new, runtime, check=False)
events = trace.read_text()[len(before):]
print('TRANSITION_EVENTS:\n' + events, flush=True)
assert 'runtime2 post 1' in events and 'main2 pre 2' in events
assert events.index('runtime2 post 1') < events.index('main2 pre 2')
assert 'MODEL_RUNTIME_GATE_REFUSED' in result.stdout + result.stderr
assert 'MODEL_NEW_MAIN_GATE_REFUSED' in result.stdout + result.stderr
assert 'main1 preun' not in events and 'main1 postun' not in events
assert sentinel.read_text() == 'original\n' and sentinel.stat().st_mode & 0o777 == 0o600
run('rpm', '-q', '--qf', '%{NAME} %{VERSION}-%{RELEASE}\n', 'fic-m1-runtime-admission-probe', 'fic-m1-main-admission-probe')
print('REPRODUCED_RED: Requires(pre) orders availability, NOT successful runtime %post gate; independent new-main %pre refusal retains old dummy product', flush=True)
