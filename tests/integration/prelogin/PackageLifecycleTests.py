#!/usr/bin/env python3
"""Execute generated DEB maintainer scripts against an isolated helper fixture."""
import pathlib
import re
import subprocess
import sys
import tempfile
root = pathlib.Path(sys.argv[1])
for name in ['SystemdVmTests.py', 'GraphicsVmTests.py']:
    path = root / 'tests/integration/prelogin' / name
    compile(path.read_text(), str(path), 'exec')
script = (root / 'packaging/deb/build-fic-debian12-deb.sh').read_text()
section = script.split('build_fic_prelogin_package() {', 1)[1].split('\nmain() {', 1)[0]
with tempfile.TemporaryDirectory(prefix='fic-prelogin-package-') as directory:
    work = pathlib.Path(directory)
    calls = work / 'calls'
    helper = work / 'helper'
    helper.write_text('#!/bin/sh\nprintf "%s\\n" "$1" >> "' + str(calls) + '"\nexit "${FIXTURE_EXIT:-0}"\n')
    helper.chmod(0o755)
    for name, cases in [('postinst', {'configure':'activate', 'abort-remove':'activate', 'abort-deconfigure':'activate', 'abort-upgrade':'activate', 'triggered':None}),
                        ('prerm', {'remove':'deactivate', 'deconfigure':'deactivate', 'upgrade':'deactivate', 'failed-upgrade':None})]:
        match = re.search(r'/DEBIAN/' + name + r'" <<\'EOF\'\n(.*?)\nEOF', section, re.S)
        assert match, name
        text = match[1].replace('/opt/fic/bin/fic-prelogin-integration', str(helper))
        text = text.replace('/run/systemd/system', str(work))
        target = work / name
        target.write_text(text)
        subprocess.run(['sh', '-n', str(target)], check=True)
        for case, expected in cases.items():
            calls.unlink(missing_ok=True)
            subprocess.run(['sh', str(target), case], check=True)
            assert (calls.read_text().strip() if calls.exists() else None) == expected, (name, case)
            if expected:
                import os
                env = dict(os.environ, FIXTURE_EXIT='23')
                assert subprocess.run(['sh', str(target), case], env=env).returncode == 23, (name, case, 'hidden helper failure')
print('DEB generated lifecycle dispatch, upgrade and failure propagation PASS')
