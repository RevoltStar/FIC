#!/usr/bin/env python3
"""Isolated script dispatch tests; domain release is tested in C++/native gates."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

root = Path(sys.argv[1])
with tempfile.TemporaryDirectory(prefix='fic-package-dispatch-') as directory:
    work = Path(directory)
    log = work/'calls'
    helper = work/'infrastructure'
    helper.write_text('#!/bin/sh\nprintf "helper %s\\n" "$*" >> "$CALL_LOG"\nexit "${HELPER_EXIT:-0}"\n')
    helper.chmod(0o755)
    systemctl = work/'systemctl'
    systemctl.write_text('#!/bin/sh\nprintf "systemctl %s\\n" "$*" >> "$CALL_LOG"\nexit 0\n')
    systemctl.chmod(0o755)
    for kind, action, upgrade in [('deb', 'remove', 'upgrade'), ('rpm', '0', '1')]:
        template=root/f'packaging/{kind}/lifecycle'/('fic.prerm' if kind=='deb' else 'fic.preun')
        text=template.read_text().replace('/opt/fic/bin/fic-package-infrastructure',str(helper)).replace('/bin/fic',str(work/'command-link'))
        assert 'control ' not in text and 'prerm-prepare' not in text
        script=work/f'{kind}.sh';script.write_text(text)
        for exit_code in ('0','23'):
            log.write_text('')
            env={**os.environ,'PATH':str(work)+':/usr/bin:/bin','CALL_LOG':str(log),'HELPER_EXIT':exit_code}
            p=subprocess.run(['sh',str(script),action],env=env,capture_output=True,text=True)
            assert p.returncode==int(exit_code),(kind,p.stdout,p.stderr)
            calls=log.read_text().splitlines()
            assert calls[0]=='helper remove',calls
            assert (len(calls)>1)==(exit_code=='0'),calls
        log.write_text('')
        env['HELPER_EXIT']='0'
        subprocess.run(['sh',str(script),upgrade],env=env,check=True)
        calls=log.read_text()
        assert 'helper remove' not in calls and 'rollback' not in calls
        assert ('helper prepare-install' in calls)==(kind=='deb'),calls
print('PASS: DEB/RPM infrastructure helper failure blocks disable/erase; upgrade does not invoke rollback (isolated dispatch only)')
