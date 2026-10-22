"""Actual writer proof in an explicitly disposable systemd container only."""
import os
import subprocess
from pathlib import Path

assert os.environ.get('FIC_MAINTENANCE_NATIVE') == '1'

def run(*args, check=True):
    return subprocess.run(args, text=True, capture_output=True, check=check, timeout=40)

def ctl(*args, check=True):
    return run('systemctl', *args, check=check)

def mask(action):
    return run('/usr/local/bin/m1-masks', action)

def proof(action, check=True):
    return run('/usr/local/bin/m1-quiescence', action, check=check)

mask('publish')
proof('stop-prove')
print('PASS: actual systemd, private masks, cgroup and process inventory', flush=True)
mask('restore')
unit = Path('/usr/lib/systemd/system/fic.service')
unit.write_text('[Unit]\nDescription=M1 dummy with surviving child\n'
                '[Service]\nKillMode=process\nSendSIGKILL=no\n'
                "ExecStart=/bin/sh -c 'sleep infinity & wait'\n")
ctl('daemon-reload')
ctl('start', 'fic.service')
group = ctl('show', 'fic.service', '-p', 'ControlGroup', '--value').stdout.strip()
assert group.startswith('/') and group != '/'
proof('pre-stop')
assert ctl('show', 'fic.service', '-p', 'MainPID', '--value').stdout.strip() == '0'
events = Path('/sys/fs/cgroup' + group) / 'cgroup.events'
assert 'populated 1' in events.read_text(), 'fixture lost surviving child'
mask('publish')
ctl('daemon-reload')
result = proof('prove', check=False)
assert result.returncode != 0 and 'cgroup is populated' in result.stderr, result
mask('prove')
assert 'populated 1' in events.read_text(), 'proof killed a surviving process'
print('PASS: inactive/MainPID=0 with live child refused; mask and process preserved', flush=True)
# Cleanup only dummy processes in the exact fixture cgroup, no name-based kill.
for pid in (Path('/sys/fs/cgroup' + group) / 'cgroup.procs').read_text().split():
    os.kill(int(pid), 9)
mask('restore')
ctl('daemon-reload')
unit.write_text('[Unit]\nDescription=M1 failed stop fixture\n'
                '[Service]\nExecStart=/bin/sleep infinity\nExecStop=/bin/sleep 30\nTimeoutStopSec=60\n')
ctl('daemon-reload')
ctl('reset-failed', 'fic.service', check=False)
ctl('start', 'fic.service')
group = ctl('show', 'fic.service', '-p', 'ControlGroup', '--value').stdout.strip()
result = proof('pre-stop', check=False)
assert result.returncode != 0 and 'operation failed' in result.stderr, result
print('PASS: stop exceeding command deadline refused, no successful shutdown claimed', flush=True)
for pid in (Path('/sys/fs/cgroup' + group) / 'cgroup.procs').read_text().split():
    os.kill(int(pid), 9)
ctl('stop', 'fic.service')
ctl('reset-failed', 'fic.service', check=False)
unit.write_text('[Unit]\nDescription=FIC M1 dummy legacy writer\n'
                '[Service]\nExecStart=/bin/sleep infinity\n'
                '[Install]\nWantedBy=multi-user.target\n')
ctl('daemon-reload')
