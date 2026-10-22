"""Native transport/protocol fixture; never a FIC security finalizer proof."""
import os
assert os.environ.get('FIC_FINALIZER_RESEARCH') == '1', 'disposable native opt-in required'
import ctypes
from pathlib import Path
import select
import subprocess
import time

r = Path('/var/lib/m1-retry')
r.mkdir(exist_ok=True)
u = Path('/etc/systemd/system')

def call(*args):
    return subprocess.run(['systemctl', *args], check=True, text=True,
                          stdout=subprocess.PIPE, timeout=15).stdout.strip()

# Unit success for temporary/blocked results; failures/crashes do not consume a
# total retry budget. Service has NO Restart loop and NO start-limit exhaustion.
(u/'m1-retry.service').write_text('''[Unit]
StartLimitIntervalSec=0
[Service]
Type=oneshot
ExecStart=/usr/local/bin/m1-retry-probe
TimeoutStartSec=700ms
TimeoutStopSec=700ms
''')
(u/'m1-retry.timer').write_text('''[Timer]
OnBootSec=100ms
OnUnitInactiveSec=300ms
AccuracySec=1ms
Unit=m1-retry.service
[Install]
WantedBy=timers.target
''')
call('daemon-reload')
lib = ctypes.CDLL(None)
fd = lib.inotify_init1(os.O_CLOEXEC | os.O_NONBLOCK)
assert fd >= 0 and lib.inotify_add_watch(fd, str(r).encode(), 0x100 | 0x8 | 0x80) >= 0

def wait(predicate, seconds=8):
    end = time.monotonic()+seconds
    while not predicate():
        remaining = end-time.monotonic()
        assert remaining > 0, 'deadline; service=' + call('show', 'm1-retry.service', '-p', 'Result')
        if select.select([fd], [], [], min(remaining, 0.05))[0]:
            os.read(fd, 65536)


def attempts():
    return [int(x) for x in (r/'attempts').read_text().splitlines()] if (r/'attempts').exists() else []


def reset(state):
    call('stop', 'm1-retry.timer', 'm1-retry.service')
    for p in r.iterdir():
        p.unlink()
    (r/'fence').write_text('pending')
    (r/'package-state').write_text(state)
    call('start', 'm1-retry.service')
    call('start', 'm1-retry.timer')

reset('busy')
# More than any old fixture budget (one attempt), without DB/path/hook events.
wait(lambda: len(attempts()) >= 8)
a = attempts()
assert all(y-x >= 250 for x, y in zip(a, a[1:])), a
assert (r/'fence').read_text() == 'pending' and not (r/'accepted').exists()
# Hook storm bypasses neither cooldown nor persisted last-attempt admission.
for _ in range(15):
    call('start', 'm1-retry.service')
a = attempts()
assert all(y-x >= 250 for x, y in zip(a, a[1:])), a
(r/'package-state').write_text('installed')
wait(lambda: (r/'accepted').exists() and (r/'fence').read_text() == 'completed')
assert (r/'fence').read_text() == 'completed'
print('PASS temporary: >=8 attempts, hook storm rate bounded; no completion event needed', flush=True)

reset('structural')
wait(lambda: (r/'blocked').exists())
count = len(attempts())
blocked_at = int((r/'last').read_text().split()[1])
# Let several actual timer intervals elapse while blocked.
wait(lambda: int((r/'last').read_text().split()[1]) >= blocked_at+750)
(r/'package-state').write_text('installed')
# Use native service activations as deterministic barriers, no sleep assertions.
for _ in range(12):
    call('start', 'm1-retry.service')
assert len(attempts()) == count and not (r/'accepted').exists()
assert (r/'fence').read_text() == 'pending'
print('PASS structural: installed input/hook storm never clears block or repeats costly proof', flush=True)

# No automatic structural repair claimed. A real FIC closed recovery is NOT in
# this fixture; the next scenarios use independent fresh operations.
reset('busy')
(r/'package-state').write_text('crash')
wait(lambda: call('show', 'm1-retry.service', '-p', 'Result', '--value') == 'exit-code')
assert (r/'fence').read_text() == 'pending'
(r/'package-state').write_text('installed')
wait(lambda: (r/'accepted').exists() and (r/'fence').read_text() == 'completed')
print('PASS crash: no total crash budget; independent timer delivers later attempt', flush=True)

reset('busy')
(r/'package-state').write_text('timeout')
wait(lambda: call('show', 'm1-retry.service', '-p', 'Result', '--value') == 'timeout')
assert (r/'fence').read_text() == 'pending'
(r/'package-state').write_text('installed')
wait(lambda: (r/'accepted').exists() and (r/'fence').read_text() == 'completed')
print('PASS cost: systemd kills stuck proof; timer later retries successfully', flush=True)

# Runtime last-attempt data survives manager reexec. BOOTTIME is unaffected by
# wall clock changes. Actual kernel reboot is a separate untested boundary.
reset('busy')
call('daemon-reexec')
wait(lambda: len(attempts()) >= 3)
assert (r/'fence').read_text() == 'pending'
call('stop', 'm1-retry.timer', 'm1-retry.service')
# Package removal: delivery artifacts disappear, tombstone is outside units/helper.
(r/'fence').write_text('removed-tombstone')
for name in ('m1-retry.timer', 'm1-retry.service'):
    (u/name).unlink()
call('daemon-reload')
assert (r/'fence').read_text() == 'removed-tombstone'
print('PASS reexec and removed delivery units: fence/tombstone retained', flush=True)
os.close(fd)
