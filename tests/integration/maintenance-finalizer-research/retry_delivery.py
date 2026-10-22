import os
assert os.environ.get('FIC_FINALIZER_RESEARCH') == '1', 'explicit disposable research opt-in required'
from pathlib import Path
import subprocess
r=Path('/var/lib/m1-delivery')
(r/'package-state').write_text('half-configured')
p=Path('/etc/systemd/system')
(p/'m1-proof.service').write_text('[Service]\nType=oneshot\nExecStart=/usr/local/bin/m1-oneshot\n')
(p/'m1-proof.timer').write_text('[Timer]\nOnActiveSec=200ms\nAccuracySec=1ms\nUnit=m1-proof.service\n')
(p/'m1-boot.service').write_text('[Service]\nType=oneshot\nExecStart=/usr/bin/touch /var/lib/m1-delivery/boot-attempt\n[Install]\nWantedBy=multi-user.target\n')
def call(*args):subprocess.run(['systemctl',*args],check=True,timeout=15)
call('daemon-reload');call('start','m1-proof.service')
assert not (r/'accepted').exists()
(r/'package-state').write_text('installed')
# Independent one-shot timer supplies a fresh attempt even with no path event.
call('start','m1-proof.timer')
# Completion observation: inotify watches accepted file's parent before checking.
import ctypes,os,select
lib=ctypes.CDLL(None);fd=lib.inotify_init1(os.O_CLOEXEC|os.O_NONBLOCK)
assert fd>=0 and lib.inotify_add_watch(fd,str(r).encode(),0x100|0x8)>=0
if not (r/'accepted').exists():
 assert select.select([fd],[],[],5)[0], 'timer did not dispatch'
 # service may write attempts first; wait for accepted through bounded event drain
 import time
 deadline=time.monotonic()+5
 while not (r/'accepted').exists():
  assert select.select([fd],[],[],max(0,deadline-time.monotonic()))[0]
  os.read(fd,8192)
os.close(fd)
assert (r/'attempts').read_text().splitlines()==['half-configured','installed']
print('PASS: closed C++ oneshot defers unproven state; single bounded timer recovers a missing event')
call('enable','m1-boot.service')
