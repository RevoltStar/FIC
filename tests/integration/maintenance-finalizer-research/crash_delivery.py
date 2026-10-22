import os,select,subprocess
from pathlib import Path
assert os.environ.get('FIC_FINALIZER_RESEARCH')=='1'
r=Path('/var/lib/m1-delivery')
for name in ('count',): (r/name).unlink(missing_ok=True)
ready=os.open(r/'ready',os.O_RDWR|os.O_NONBLOCK)
p=Path('/etc/systemd/system/m1-delivery.service')
p.write_text('[Unit]\nStartLimitIntervalSec=60s\nStartLimitBurst=3\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 /var/lib/m1-delivery/worker.py\nTimeoutStartSec=20s\nRestart=on-failure\nRestartSec=100ms\n')
def call(*args):subprocess.run(['systemctl',*args],check=True,timeout=10)
call('daemon-reload');call('start','--no-block','m1-delivery.service')
assert select.select([ready],[],[],5)[0]
assert os.read(ready,100).strip()==b'1'
call('kill','--signal=KILL','--kill-whom=all','m1-delivery.service')
assert select.select([ready],[],[],5)[0], 'bounded restart not delivered'
assert os.read(ready,100).strip()==b'2'
call('stop','m1-delivery.service')
os.close(ready)
print('PASS: oneshot crash → bounded systemd on-failure restart, FIFO barriers')
