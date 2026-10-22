import os
assert os.environ.get('FIC_FINALIZER_RESEARCH') == '1', 'explicit disposable research opt-in required'
from pathlib import Path
import os, select, subprocess
r=Path('/var/lib/m1-delivery');r.mkdir()
for name in ('ready','release'): os.mkfifo(r/name)
ready=os.open(r/'ready',os.O_RDWR|os.O_NONBLOCK)
release=os.open(r/'release',os.O_RDWR|os.O_NONBLOCK)
(r/'lock').write_text('initial')
(r/'worker.py').write_text('''from pathlib import Path
import os
r=Path('/var/lib/m1-delivery');p=r/'count'
n=int(p.read_text())+1 if p.exists() else 1
p.write_text(str(n))
with open(r/'ready','w') as f: f.write(str(n)+'\\n');f.flush()
if n==1:
 with open(r/'release') as f: f.read(1)
''')
Path('/etc/systemd/system/m1-delivery.service').write_text('[Unit]\nStartLimitIntervalSec=0\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 /var/lib/m1-delivery/worker.py\nTimeoutStartSec=20\n')
Path('/etc/systemd/system/m1-delivery.path').write_text('[Path]\nPathChanged=/var/lib/m1-delivery/lock\nUnit=m1-delivery.service\n')
subprocess.run(['systemctl','daemon-reload'],check=True,timeout=10)
subprocess.run(['systemctl','start','m1-delivery.path'],check=True,timeout=10)
(r/'lock').write_text('first-close')
assert select.select([ready],[],[],5)[0], 'initial activation missing'
print('FIRST:',os.read(ready,100).decode().strip(),flush=True)
(r/'lock').write_text('second-close-while-active')
os.write(release,b'Q')
again=select.select([ready],[],[],5)[0]
print('SECOND:',os.read(ready,100).decode().strip() if again else 'NO_REDELIVERY',flush=True)
subprocess.run(['systemctl','stop','m1-delivery.service'],check=True,timeout=10)
# Atomic status-file replacement must still be observed after the first inode.
(r/'replacement').write_text('atomic-replacement')
os.replace(r/'replacement',r/'lock')
event=select.select([ready],[],[],5)[0]
print('ATOMIC_REPLACE:',os.read(ready,100).decode().strip() if event else 'NO_DELIVERY',flush=True)
subprocess.run(['systemctl','stop','m1-delivery.service'],check=True,timeout=10)
subprocess.run(['systemctl','daemon-reexec'],check=True,timeout=15)
(r/'lock').write_text('after-manager-reexec')
event=select.select([ready],[],[],5)[0]
print('MANAGER_REEXEC:',os.read(ready,100).decode().strip() if event else 'NO_DELIVERY',flush=True)
subprocess.run(['systemctl','stop','m1-delivery.path','m1-delivery.service'],check=True,timeout=10)
(r/'lock').write_text('event-while-watch-stopped')
subprocess.run(['systemctl','start','m1-delivery.path'],check=True,timeout=10)
event=select.select([ready],[],[],2)[0]
print('WATCH_RESTART:',os.read(ready,100).decode().strip() if event else 'NO_INITIAL_RESCAN',flush=True)
subprocess.run(['systemctl','stop','m1-delivery.path','m1-delivery.service'],check=True,timeout=10)
