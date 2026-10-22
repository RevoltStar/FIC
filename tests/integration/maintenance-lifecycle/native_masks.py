"""Actual PackageUnitMasks component in private systemd container, dummy units."""
import os
assert os.environ.get('FIC_MAINTENANCE_NATIVE')=='1'
from pathlib import Path
import subprocess
import sys
units=('fic.service','fic-device.service','fic-notify.service',
       'fic_get_device_info.service','fic_get_device_udev_info.service')
r=Path('/var/lib/m1-native-masks')
def ctl(*args,check=True):
    return subprocess.run(['systemctl',*args],check=check,text=True,capture_output=True,timeout=20)
def driver(action):
    subprocess.run(['/usr/local/bin/m1-masks',action],check=True,timeout=10)
if sys.argv[1]=='setup':
    r.mkdir(mode=0o700)
    for unit in units:
        path=Path('/usr/lib/systemd/system')/unit
        assert not path.exists() and not (Path('/etc/systemd/system')/unit).is_symlink(), 'fresh disposable image required'
        path.write_text('[Unit]\nDescription=FIC M1 dummy legacy writer\n[Service]\nExecStart=/bin/sleep infinity\n[Install]\nWantedBy=multi-user.target\n')
    ctl('daemon-reload');ctl('enable','--now',*units)
    for unit in units:assert ctl('is-active',unit).stdout.strip()=='active'
    driver('prepare');driver('publish');driver('prove')
    ctl('daemon-reload');ctl('stop',*units)
    for unit in units:
        assert ctl('show',unit,'-p','LoadState','--value').stdout.strip()=='masked'
        assert ctl('show',unit,'-p','MainPID','--value').stdout.strip()=='0'
        assert ctl('start',unit,check=False).returncode!=0
    print('PASS production mask component: durable plan/publication; actual systemd refuses legacy activation',flush=True)
elif sys.argv[1]=='verify-restore':
    driver('prove')
    for unit in units:
        assert ctl('show',unit,'-p','LoadState','--value').stdout.strip()=='masked'
        assert ctl('show',unit,'-p','MainPID','--value').stdout.strip()=='0'
    driver('restore');ctl('daemon-reload');ctl('start',*units)
    for unit in units:assert ctl('is-active',unit).stdout.strip()=='active'
    ctl('stop',*units)
    print('PASS production mask component: private PID1 restart retained all masks; exact restore permits dummy units',flush=True)
else:raise AssertionError('unknown native scenario')
