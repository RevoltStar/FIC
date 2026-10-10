#!/usr/bin/env python3
"""Qt EGLFS/KMS and stock LightDM handoff, ONLY in the guarded disposable VM.
Usage: GraphicsVmTests.py KEY [SSH_PORT=2222] [QMP_PORT=4444] [VNC_PORT=5901]
The optional package and stock lightdm-gtk-greeter must already be installed.
"""
import json
import socket
import struct
import subprocess
import sys
import time
key=sys.argv[1]; port=sys.argv[2] if len(sys.argv)>2 else '2222'
qmp_port=int(sys.argv[3]) if len(sys.argv)>3 else 4444
vnc_port=int(sys.argv[4]) if len(sys.argv)>4 else 5901
options=['-F','/dev/null','-i',key,'-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile=/tmp/fic-prelogin-vm-knownhosts','-o','ConnectTimeout=10']
def guest(command,check=True):
    result=subprocess.run(['ssh',*options,'-p',port,'root@127.0.0.1','set -eu; '+command],text=True,capture_output=True,timeout=40)
    if check and result.returncode:raise RuntimeError(command+'\n'+result.stdout+result.stderr)
    return result.stdout.strip()
def wait(command,expected,timeout=25):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        if guest(command,False)==expected:return
        time.sleep(.2)
    raise RuntimeError('Timeout '+command+'\n'+guest('journalctl -u fic-prelogin.service -u lightdm.service -n 30 --no-pager',False))
def qmp(command):
    with socket.create_connection(('127.0.0.1',qmp_port),timeout=5) as s:
        f=s.makefile('rwb',buffering=0);f.readline()
        for cmd in [{'execute':'qmp_capabilities'},command]:
            f.write((json.dumps(cmd)+'\n').encode())
            while True:
                value=json.loads(f.readline())
                if 'return' in value:break
                if 'error' in value:raise RuntimeError(str(value))
        return value['return']
def keys(value):qmp({'execute':'human-monitor-command','arguments':{'command-line':'sendkey '+value}})
def click(x,y):
    mice=qmp({'execute':'query-mice'})
    assert any(m['current'] and m['absolute'] for m in mice), 'VM requires virtual USB tablet'
    # A new evdev client has no previous cursor position. Force a movement:
    # repeated absolute coordinates can be suppressed by the guest input core.
    for target_x,target_y in [(0,0),(x,y)]:
        qmp({'execute':'input-send-event','arguments':{'events':[
            {'type':'abs','data':{'axis':'x','value':int(target_x*32767/1279)}},
            {'type':'abs','data':{'axis':'y','value':int(target_y*32767/799)}}]}})
        time.sleep(.2)
    time.sleep(.5) # Input release/event processing, never a DRM cleanup proof.
    for down in [True,False]:
        qmp({'execute':'input-send-event','arguments':{'events':[{'type':'btn','data':{'button':'left','down':down}}]}})
        time.sleep(.5)
def reset(stage):
    guest('systemctl stop lightdm.service fic-prelogin.service; systemctl reset-failed; mkdir -p /run/fic-prelogin-tests; echo '+stage+' > /run/fic-prelogin-tests/case; systemctl start --no-block lightdm.service')
def renderer():
    wait("pgrep -u fic-prelogin -x -f fic-prelogin-frontend >/dev/null && echo running",'running')
    # Prove this invocation reached the real QPA, not an earlier journal entry.
    wait("id=$(systemctl show fic-prelogin.service -p InvocationID --value); journalctl _SYSTEMD_INVOCATION_ID=$id --no-pager | grep -q 'qpa=eglfs integration=eglfs_kms' && echo ready",'ready')
    wait("id=$(systemctl show fic-prelogin.service -p InvocationID --value); journalctl _SYSTEMD_INVOCATION_ID=$id --no-pager | grep -q 'broker: renderer readiness acknowledged' && echo ready",'ready')
    wait("id=$(systemctl show fic-prelogin.service -p InvocationID --value); journalctl _SYSTEMD_INVOCATION_ID=$id --no-pager | grep -q 'view-state=' && echo displayed",'displayed')
def released():
    wait('systemctl show fic-prelogin.service -p SubState --value','exited')
    wait('systemctl is-active lightdm.service','active')
    assert guest("pgrep -u fic-prelogin -f fic-prelogin-frontend >/dev/null && echo leaked || echo reaped")=='reaped'
    wait('pgrep -x Xorg >/dev/null && echo active','active')
    wait("pgrep -f '^/usr/sbin/lightdm-gtk-greeter( |$)' >/dev/null && echo active",'active')
    assert 'Device or resource busy' not in guest('tail -100 /var/log/lightdm/x-0.log',False)
assert guest('cat /sys/class/dmi/id/product_name; test -f /etc/fic-prelogin-test-vm')=='FIC-Prelogin-Disposable'
assert guest("test ! -e /etc/systemd/system/lightdm.service.d/90-fic-test.conf; dpkg-query -W -f='${db:Status-Status}' lightdm-gtk-greeter")=='installed'
reset('FAILED');renderer()
assert guest('systemctl show lightdm.service -p MainPID --value')=='0'
qmp({'execute':'screendump','arguments':{'filename':'/vm/graphics-error.ppm'}})
before=guest('sha256sum /opt/fic/lockstatus /opt/fic/config/GLOBAL.conf /etc/pam.d/lightdm /etc/pam.d/lightdm-autologin')
keys('ret');released()
assert guest('sha256sum /opt/fic/lockstatus /opt/fic/config/GLOBAL.conf /etc/pam.d/lightdm /etc/pam.d/lightdm-autologin')==before
qmp({'execute':'screendump','arguments':{'filename':'/vm/stock-lightdm.ppm'}})
print('Keyboard manual/error UI -> Qt reap -> actual LightDM/Xorg/greeter; PAM/severity unchanged PASS',flush=True)
invocation=guest('systemctl show fic-prelogin.service -p InvocationID --value')
guest('systemctl restart lightdm.service')
assert guest('systemctl show fic-prelogin.service -p InvocationID --value')==invocation
print('Stock DM restart never relaunches Qt gate PASS',flush=True)
reset('FAILED');renderer();click(640,630);released()
print('Actual Qt/evdev mouse button -> stock DM PASS',flush=True)
reset('READY');released()
print('Verified startup + renderer-ready auto handoff -> stock DM PASS',flush=True)
reset('APPLYING');renderer();guest('systemctl stop fic.service');keys('ret');released();guest('systemctl start fic.service')
print('Daemon loss leaves real GUI interactive and manual handoff works PASS',flush=True)
# Force a renderer failure, then verify manual console recovery after reap.
reset('FAILED');renderer();guest('pkill -KILL -u fic-prelogin -f fic-prelogin-frontend')
wait("id=$(systemctl show fic-prelogin.service -p InvocationID --value); journalctl _SYSTEMD_INVOCATION_ID=$id --no-pager | grep -q 'interactive console fallback' && echo fallback",'fallback')
keys('ret');released()
print('Renderer crash -> proven reap/text VT fallback -> manual DM handoff PASS',flush=True)

# A descendant/sibling in the same service cgroup must never survive a false
# successful main-renderer handoff. Root injects a disposable process into the
# guest cgroup; AttachProcessesToUnit requires Delegate=yes and cannot be used
# on the production non-delegated unit.
reset('FAILED');renderer()
guest('systemd-run --unit=fic-prelogin-extra-process.service /usr/bin/sleep infinity')
extra=guest('systemctl show fic-prelogin-extra-process.service -p MainPID --value')
assert int(extra)>0
assert guest('systemctl show fic-prelogin.service -p ControlGroup --value')=='/system.slice/fic-prelogin.service'
guest('echo '+extra+' > /sys/fs/cgroup/system.slice/fic-prelogin.service/cgroup.procs')
keys('ret');wait('systemctl show fic-prelogin.service -p ActiveState --value','failed')
assert guest('systemctl show lightdm.service -p MainPID --value')=='0'
assert 'cgroup still contains another process' in guest('journalctl -u fic-prelogin.service -n 10 --no-pager')
wait('test ! -e /proc/'+extra+' && echo reaped','reaped')
guest('systemctl stop fic-prelogin-extra-process.service',False) # Empty unit may already be collected.
print('Remaining cgroup process denies false successful DRM handoff PASS',flush=True)

# A missing real DRM node must recover to text VT without silently releasing DM.
reset('FAILED');guest('systemctl stop lightdm.service fic-prelogin.service')
guest('mv /dev/dri/card0 /dev/dri/card0.fixture-hidden; systemctl start --no-block lightdm.service')
try:
    wait("id=$(systemctl show fic-prelogin.service -p InvocationID --value); journalctl _SYSTEMD_INVOCATION_ID=$id --no-pager | grep -q 'interactive console fallback' && echo fallback",'fallback')
    assert guest('systemctl show lightdm.service -p MainPID --value')=='0'
finally:
    guest('mv /dev/dri/card0.fixture-hidden /dev/dri/card0')
keys('ret');released()
print('Missing DRM -> interactive text VT, explicit manual handoff -> stock DM PASS',flush=True)

# Exercise the actual Qt confirmation and logind while first apply is pending.
reset('APPLYING');renderer()
old_boot=guest('cat /proc/sys/kernel/random/boot_id')
click(340,706)
time.sleep(2) # Give the virtual GPU time to display the modal confirmation.
keys('left');time.sleep(.5);keys('spc')
deadline=time.monotonic()+120
while time.monotonic()<deadline:
    boot=guest('cat /proc/sys/kernel/random/boot_id',False)
    if len(boot)==36 and boot!=old_boot:break
    time.sleep(1)
else:raise RuntimeError('Qt/logind reboot did not produce a new kernel boot identity')
assert guest('sha256sum /opt/fic/lockstatus /opt/fic/config/GLOBAL.conf /etc/pam.d/lightdm /etc/pam.d/lightdm-autologin')==before
print('Qt confirmed reboot during APPLYING -> new kernel boot; PAM/severity unchanged PASS',flush=True)
# A failed stopped unit must still be removable after an empty-cgroup proof.
reset('FAILED');renderer();guest('systemctl kill --signal=KILL --kill-who=main fic-prelogin.service')
wait('systemctl show fic-prelogin.service -p ActiveState --value','failed')
assert guest('systemctl show lightdm.service -p MainPID --value')=='0'
keys('ctrl-alt-f1')
wait('cat /sys/class/tty/tty0/active','tty1')
assert guest('systemctl is-active getty@tty1.service')=='active'
print('Broker SIGKILL denies DM; actual keyboard VT1 recovery remains available PASS',flush=True)
guest('dpkg --remove fic-prelogin; systemctl daemon-reload; systemctl start lightdm.service')
assert guest('systemctl is-active lightdm.service')=='active'
assert guest("dpkg-query -W -f='${db:Status-Status}' fic-prelogin",False)!='installed'
guest('dpkg --purge fic-prelogin')
print('Remove/purge after failed GUI unit restores stock DM PASS',flush=True)
