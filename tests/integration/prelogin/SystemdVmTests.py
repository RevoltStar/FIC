#!/usr/bin/env python3
"""Real systemd ordering tests; refuse any VM without the explicit disposable marker.

Usage: SystemdVmTests.py KEY DEB [SSH_PORT=2222] [QMP_PORT=4444]
Uses a real selected LightDM alias with a sleep ExecStart override for ordering.
The graphics suite separately removes that override and starts the stock DM.
"""
import json
import pathlib
import shlex
import socket
import subprocess
import sys
import time
key, package = sys.argv[1:3]
port = sys.argv[3] if len(sys.argv) > 3 else '2222'
qmp_port = int(sys.argv[4]) if len(sys.argv) > 4 else 4444
options = ['-F','/dev/null','-i',key,'-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile=/tmp/fic-prelogin-vm-knownhosts','-o','ConnectTimeout=10']
def guest(command, check=True):
    p = subprocess.run(['ssh', *options, '-p',port,'root@127.0.0.1','set -eu; '+command], text=True, capture_output=True, timeout=40)
    if check and p.returncode: raise RuntimeError(command+'\n'+p.stdout+p.stderr)
    return p.stdout.strip()
def wait(command, expected, limit=20):
    until = time.monotonic()+limit
    while time.monotonic()<until:
        if guest(command,False)==expected: return
        time.sleep(.25)
    raise RuntimeError('timeout: '+command+' expected '+expected+'\n'+guest('systemctl list-jobs; systemctl status fic-prelogin.service lightdm.service --no-pager',False))
def keypress():
    with socket.create_connection(('127.0.0.1',qmp_port),timeout=5) as s:
        f=s.makefile('rwb',buffering=0)
        f.readline()
        for command in [{'execute':'qmp_capabilities'}, {'execute':'human-monitor-command','arguments':{'command-line':'sendkey ret'}}]:
            f.write((json.dumps(command)+'\n').encode())
            while True:
                answer=json.loads(f.readline())
                if 'return' in answer: break
                if 'error' in answer: raise RuntimeError(str(answer))
assert guest('cat /sys/class/dmi/id/product_name; test -f /etc/fic-prelogin-test-vm')=='FIC-Prelogin-Disposable', 'refusing non-disposable guest'
subprocess.run(['scp',*options,'-O','-P',port,package,'root@127.0.0.1:/tmp/prelogin.deb'],check=True,timeout=30)
guest("for s in login sshd lightdm lightdm-autologin; do [ ! -f /etc/pam.d/$s ] || { sed -i '/^account required pam_fic_access.so$/d' /etc/pam.d/$s; sed -i '1i account required pam_fic_access.so' /etc/pam.d/$s; }; done")
guest('systemctl stop lightdm.service fic-prelogin.service fic.service; systemctl reset-failed')
guest('mkdir -p /run/fic-prelogin-tests /etc/systemd/system/lightdm.service.d; echo FAILED > /run/fic-prelogin-tests/case')
guest("printf '[Service]\\nType=simple\\nExecStart=\\nExecStart=/usr/bin/sleep infinity\\n' > /etc/systemd/system/lightdm.service.d/90-fic-test.conf")
# Only the optional package lifecycle is under test here. Production daemon/PAM
# binaries were staged independently, hence intentionally absent fic dpkg record.
guest('dpkg --force-depends -i /tmp/prelogin.deb')
guest('/opt/fic/bin/fic-prelogin-integration verify')
guest('systemctl start --no-block graphical.target')
wait('systemctl show fic-prelogin.service -p ActiveState --value','activating')
assert guest('systemctl show lightdm.service -p MainPID --value')=='0'
print('S1 graph/alias transaction: DM waits PASS',flush=True)
time.sleep(1)
assert guest('systemctl show fic-prelogin.service -p ActiveState --value')=='activating'
print('S6 failed first apply keeps gate running PASS',flush=True)
keypress(); wait('systemctl show fic-prelogin.service -p SubState --value','exited')
wait('systemctl show lightdm.service -p ActiveState --value','active')
print('S2 manual handoff releases pending DM PASS',flush=True)
old=guest('systemctl show fic-prelogin.service -p InvocationID --value')
guest('systemctl restart lightdm.service')
assert guest('systemctl show fic-prelogin.service -p InvocationID --value')==old
print('S7 DM restart does not relaunch gate PASS',flush=True)
def reset(stage):
    guest('systemctl stop lightdm.service fic-prelogin.service; systemctl reset-failed; echo '+stage+' > /run/fic-prelogin-tests/case; systemctl start --no-block lightdm.service')
reset('APPLYING'); wait('systemctl show fic-prelogin.service -p ActiveState --value','activating')
guest('systemctl kill --signal=KILL fic-prelogin.service')
wait('systemctl show fic-prelogin.service -p ActiveState --value','failed')
assert guest('systemctl show lightdm.service -p MainPID --value')=='0'
assert guest('systemctl is-active getty@tty1.service')=='active'
print('S3 fatal gate failure denies DM; recovery TTY alive PASS',flush=True)
reset('APPLYING'); wait('systemctl show fic-prelogin.service -p ActiveState --value','activating')
guest('systemctl stop fic.service')
keypress(); wait('systemctl show fic-prelogin.service -p SubState --value','exited')
wait('systemctl show lightdm.service -p ActiveState --value','active')
print('S4 daemon loss/manual handoff PASS (PAM tested separately)',flush=True)
guest('systemctl start fic.service')
reset('READY'); wait('systemctl show fic-prelogin.service -p SubState --value','exited')
wait('systemctl show lightdm.service -p ActiveState --value','active')
print('S5 verified startup auto handoff PASS',flush=True)
# Reinstall/upgrade script must detach/re-attach without stopping running DM.
guest('dpkg --force-depends -i /tmp/prelogin.deb')
wait('systemctl show lightdm.service -p ActiveState --value','active')
guest('/opt/fic/bin/fic-prelogin-integration verify')
print('Package reinstall preserves running DM PASS',flush=True)
guest('dpkg --remove fic-prelogin; systemctl daemon-reload; systemctl restart lightdm.service')
assert guest('test ! -e /etc/systemd/system/display-manager.service.d/50-fic-prelogin.conf; systemctl is-active lightdm.service')=='active'
assert guest("dpkg-query -W -f='${db:Status-Status}' fic-prelogin", False) != 'installed'
print('S8 package removal restores stock ordering PASS',flush=True)
guest('dpkg --purge fic-prelogin')
