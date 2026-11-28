#!/usr/bin/env python3
"""Disposable Docker IPC gate for static hardware vs generated udev policy.

Run after building fic-dick in a compatible builder with /src read-only and
/build writable: python3 /src/tests/integration/device-control/static_hardware_ipc_gate.py /build /src
The lifecycle file and udevadm are test fixtures, not package installation or
physical udev enforcement evidence.
"""
import json
import grp
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess
import sys
import time

build, repo = map(Path, sys.argv[1:])
root = Path('/opt/fic')
assert Path('/.dockerenv').exists() and os.getuid() == 0
helper_source = (repo / 'tests/integration/device-control/lib/common.sh').read_text().split("<<'PY'\n", 1)[1].split('\nPY\n', 1)[0]
helper = {'__name__': 'fic_dc_vm_helper'}
exec(compile(helper_source, 'device-control/lib/common.sh:helper', 'exec'), helper)
for path in (root, Path('/run/fic'), Path('/var/lib/fic-lifecycle')):
    path.mkdir(parents=True, exist_ok=True)
for name in ('bin', 'config', 'db', 'log', 'notify', 'share', 'image'):
    (root / name).mkdir(exist_ok=True)
shutil.copy2(build / 'fic-dick/fic-dick', root / 'bin/fic-dick')
for path in [*(repo / 'fic/src/resources/config').glob('*.conf'), *(build / 'fic/generated/scripts/config').glob('*.conf')]:
    shutil.copy2(path, root / 'config' / path.name)
# Disposable test admission fixture; this does not exercise package installation.
life = Path('/var/lib/fic-lifecycle')
life.chmod(0o700)
(life / 'status').write_text('INSTALLED\n')
(life / 'status').chmod(0o600)
subprocess.run(['groupadd', '-f', 'fic'], check=True)
fic_gid = grp.getgrnam('fic').gr_gid
for path in [root, *root.rglob('*')]:
    os.chown(path, 0, fic_gid)
    if path.is_dir(): path.chmod(0o2750)
    elif path.parent.name == 'config': path.chmod(0o640)
udevadm = Path('/usr/bin/udevadm')
udevadm.write_text('#!/bin/sh\nif [ "$1" = control ]; then exit 0; fi\nif [ "$1" = info ]; then exit 0; fi\nexit 1\n')
udevadm.chmod(0o755)
log = open(build / 'static-ipc-daemon.log', 'w')
proc = subprocess.Popen([str(root / 'bin/fic-dick'), '--daemon'], stdout=log, stderr=log)
sock = Path('/run/fic/fic-device.sock')
try:
    deadline = time.monotonic() + 30
    while not sock.exists():
        assert proc.poll() is None, (build / 'static-ipc-daemon.log').read_text()
        assert time.monotonic() < deadline, 'device daemon socket timeout'
        time.sleep(.1)
    def ipc(request):
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as client:
            client.settimeout(15)
            client.connect(str(sock))
            request['api_version'] = 1
            client.send(json.dumps(request).encode())
            return helper['receive_response'](client)
    boot_id = ipc({'command': 'boot_id'})['boot_id']
    db_path = root / 'db/devices.db'
    rules_path = Path('/etc/udev/rules.d/99-fic-devices.rules')
    baseline = rules_path.read_bytes()
    with sqlite3.connect(db_path) as db:
        static_ids = {}
        for subsystem in ('cpu', 'board', 'memory'):
            parent = db.execute('SELECT id FROM devices WHERE subsystem=?', ('__' + subsystem + '__',)).fetchone()[0]
            static_ids[subsystem] = db.execute(
                'INSERT INTO devices(device_hash,devpath,subsystem,device_type,parent_id,control_level,control_explicit,ignore_hierarchy,boot_id) VALUES(?,?,?,?,?,?,0,1,?)',
                ('gate-' + subsystem, '/' + subsystem + '_list/gate-' + subsystem, subsystem, subsystem, parent, 'allowed', boot_id)).lastrowid
        parent = db.execute("SELECT id FROM devices WHERE subsystem='__udev__'").fetchone()[0]
        usb_id = db.execute("INSERT INTO devices(device_hash,devpath,subsystem,device_type,parent_id,control_level,control_explicit,boot_id) VALUES('gate-usb','/devices/gate-usb','usb','usb_device',?,'allowed',0,'old-boot')", (parent,)).lastrowid
    for subsystem, level in (('cpu','permanent'),('board','blocked'),('memory','ignored')):
        result = ipc({'command':'device_update_control_level','device_id':static_ids[subsystem], 'control_level':level,'ignore_hierarchy':True})
        assert result['ok'], result
        if rules_path.read_bytes() != baseline:
            import difflib
            print(''.join(difflib.unified_diff(baseline.decode().splitlines(True), rules_path.read_text().splitlines(True))), file=sys.stderr)
            raise AssertionError('static rule changed udev bytes')
        with sqlite3.connect(db_path) as db:
            desired, active = db.execute('SELECT desired_revision,active_revision FROM device_policy_state').fetchone()
            assert desired == active, (desired,active)
    assert ipc({'command':'device_check_permanent'})['ok']
    result = ipc({'command':'device_update_control_level','device_id':usb_id,'control_level':'blocked','ignore_hierarchy':False})
    assert result['ok'], result
    changed = rules_path.read_bytes()
    assert changed != baseline and b'/devices/gate-usb' in changed
    with sqlite3.connect(db_path) as db:
        db.execute("UPDATE devices SET boot_id='old-boot' WHERE id=?", (static_ids['cpu'],))
    result = ipc({'command':'device_check_permanent'})
    assert any(item['device_id'] == static_ids['cpu'] for item in result['missing']), result
    assert 'incident_requested_severity' in result, result
    print('PASS: static IPC updates, unchanged udev rules, later USB activation, missing permanent CPU scan')
finally:
    proc.terminate()
    proc.wait(timeout=15)
    log.close()
