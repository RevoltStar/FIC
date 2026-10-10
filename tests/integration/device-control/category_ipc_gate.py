#!/usr/bin/env python3
"""Real daemons/CLI/SQLite in disposable Docker; activation uses a faultable udev fixture.
No real enforcement helper is executed against the container/host sysfs.
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
assert Path('/.dockerenv').exists() and os.getuid() == 0
# Reuse the existing VM harness framing implementation.
helper_source = (repo / 'tests/integration/device-control/lib/common.sh').read_text().split("<<'PY'\n", 1)[1].split('\nPY\n', 1)[0]
helper = {'__name__': 'fic_dc_vm_helper'}
exec(compile(helper_source, 'device-control/lib/common.sh:helper', 'exec'), helper)
root = Path('/opt/fic')
shutil.rmtree(root, ignore_errors=True)
shutil.rmtree('/run/fic', ignore_errors=True)
subprocess.run(['groupadd', '-f', 'fic'], check=True)
fic_gid = grp.getgrnam('fic').gr_gid
for directory in ('bin', 'config', 'lang', 'db', 'log', 'notify', 'share/default-config', 'image'):
    (root / directory).mkdir(parents=True, exist_ok=True)
Path('/run/fic').mkdir(exist_ok=True)
for name, component in [('fic', 'fic'), ('fic-dick', 'fic-dick'), ('fic-cli', 'fic-cli')]:
    shutil.copy2(build / component / name, root / 'bin' / name)
for path in [*(repo / 'fic/src/resources/config').glob('*.conf'), *(build / 'fic/generated/scripts/config').glob('*.conf')]:
    text = path.read_text()
    lines = [line.split('=', 1)[0] + '=DISABLE' if '.status=' in line else line for line in text.splitlines()]
    text = '\n'.join(lines) + '\n'
    if path.name == 'GLOBAL.conf':
        text = text.replace('lang.status=DISABLE', 'lang.status=ENABLE')
    (root / 'config' / path.name).write_text(text)
for path in (repo / 'fic/src/resources/lang').glob('*.lang'):
    shutil.copy2(path, root / 'lang' / path.name)
for path in [root, *root.rglob('*')]:
    os.chown(path, 0, fic_gid)
    if path.is_dir(): path.chmod(0o2750)
    elif path.parent.name in ('config', 'lang'): path.chmod(0o640)
subprocess.run([str(root / 'bin/fic'), '--maintenance', 'incident-init'], check=True)
real_udev = Path('/usr/bin/udevadm')
if real_udev.exists():
    shutil.copy2(real_udev, '/tmp/udevadm-native')
# Deliberate fixture: empty inventory means no physical targets.
real_udev.write_text('''#!/bin/sh
if [ "$1" = control ]; then
    [ ! -f /tmp/dc-fail-activation ]
    exit $?
fi
if [ "$1" = info ] && [ "$2" = --export-db ]; then exit 0; fi
exit 1
''')
real_udev.chmod(0o755)
processes = []
logs = []

def start(name, arguments=()):
    output = open(build / ('dc-' + name + '-daemon.log'), 'a')
    logs.append(output)
    process = subprocess.Popen([str(root / 'bin' / name), *arguments], stdout=output, stderr=output)
    processes.append(process)
    socket_path = Path('/run/fic/fic-device.sock' if name == 'fic-dick' else '/run/fic/fic.sock')
    deadline = time.monotonic() + 30
    while not socket_path.exists():
        assert process.poll() is None, f'{name} exited: see daemon log'
        assert time.monotonic() < deadline, f'{name} socket timeout'
        time.sleep(.1)
    return process

def cli(*args, ok=True):
    result = subprocess.run([str(root / 'bin/fic-cli'), *args], capture_output=True, text=True)
    assert (result.returncode == 0) == ok, (args, result.stdout, result.stderr)
    return result

def ipc(endpoint, request):
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as client:
        client.settimeout(15)
        client.connect('/run/fic/' + endpoint)
        request['api_version'] = 1
        client.send(json.dumps(request).encode())
        return helper['receive_response'](client)

def state():
    with sqlite3.connect(root / 'db/devices.db') as db:
        return db.execute('SELECT block_usb_storage,block_printers_scanners,block_optical_drives,usb_epoch,printers_epoch,optical_epoch,desired_revision,active_revision FROM device_policy_state').fetchone()

def wait_state(predicate):
    deadline = time.monotonic() + 15
    while not predicate(state()):
        assert time.monotonic() < deadline, state()
        time.sleep(.1)

try:
    dick = start('fic-dick', ['--daemon'])
    daemon = start('fic', ['--interval', '2'])
    names = ('block_usb_storage', 'block_printers_scanners', 'block_optical_drives')
    for index, name in enumerate(names):
        cli('policy', 'set', 'DC', name, 'all')
        cli('policy', 'enable', 'DC', name)
        assert state()[index] == 'all'
        cli('policy', 'apply', 'DC', 'all')
        cli('policy', 'set', 'DC', name, 'new')
        before = state()
        assert before[index] == 'new' and before[index + 3] == 1
        cli('policy', 'set', 'DC', name, 'new')
        cli('policy', 'apply', 'DC', name)
        assert state()[index + 3] == 1
        cli('policy', 'set', 'DC', name, 'true', ok=False)
        cli('policy', 'disable', 'DC', name)
        assert state()[index] == 'disabled'
    cli('policy', 'apply', 'DC', 'all')  # all disabled still reconciles
    before_invalid = state()
    desired_fields = dict.fromkeys(names, 'disabled')
    for invalid in ({'block_usb_storage': True}, {'block_usb_storage': 'bogus'}, {'extra': 'all'}):
        bad = ipc('fic-device.sock', {'command': 'device_regenerate_policy', **desired_fields, **invalid})
        assert not bad['ok'] and state() == before_invalid
    bad = ipc('fic-device.sock', {'command': 'device_regenerate_policy'})
    assert not bad['ok'] and state() == before_invalid
    # Actual SQLite write failure must not fabricate a rolled-back config.
    with sqlite3.connect(root / 'db/devices.db') as db:
        db.execute("CREATE TRIGGER gate_save_failure BEFORE UPDATE ON device_policy_state BEGIN SELECT RAISE(ABORT,'gate save failure'); END")
    cli('policy', 'enable', 'DC', names[0], ok=False)
    assert state()[0] == 'disabled'
    assert 'block_usb_storage.status=ENABLE' in (root / 'config/DC.conf').read_text()
    with sqlite3.connect(root / 'db/devices.db') as db: db.execute('DROP TRIGGER gate_save_failure')
    wait_state(lambda row: row[0] == 'new' and row[6] == row[7])
    cli('policy', 'disable', 'DC', names[0])
    # Failed activation preserves persistent intent and desired/active difference.
    Path('/tmp/dc-fail-activation').touch()
    cli('policy', 'enable', 'DC', names[0], ok=False)
    assert state()[0] == 'new' and state()[6] != state()[7]
    Path('/tmp/dc-fail-activation').unlink()
    wait_state(lambda row: row[6] == row[7])
    # Compilation failure keeps desired intent and the previous active revision.
    with sqlite3.connect(root / 'db/devices.db') as db:
        parent = db.execute("SELECT id FROM devices WHERE subsystem='__computer__'").fetchone()[0]
        bad_id = db.execute("INSERT INTO devices(device_hash,devpath,subsystem,device_type,parent_id,control_level,control_explicit,ignore_hierarchy,boot_id) VALUES('compile-fault','/devices/compile-fault','pci','pci',?,'allowed',1,1,'fixture')", (parent,)).lastrowid
    cli('policy', 'set', 'DC', names[0], 'all', ok=False)
    assert state()[0] == 'all' and state()[6] != state()[7]
    with sqlite3.connect(root / 'db/devices.db') as db: db.execute('DELETE FROM devices WHERE id=?', (bad_id,))
    wait_state(lambda row: row[6] == row[7])
    # Publication failure (target replaced by a directory), then periodic repair.
    rules_path = Path('/etc/udev/rules.d/99-fic-devices.rules')
    previous_rules = rules_path.read_text()
    rules_path.unlink(); rules_path.mkdir()
    cli('policy', 'set', 'DC', names[0], 'new', ok=False)
    assert state()[0] == 'new' and state()[6] != state()[7]
    rules_path.rmdir(); rules_path.write_text(previous_rules)
    wait_state(lambda row: row[6] == row[7])
    # Intent/database drift is repaired by periodic even with no enabled category.
    cli('policy', 'disable', 'DC', names[0])
    with sqlite3.connect(root / 'db/devices.db') as db:
        db.execute("UPDATE device_policy_state SET block_usb_storage='all',desired_revision=desired_revision+1")
    wait_state(lambda row: row[0] == 'disabled' and row[6] == row[7])
    cli('policy', 'set', 'DC', names[0], 'all')
    cli('policy', 'enable', 'DC', names[0])
    with sqlite3.connect(root / 'db/devices.db') as db:
        db.execute("UPDATE device_policy_state SET block_usb_storage='disabled',desired_revision=desired_revision+1")
    wait_state(lambda row: row[0] == 'all' and row[6] == row[7])
    cli('policy', 'set', 'DC', names[0], 'new')
    cli('policy', 'set', 'DC', names[0], 'all')
    Path('/tmp/dc-fail-activation').touch()
    cli('policy', 'set', 'DC', names[0], 'new', ok=False)
    epoch = state()[3]
    assert state()[6] != state()[7]
    daemon.terminate(); daemon.wait(timeout=15)
    dick.kill(); dick.wait(timeout=15)
    Path('/tmp/dc-fail-activation').unlink()
    dick = start('fic-dick', ['--daemon'])
    daemon = start('fic', ['--interval', '2'])
    wait_state(lambda row: row[0] == 'new' and row[6] == row[7])
    assert state()[3] == epoch
    journal = root / 'db/mutation-journal.json'
    if journal.exists():
        content = journal.read_text()
        assert 'device_control' not in content and 'disable_device_feature' not in content
    assert Path('/etc/udev/rules.d/99-fic-devices.rules').exists()
    # Native rule parser/matcher on a read-only virtual block sysfs node.
    # udevadm test schedules RUN but does not execute it. No host sysfs writes.
    native = Path('/tmp/udevadm-native')
    virtual = sorted(Path('/sys/devices/virtual/block').glob('loop*'))
    if native.exists() and virtual:
        device_path = virtual[0]
        devpath = str(device_path)[4:]
        cli('policy', 'disable', 'DC', names[0])
        with sqlite3.connect(root / 'db/devices.db') as db:
            parent = db.execute("SELECT id FROM devices WHERE subsystem='__computer__'").fetchone()[0]
            cursor = db.execute("INSERT INTO devices(device_hash,devpath,subsystem,device_type,parent_id,control_level,control_explicit,boot_id) VALUES('native-known','/devices/native-known','block','disk',?,'allowed',0,'fixture')", (parent,))
            for key, value in [('ID_BUS', 'usb'), ('ID_WWN', 'fic-native-known'), ('DEVTYPE', 'disk')]:
                db.execute('INSERT INTO device_attributes(device_id,attribute_name,attribute_value) VALUES(?,?,?)', (cursor.lastrowid, key, value))
        with sqlite3.connect(root / 'db/devices.db') as db:
            usb_id = db.execute("INSERT INTO devices(device_hash,devpath,subsystem,device_type,parent_id,control_level,control_explicit,boot_id) VALUES('native-usb-known','/devices/native-usb-known','usb','usb',?,'allowed',0,'fixture')", (parent,)).lastrowid
            for key, value in [('DEVTYPE', 'usb_device'), ('ID_VENDOR_ID', '1234'), ('ID_MODEL_ID', '5678'), ('ID_SERIAL_SHORT', 'native-usb-known')]:
                db.execute('INSERT INTO device_attributes(device_id,attribute_name,attribute_value) VALUES(?,?,?)', (usb_id, key, value))
        cli('policy', 'set', 'DC', names[0], 'new')
        cli('policy', 'enable', 'DC', names[0])
        fixture_rule = Path('/etc/udev/rules.d/98-fic-native-fixture.rules')
        def native_level(identity, expected):
            fixture_rule.write_text('SUBSYSTEM=="block", ENV{ID_BUS}="usb", ENV{ID_WWN}="' + identity + '"\n')
            result = subprocess.run([str(native), 'test', str(device_path)], capture_output=True, text=True)
            text = result.stdout + result.stderr
            with open(build / 'dc-native-udev.log', 'a') as output: output.write(text + '\n')
            assert result.returncode == 0, text[-4000:]
            assert 'FIC_EFFECTIVE_LEVEL=' + expected in text, text[-4000:]
            assert 'Invalid key' not in text and 'Invalid rule' not in text
        native_level('fic-native-known', 'ALLOW')
        native_level('fic-native-new', 'DENY')
        with sqlite3.connect(root / 'db/devices.db') as db:
            cursor = db.execute("INSERT INTO devices(device_hash,devpath,subsystem,device_type,parent_id,control_level,control_explicit,boot_id) VALUES('native-placement',?,'block','disk',?,'allowed',1,?)", (devpath, parent, Path('/proc/sys/kernel/random/boot_id').read_text().strip()))
            placement_id = cursor.lastrowid
        cli('policy', 'apply', 'DC', 'all')
        native_level('fic-native-new', 'ALLOW')
        cli('policy', 'set', 'DC', names[0], 'all')
        for level in ('allowed', 'ignored', 'permanent'):
            cli('device', 'set', str(placement_id), level)
            native_level('fic-native-new', 'DENY')
        with sqlite3.connect(root / 'db/devices.db') as db:
            db.execute('INSERT INTO device_attributes(device_id,attribute_name,attribute_value) VALUES(?,?,?)', (placement_id, 'ID_WWN', 'fic-native-new'))
        cli('device', 'ignore-hierarchy', str(placement_id), 'true')
        native_level('fic-native-new', 'DENY')
        print('PASS: native udevadm test known/new, explicit new ALLOW, absolute all over ALLOW/IGNORE/PERMANENT/direct identity; RUN not executed')
    else:
        print('SKIP native udev matcher: native udevadm or read-only virtual block sysfs node unavailable')
    print('PASS: real CLI/IPC three modes, disable/all-disabled, DB/compile/publish/activation failures, desired/active recovery, periodic drift, crash/restart epochs, no DC rollback')
    print('Activation/inventory: fixtures; physical hardware enforcement not exercised')
finally:
    for process in reversed(processes):
        if process.poll() is None:
            process.terminate()
            try: process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait()
    for output in logs: output.close()
