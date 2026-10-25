"""Real daemon restricted-mode probe; not package-manager E2E.

Only run in the disposable PID1 systemd container created by the native runner.
The fixture intentionally supplies no healthy policy configuration or journal.
"""
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import time

assert os.environ.get('FIC_PACKAGE_LIFECYCLE_NATIVE') == '1'
assert Path('/proc/1/comm').read_text().strip() == 'systemd'
assert os.stat('/proc/self/ns/mnt').st_ino != int(os.environ['FIC_HOST_MNT_INODE'])
assert subprocess.run(['systemctl', 'show-environment'], capture_output=True).returncode == 0
subprocess.run(['mount','--rbind','/sys','/sys'],check=True)
subprocess.run(['mount','-o','remount,bind,ro','/sys'],check=True)
assert os.statvfs('/sys').f_flag & os.ST_RDONLY
subprocess.run(['groupadd', '-f', 'fic'], check=True)
state = Path('/var/lib/fic-lifecycle/status')
if sys.argv[1:]==['--resume-after-pid1-restart']:
    assert state.read_text()=='UNINSTALLING\n'
    assert not Path('/run/fic/daemon.lock').exists(), 'runtime lock survived tmpfs restart'
else:
    assert not sys.argv[1:]
    Path('/var/lib/fic-lifecycle').mkdir(mode=0o700)
    state.write_text('UNINSTALLING\n'); state.chmod(0o600)
    Path('/opt/fic/db').mkdir(parents=True)
    Path('/opt/fic/config').mkdir()
# Malformed configuration and journal must never trigger containment/apply in
# restricted startup, and readonly requests must not bootstrap provenance.
config = Path('/opt/fic/config/GLOBAL.conf')
journal = Path('/opt/fic/db/mutation-journal.json')
if not sys.argv[1:]:
    config.write_text('invalid config\n')
    journal.write_text('damaged journal\n')
assert config.read_text()=='invalid config\n' and journal.read_text()=='damaged journal\n'
before = (config.read_bytes(), journal.read_bytes())

def request(command, **fields):
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as client:
        client.settimeout(10)
        client.connect('/run/fic/fic.sock')
        client.send(json.dumps(dict(api_version=1, command=command, **fields)).encode())
        body = b''
        while True:
            frame = client.recv(1024*1024)
            assert len(frame) >= 16, 'truncated IPC header'
            magic, total, offset, length = struct.unpack('!4I', frame[:16])
            assert magic == 0x00464943 and offset == len(body) and len(frame) == 16 + length
            assert len(body) + length <= total <= 1024*1024
            body += frame[16:]
            if len(body) == total:
                return json.loads(body)

children = []

def start():
    log = open('/run/lifecycle-daemon.log', 'ab')
    p = subprocess.Popen(['/opt/fic/bin/fic', '--interval', '1'], stdout=log, stderr=log)
    log.close()
    children.append(p)
    for _ in range(100):
        assert p.poll() is None, Path('/run/lifecycle-daemon.log').read_text()
        try:
            result = request('status')
            assert result['ok'] and result['lifecycle_state'] == 'UNINSTALLING', result
            return p
        except (FileNotFoundError, ConnectionRefusedError):
            time.sleep(.1)
    raise AssertionError('daemon socket deadline')

p = None
try:
    p = start()
    for command, fields in [
        ('apply_all', {}), ('apply_module', {'module': 'NET'}),
        ('apply_policy', {'module': 'NET', 'policy': 'ssh_use_pam'}),
        ('enable_policy', {'module': 'NET', 'policy': 'ssh_use_pam'}),
        ('disable_policy', {'module': 'NET', 'policy': 'ssh_use_pam'}),
        ('set_policy_value', {'module': 'NET', 'policy': 'ssh_use_pam', 'value': 'YES'}),
        ('reload_config', {}), ('incident_clear', {}),
    ]:
        reply = request(command, **fields)
        assert not reply['ok'] and reply['error_code'] == 'UNINSTALL_IN_PROGRESS', reply
    reply = request('prepare_uninstall')
    assert reply['ok'], reply
    time.sleep(2.2)  # More than two configured periodic apply intervals.
    assert (config.read_bytes(), journal.read_bytes()) == before
    assert not Path(str(journal) + '.initialized').exists()
    p.kill(); p.wait(timeout=10)
    p = start()
    assert request('prepare_uninstall')['ok']
    assert (config.read_bytes(), journal.read_bytes()) == before
    assert state.read_text() == 'UNINSTALLING\n'
    p.send_signal(signal.SIGTERM)
    assert p.wait(timeout=10) == 0
    p = None
    print('PASS: real restricted daemon, denied mutations, periodic suppression, SIGKILL/restart, no config/journal repair')
finally:
    for child in children:
        if child.poll() is None:
            child.kill(); child.wait(timeout=10)
