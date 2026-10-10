#!/usr/bin/env python3
"""Native ALT gate. Run ONLY in a disposable container; arguments: driver probe evidence."""
import hashlib
import json
import os
import time
import re
from pathlib import Path
import subprocess
import sys

if not __debug__:
    raise RuntimeError('NOT VERIFIED: Python assertions must be enabled')
if os.getuid() != 0 or not Path('/.dockerenv').exists():
    raise RuntimeError('NOT VERIFIED: disposable root Docker container required')
if 'ID=altlinux' not in Path('/etc/os-release').read_text():
    raise RuntimeError('NOT VERIFIED: native ALT required')
driver, probe, evidence = sys.argv[1:4]
out = Path(evidence); out.mkdir(parents=True, exist_ok=True)
primary = Path('/etc/passwdqc.conf')
journal = Path('/var/lib/fic/pam-provider-gate/mutation-journal.json')
log = (out / 'commands.log').open('w')
passes = []
def matrix(status, failures=None):
    (out / 'matrix.json').write_text(json.dumps(
        {'status': status, 'PASS': passes, 'FAIL': failures or []}, indent=2))
matrix('RUNNING')  # Never leave a stale PASS from an earlier invocation.
def failed(kind, error, traceback):
    matrix('FAIL', [f'{kind.__name__}: {error}'])
    sys.__excepthook__(kind, error, traceback)
sys.excepthook = failed

def run(args, ok=True, env=None):
    result = subprocess.run(list(map(str, args)), capture_output=True, text=True, env=env)
    log.write(f'{args!r}\nexit={result.returncode}\n{result.stdout}{result.stderr}\n'); log.flush()
    assert (result.returncode == 0) == ok, result.stdout + result.stderr
    return result.stdout

def action(name, key, value=None, ok=True, env=None):
    args = [driver, name, 'pam_passwdqc', key]
    if value is not None: args.append(value)
    return run(args, ok, env)

def native():
    return dict(line.split('=', 1) for line in run([probe, primary]).splitlines())

def hashes():
    return {str(p): {'sha256': hashlib.sha256(p.read_bytes()).hexdigest(),
                    'link': os.readlink(p) if p.is_symlink() else None,
                    'mode': p.stat().st_mode, 'uid': p.stat().st_uid, 'gid': p.stat().st_gid}
            for p in sorted(Path('/etc/pam.d').iterdir()) if p.is_file()}

Path(out / 'os-release').write_bytes(Path('/etc/os-release').read_bytes())
Path(out / 'packages.txt').write_text(run(['rpm', '-q', 'libpasswdqc', 'pam0_passwdqc', 'pam', 'pam-config']))
assert run(['rpm', '-ql', 'pam0_passwdqc']).find('pam_passwdqc.so') >= 0
before = hashes(); (out / 'pam-before.json').write_text(json.dumps(before, indent=2))
(out / 'pam-topology.json').write_text(json.dumps(
    {str(p): p.read_text(errors='backslashreplace')
     for p in sorted(Path('/etc/pam.d').iterdir()) if p.is_file()}, indent=2))
run([driver, 'report'])
if len(sys.argv) == 5 and sys.argv[4] == '--write-failure':
    assert primary.stat().st_uid == 0 and primary.stat().st_mode & 0o022 == 0
    original = primary.read_bytes()
    action('apply', 'match', '5', ok=False)
    assert primary.read_bytes() == original and hashes() == before
    assert any(r['status'] == 'prepared' for r in json.loads(journal.read_text())['records'])
    passes.append('read-only primary atomic replacement fails after Prepared; no bytes/topology changed')
    matrix('PASS')
    sys.exit(0)
original = primary.read_bytes(); (out / 'primary-installed.before').write_bytes(original)
# Deliberate administrator fixture in the REAL primary; includes a native config=.
include = Path('/etc/fic-passwdqc-gate-include.conf')
include.write_text('match=3\npassphrase=4\n')
foreign = b'# administrator bytes\nmin=disabled,24,11,8,7\nmatch=1\nconfig=/etc/fic-passwdqc-gate-include.conf\nmatch=2\nsimilar=permit\nretry=2\nenforce=users\npassphrase=3\n'
primary.write_bytes(foreign); os.chmod(primary, 0o644)
values = {'min': 'disabled,24,11,8,7', 'passphrase': '4', 'match': '5',
          'similar': 'deny', 'retry': '4', 'enforce': 'everyone'}
base = native()
def passed(name):
    passes.append(name); matrix('RUNNING')

# Each assignment: original equal/different values, native priority and exact release.
for key, value in values.items():
    action('apply', key, value); assert native()[key] == value
    action('apply', key, value); assert native()[key] == value
    if key == 'min':
        action('apply', key, 'disabled,23,10,8,7'); assert native()[key] == 'disabled,23,10,8,7'
    action('disable', key); action('disable', key)
    assert native()[key] == base[key] and primary.read_bytes() == foreign
passed('each of six: native parser, priority, apply/rollback idempotence, foreign bytes')
for order in [list(values), list(reversed(values))]:
    for key, value in values.items(): action('apply', key, value)
    assert all(native()[k] == v for k, v in values.items())
    admin = b'# later administrator change\nconfig=/etc/fic-passwdqc-gate-include.conf\nmatch=2\n'
    primary.write_bytes(primary.read_bytes() + admin)
    action('apply', 'match', '5')  # Relocate whole block to root EOF.
    assert native()['match'] == '5'
    action('apply', 'match', '6'); assert native()['match'] == '6'
    action('apply', 'enforce', 'users'); assert native()['enforce'] == 'users'
    action('apply', 'enforce', 'everyone')
    for key in order: action('disable', key)
    assert primary.read_bytes() == foreign + admin
    assert native()['passphrase'] == '4', 'rollback must expose CURRENT foreign include value'
    primary.write_bytes(foreign)
passed('six together, two rollback orders, refresh, enforce users/everyone, EOF relocation')
for key, value in values.items(): action('apply', key, value)
run([driver, 'preflight']); run([driver, 'release']); run([driver, 'release'])
assert primary.read_bytes() == foreign
passed('package preflight/release multiple entries and repeat')
# Drift and ABA must refuse both ordinary rollback and package preflight.
for changed in [lambda b: b.replace(b"# FIC_PAM_PROVIDER_BLOCK_END", re.search(rb"# FIC_PAM_ENTRY_BEGIN[^\n]*\n[^\n]*\n# FIC_PAM_ENTRY_END\n", b).group(0) + b"# FIC_PAM_PROVIDER_BLOCK_END"),
                lambda b: b.replace(b'match=5\n', b'match=6\n'),
                lambda b: b.replace(b'mutation=', b'mutation=9', 1),
                lambda b: b.replace(b'FIC_PAM_ENTRY_END', b'FIC_PAM_ENTRY_BROKEN', 1)]:
    action('apply', 'match', '5'); owned = primary.read_bytes()
    primary.write_bytes(changed(owned)); damaged = primary.read_bytes()
    action('disable', 'match', ok=False); run([driver, 'preflight'], ok=False)
    assert primary.read_bytes() == damaged
    primary.write_bytes(owned); action('disable', 'match')
passed('drift, foreign mutation ID/ABA, corrupted markers: conflict refusal without writes')
# Orphan: hide the journal AND virgin witness together (never host state).
action('apply', 'match', '5')
saved = [(p, p.read_bytes()) for p in journal.parent.iterdir() if p.is_file()]
for p, _ in saved: p.unlink()
action('disable', 'match', ok=False); run([driver, 'preflight'], ok=False)
for p, data in saved: p.write_bytes(data); os.chmod(p, 0o600)
action('disable', 'match')
passed('orphan physical ownership refused without journal')
# Inject durability and post-write failures; restart driver must recover its durable target.
for fault in ['primary-fsync', 'journal-fsync', 'applied-fsync', 'semantic']:
    env = dict(os.environ, FIC_PROVIDER_GATE_FAULT=fault)
    action('apply', 'match', '5', ok=False, env=env)
    action('apply', 'match', '6'); assert native()['match'] == '6'
    action('disable', 'match'); assert primary.read_bytes() == foreign
passed('primary/Prepared/Applied fsync and semantic failures: recovery then refresh')
action('apply', 'match', '5', ok=False, env=dict(os.environ, FIC_PROVIDER_GATE_FAULT='primary-cas'))
assert primary.read_bytes() == foreign + b'# concurrent admin\n'
action('apply', 'match', '6'); action('disable', 'match')
assert primary.read_bytes() == foreign + b'# concurrent admin\n'
primary.write_bytes(foreign)
passed('snapshot CAS refusal preserves concurrent administrator bytes; restart recovery')
owner = subprocess.Popen([driver, 'hold-lock'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
assert owner.stdout.readline().strip() == 'locked'
contender = subprocess.Popen([driver, 'apply', 'pam_passwdqc', 'match', '5'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
try:
    time.sleep(0.2); assert contender.poll() is None, 'apply did not serialize on lock'
    run([driver, 'release'], ok=False)
finally:
    owner.communicate('\n', timeout=10)
stdout, stderr = contender.communicate(timeout=15)
log.write(f'concurrent apply exit={contender.returncode}\n{stdout}{stderr}\n')
assert contender.returncode == 0 and native()['match'] == '5'
action('disable', 'match')
passed('shared interprocess lock: apply waits, package release refuses, no lost entry')
for key, value in values.items(): action('apply', key, value)
run([driver, 'release'], ok=False, env=dict(os.environ, FIC_PROVIDER_GATE_FAULT='journal-fsync'))
run([driver, 'release']); assert primary.read_bytes() == foreign
passed('partial package release journal failure then restart/repeat')
# Missing, writable and symlink primary must fail closed, not create/follow.
primary.unlink(); action('apply', 'match', '5', ok=False); assert not primary.exists()
primary.write_bytes(foreign); os.chmod(primary, 0o666)
action('apply', 'match', '5', ok=False); os.chmod(primary, 0o644)
primary.unlink(); primary.symlink_to(include)
action('apply', 'match', '5', ok=False); primary.unlink(); primary.write_bytes(foreign)
passed('absent primary, writable permissions, symlink refusal')
# Native parser rejects spaced assignment; catches accidental generic serializer use.
primary.write_bytes(b'match = 5\n'); run([probe, primary], ok=False)
primary.write_bytes(foreign)
passed('native negative control rejects key = value')
assert hashes() == before, 'RPM PAM service topology modified'
(out / 'pam-after.json').write_text(json.dumps(hashes(), indent=2))
(out / 'primary.after').write_bytes(primary.read_bytes())
(out / 'sha256.json').write_text(json.dumps({'before': hashlib.sha256(foreign).hexdigest(),
    'after': hashlib.sha256(primary.read_bytes()).hexdigest()}, indent=2))
passed('RPM-owned PAM topology unchanged, before/after hashes equal')
matrix('PASS')
print(json.dumps({'status': 'PASS', 'PASS': passes}, indent=2))
