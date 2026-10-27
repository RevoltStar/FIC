#!/usr/bin/env python3
"""Disposable real-OpenSSH adapter/module experiments; no host SSH or shell emulation."""
import glob
import ctypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import struct
import subprocess
import sys

WORK = Path('/run/fic-openssh-work')
OUT = Path('/run/fic-openssh-results')
MAIN = Path('/etc/ssh/sshd_config')
ENV = Path('/etc/default/ssh')
DROP = Path('/etc/ssh/sshd_config.d')
STOCK_DROP = DROP
KEY = Path('/etc/ssh/ssh_host_ed25519_key')
DRIVER = '/usr/local/bin/fic-openssh-driver'


def run(args, check=True, timeout=20):
    p = subprocess.run(args, text=True, capture_output=True, timeout=timeout)
    if check and p.returncode:
        raise RuntimeError(f'{args[0]} failed: {p.stderr[:1000]} {p.stdout[-4000:]}')
    return p


def guard():
    token = os.environ.get('FIC_OPENSSH_DISPOSABLE')
    assert token and os.geteuid() == 0 and Path('/.dockerenv').exists(), 'explicit disposable Docker required'
    assert (WORK / 'runner-marker').read_text() == token, 'runner marker mismatch'
    assert Path('/proc/1/comm').read_text() == 'systemd\n'
    ns = os.stat('/proc/1/ns/mnt')
    assert f'{ns.st_dev}:{ns.st_ino}' != os.environ['FIC_OPENSSH_HOST_MNT']
    root = os.stat('/')
    assert f'{root.st_dev}:{root.st_ino}' != os.environ['FIC_OPENSSH_HOST_ROOT']
    own = os.stat('/proc/self/ns/mnt')
    assert (own.st_dev, own.st_ino) == (ns.st_dev, ns.st_ino)
    assert sorted(p.name for p in Path('/sys/class/net').iterdir()) == ['lo'], 'host network forbidden'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def config(port=2222, addendum='FIC_VERIFIED', extra=''):
    # Deliberately no authentication: the gate only uses loopback identification.
    return (f'Include {DROP}/*.conf\nPort {port}\nListenAddress 127.0.0.1\n'
            f'HostKey {KEY}\nPasswordAuthentication no\nPubkeyAuthentication no\n'
            'KbdInteractiveAuthentication no\nPermitRootLogin no\nUsePAM no\n'
            f'VersionAddendum {addendum}\nPermitTTY yes\n{extra}')


def covered(path, targets, directory=False):
    path = Path(path)
    for t in targets:
        root = Path(t['path'])
        if t.get('directory') and (path == root or root in path.parents):
            return True
        if not directory and root == path and not t.get('directory'):
            return True
    return False


def closure(path, targets, seen=None):
    """Conservative fixture-only grammar. No shell/systemd env parser.

    Accept only literal absolute Include patterns with wildcards in basename.
    Refuse unknown quoting, cycles, unsafe metadata and uncovered glob parents.
    This describes a bounded test language, not the OpenSSH parser contract.
    """
    seen = set() if seen is None else seen
    path = Path(path)
    assert len(seen) < 256 and path not in seen, 'closure cycle/limit'
    seen.add(path)
    issues = []
    for component in [path, *path.parents]:
        st = component.lstat()
        if stat.S_ISLNK(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            issues.append('untrusted/symlink: ' + str(component))
    if path.is_symlink():
        return issues + ['symlink target is not expanded by fixture analyzer']
    if not covered(path, targets):
        issues.append('uncovered file: ' + str(path))
    for line in path.read_text().splitlines():
        fields = line.split()
        if not fields or fields[0].startswith('#') or fields[0].lower() != 'include':
            continue
        for pattern in fields[1:]:
            assert pattern.startswith('/') and not any(x in pattern for x in ['"', "'", '\\', '~', '%']), 'outside fixture grammar'
            parent = Path(pattern).parent
            assert not any(x in str(parent) for x in '*?['), 'directory glob unsupported'
            if not covered(parent, targets, directory=True):
                issues.append('unguarded Include parent/negative set: ' + str(parent))
            for match in sorted(glob.glob(pattern)):
                issues += closure(match, targets, seen)
    return issues


def request(include_dir=True):
    files = [MAIN, ENV, KEY, Path(str(KEY) + '.pub')]
    targets = [{'path': str(p), 'sha256': sha(p)} for p in files]
    if include_dir:
        manifest = {str(p.relative_to(DROP)): sha(p) for p in DROP.rglob('*') if p.is_file()}
        targets.insert(1, {'path': str(DROP), 'directory': True, 'manifest': manifest})
    return {'timeout_ms': 10000, 'paths': targets, 'glob_dir': str(DROP)}


def drive(action, req, allow_crash=False):
    p = WORK / 'request.json'
    p.write_text(json.dumps(req))
    # A module request contains several independent bounded production
    # operations (admission/reference/activation each have their own deadline).
    # A fixed 150s aggregate deadline truncated valid multi-operation ALT runs.
    operations=len(req.get('operations', []))
    assert action!='module' or 0<operations<=64
    process = run([DRIVER, action, str(p)], check=not allow_crash,
                  timeout=30+240*operations if action == 'module' else 240 if action=='plan-release' else 35)
    if allow_crash and process.returncode == -9:
        return {'status': 'SIGKILL', 'readinessConfirmed': False}
    data = json.loads(process.stdout.splitlines()[-1])
    if action == 'module': data['policy_log'] = '\n'.join(process.stdout.splitlines()[:-1])[-8000:]
    assert 'harness_error' not in data, data
    return data


def reference_matches(req):
    """Persistent byte/manifest compliance, not a complete SSH policy audit."""
    for target in req['paths']:
        p = Path(target['path'])
        if p.is_symlink() or not p.exists(): return False
        if target.get('directory'):
            if not p.is_dir(): return False
            actual = {str(f.relative_to(p)): sha(f) for f in p.rglob('*') if f.is_file()}
            if actual != target['manifest']: return False
        elif not p.is_file() or sha(p) != target['sha256']: return False
    return True


def state():
    wanted = ['Id', 'Type', 'NotifyAccess', 'ActiveState', 'SubState', 'MainPID', 'InvocationID', 'Job',
              'FragmentPath', 'DropInPaths', 'TriggeredBy', 'PrivateMounts', 'PrivateTmp', 'ProtectSystem',
              'RootDirectory', 'RootImage', 'MountFlags']
    p = run(['systemctl', 'show', 'ssh.service', '--property=' + ','.join(wanted)])
    out = dict(line.split('=', 1) for line in p.stdout.splitlines() if '=' in line)
    if out.get('MainPID', '0') != '0':
        pid = out['MainPID']
        out['process_mnt_ns'] = os.readlink('/proc/' + pid + '/ns/mnt')
        fields = Path('/proc/' + pid + '/stat').read_text().rsplit(')', 1)[1].split()
        out['process_starttime'] = fields[19]
    return out


def handshake(port):
    with socket.create_connection(('127.0.0.1', port), timeout=3) as sock:
        stream = sock.makefile('rb')
        identification = stream.readline(512).decode('ascii').strip()
        assert identification.startswith('SSH-2.0-')
        sock.sendall(b'SSH-2.0-FIC_Disposable_Probe\r\n')
        header = stream.read(4)
        assert len(header) == 4
        length = int.from_bytes(header, 'big')
        assert 2 <= length <= 65536
        packet = stream.read(length)
        assert len(packet) == length and packet[1] == 20, 'expected SSH_MSG_KEXINIT'
        return identification


def effective():
    p = run(['/usr/sbin/sshd', '-T', '-C', 'user=nobody,host=localhost,addr=127.0.0.1'])
    return [line for line in p.stdout.splitlines() if line.split(' ', 1)[0] in
            {'port', 'listenaddress', 'versionaddendum', 'permittty', 'usepam', 'passwordauthentication', 'pubkeyauthentication'}]


def diagnostics():
    for pid in ('1', 'self'):
        (OUT / ('mountinfo-' + pid + '.txt')).write_text(Path('/proc/' + pid + '/mountinfo').read_text())
    paths = [str(MAIN), str(DROP), str(ENV), '/run/fic']
    return {'kernel': os.uname().release, 'os_release': Path('/etc/os-release').read_text(),
            'packages': run(['dpkg-query', '-W', '-f=${Package} ${Version}\n', 'openssh-server', 'systemd']).stdout,
            'sshd_version': run(['/usr/sbin/sshd', '-V'], check=False).stderr.strip(),
            'self_mnt_ns': os.readlink('/proc/self/ns/mnt'), 'pid1_mnt_ns': os.readlink('/proc/1/ns/mnt'),
            'topology': {p: run(['findmnt', '-T', p, '-n', '-o', 'TARGET,PROPAGATION,FSTYPE'], check=False).stdout.strip() for p in paths},
            'metadata': {p: {'uid': Path(p).lstat().st_uid, 'gid': Path(p).lstat().st_gid,
                             'mode': oct(stat.S_IMODE(Path(p).lstat().st_mode)), 'symlink': Path(p).is_symlink(),
                             'xattr_names': os.listxattr(p, follow_symlinks=False)} for p in paths},
            'socket_state': run(['systemctl', 'is-active', 'ssh.socket'], check=False).stdout.strip(), 'unit': state()}


def main():
    global DROP
    guard()
    OUT.mkdir(exist_ok=True)
    result = {'cases': [], 'environment': {}, 'limitations': [],
              'run_id': hashlib.sha256(os.environ['FIC_OPENSSH_DISPOSABLE'].encode()).hexdigest()}
    libc = ctypes.CDLL(None)
    result['initial_xattrs'] = {str(p): {'size_query': libc.listxattr(os.fsencode(p), None, 0),
                                       'names': os.listxattr(p)} for p in (MAIN, ENV, DROP)}
    original_units = {}
    # Backups/keys stay in WORK; only OUT is exported. Never serialize key bytes.
    backup = WORK / 'backup'
    backup.mkdir()
    originals = [MAIN, ENV, DROP, KEY, Path(str(KEY) + '.pub')]
    existed = {str(p): p.exists() for p in originals}
    for i, path in enumerate(originals):
        if path.exists():
            if path.is_dir(): shutil.copytree(path, backup / str(i), symlinks=True)
            else: shutil.copy2(path, backup / str(i), follow_symlinks=False)
    try:
        fragment = state()['FragmentPath']
        for p in [Path(fragment), *Path('/etc/systemd/system/ssh.service.d').glob('*')]:
            original_units[str(p)] = sha(p)
        run(['systemctl', 'stop', 'ssh.service'])
        assert run(['systemctl', 'is-active', 'ssh.socket'], check=False).returncode != 0, 'socket activation not supported'
        # Keep the existing empty vendor Include directory untouched for baseline.
        # Recreating it on OverlayFS itself adds opaque copy-up metadata.
        assert DROP.is_dir() and not any(DROP.iterdir()), 'fixture image requires empty vendor Include directory'
        # Fresh disposable key, unrelated to host/user credentials.
        KEY.unlink(missing_ok=True)
        Path(str(KEY) + '.pub').unlink(missing_ok=True)
        run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(KEY)])
        def reset():
            run(['systemctl', 'stop', 'ssh.service'], check=False)
            run(['systemctl', 'unset-environment', 'FIC_OPENSSH_TEST_CHANGE'])
            drive('cleanup', {'paths': []})
            # Preserve the copied-up stock inode; only undo the explicit
            # negative symlink fixture. No fresh-file workaround.
            if MAIN.is_symlink(): MAIN.unlink()
            MAIN.write_text(config())
            MAIN.chmod(0o644)
            ENV.write_text('SSHD_OPTS=\n'); ENV.chmod(0o644)
            for p in DROP.iterdir():
                if p.is_dir() and not p.is_symlink(): shutil.rmtree(p)
                else: p.unlink()
            (WORK / 'mutation.conf').write_text(config(2223, 'ORIGINAL_CHANGED'))
            (WORK / 'external.conf').write_text(config(2224, 'EXTERNAL'))
            run(['systemctl', 'reset-failed', 'ssh.service'], check=False)
            Path('/run/sshd').mkdir(exist_ok=True)
            run(['/usr/sbin/sshd', '-t'])
            run(['systemctl', 'start', 'ssh.service'])
        reset()
        Path('/run/fic').mkdir(exist_ok=True)
        result['environment'] = diagnostics()
        result['copyup_preflight'] = drive('preflight', request())
        reset()
        pre = drive('preflight', request())
        result['preflight'] = pre
        assert pre['status'] == 'SUPPORTED', pre
        assert not pre['TriggeredBy']['value'], 'socket/triggers present'
        result['input_paths'] = [p['path'] for p in request()['paths']]
        result['initial_closure_issues'] = closure(MAIN, request()['paths'])
        assert not result['initial_closure_issues']

        def experiment(name, action='activate', req=None, expected=('Success',), port=2222,
                       banner='FIC_VERIFIED', semantic='PROVEN', persistent='PROVEN', network=True):
            req = req or request()
            before = state()
            record = {'name': name, 'before': before, 'closure_issues': closure(MAIN, req['paths']), 'mode': action}
            # Refuse nonempty/unknown options for semantic proof; never emulate
            # systemd's quoting/expansion or infer argv from rewritten cmdline.
            record['argv_issues'] = ([] if ENV.exists() and ENV.read_text() == 'SSHD_OPTS=\n' else
                                     ['nonempty/unknown SSHD_OPTS: fixture semantic guard refuses'])
            data = drive(action, req, action == 'crash')
            record['activation'] = data
            assert data['status'] in expected, (name, data)
            after = state(); record['after'] = after
            success = data.get('primaryStatus') == 'Success'
            record['A'] = 'PROVEN' if success else 'NOT_PROVEN'
            record['B'] = 'PROVEN' if data.get('readinessConfirmed') else 'NOT_PROVEN'
            # The specified C is full SSH configuration semantics. Network
            # checks establish selected fixture expectations, not that full C.
            record['C_selected'] = semantic if success else 'NOT_PROVEN'
            record['C'] = 'FAILED' if success and semantic == 'FAILED' else 'NOT_PROVEN'
            record['persistent'] = ('NOT_PROVEN' if data.get('residual_count_before_admin_cleanup') or data['status'] == 'SIGKILL' else
                                    'PROVEN' if reference_matches(req) else 'FAILED')
            if success and persistent != 'ANY': assert record['persistent'] == persistent, (name, record['persistent'])
            if success:
                assert data['launch_contract_stable'], (name, 'launch contract changed')
                assert before['InvocationID'] != after['InvocationID'] and before['MainPID'] != after['MainPID'], (name, 'old process')
                assert after['ActiveState'] == 'active' and after['SubState'] == 'running'
                if network:
                    record['server_identification'] = handshake(port)
                    record['network_stage'] = 'identification + server SSH_MSG_KEXINIT; no completed KEX/authentication'
                    assert banner in record['server_identification'], (name, record['server_identification'])
                    record['effective_separate_process'] = effective()
                    record['listeners'] = run(['ss', '-lntp']).stdout
            if data['status'] == 'Success': assert not data['cleanupErrors'] and not data['residualPaths']
            result['cases'].append(record)
            (OUT / 'results.json').write_text(json.dumps(result, indent=2))
            return record

        experiment('baseline-public-stock-ssh')
        (STOCK_DROP / '10-copyup.conf').write_text('LogLevel VERBOSE\n')
        result['directory_copyup_preflight'] = drive('preflight', request())
        assert result['copyup_preflight']['status'] == 'SUPPORTED'
        assert result['directory_copyup_preflight']['status'] == 'SUPPORTED'
        experiment('copyup-stock-main-and-nonempty-stock-Include')
        # Complex Includes remain explicit and protected, including negative glob set.
        reset()
        (DROP / '10-nested.conf').write_text(f'Include {DROP}/nested.inc\n')
        (DROP / 'nested.inc').write_text('LogLevel VERBOSE\n')
        (DROP / 'match.inc').write_text('PermitTTY no\n')
        MAIN.write_text(config(extra=f'Match Address 127.0.0.1\n Include {DROP}/match.inc\n'))
        run(['/usr/sbin/sshd', '-t'])
        experiment('nested-and-Match-Include', semantic='NOT_PROVEN')
        reset(); MAIN.write_text(config(extra='VersionAddendum SECOND\n'))
        experiment('duplicate-directive-first-wins')
        reset(); MAIN.write_text(config(extra=f'Include {DROP}/absent*.inc\n'))
        experiment('missing-Include-with-protected-negative-set')
        reset()
        (WORK / 'symlink-target.conf').write_text('LogLevel VERBOSE\n')
        (DROP / '10-symlink.conf').symlink_to(WORK / 'symlink-target.conf')
        experiment('symlink-Include-input', expected=('UnsupportedConfiguration',), network=False)
        for name, change, expected in [
            ('wrong-reference-sha', lambda r: r['paths'][0].update(sha256='0' * 64), ('ChecksumMismatch',)),
            ('missing-required-file', lambda r: MAIN.unlink(), ('ChecksumMismatch',)),
            ('optional-env-absent', lambda r: ENV.unlink(), ('UnsupportedConfiguration',)),
            ('uncovered-env', lambda r: r.update(paths=[p for p in r['paths'] if p['path'] != str(ENV)]), ('UnsupportedConfiguration',)),
            ('symlink-main', lambda r: (MAIN.unlink(), MAIN.symlink_to(WORK / 'mutation.conf')), ('UnsupportedConfiguration',)),
            ('SSHD_OPTS-changed-since-reference', lambda r: ENV.write_text('SSHD_OPTS=-p 2225\n'), ('UnsupportedConfiguration',)),
        ]:
            reset(); req = request(); change(req)
            # Missing source cannot be analyzed by the fixture closure function.
            if not MAIN.exists() or MAIN.is_symlink():
                data = drive('activate', req); assert data['status'] in expected, (name, data)
                result['cases'].append({'name': name, 'activation': data, 'A': 'NOT_PROVEN', 'B': 'NOT_PROVEN', 'C': 'NOT_PROVEN'})
            else: experiment(name, req=req, expected=expected, network=False)
        reset(); MAIN.write_text(config(extra=f'Include {WORK}/external.conf\n'))
        # Existing VersionAddendum wins here; put external Include first to show escape.
        MAIN.write_text(f'Include {WORK}/external.conf\n' + config())
        experiment('uncovered-external-Include', port=2224, banner='EXTERNAL', semantic='FAILED')
        reset(); experiment('unguarded-new-glob', action='new-glob', req=request(False), banner='GLOB', semantic='FAILED')
        reset(); experiment('guarded-new-glob', action='new-glob', persistent='FAILED')
        for name, opts, port, banner in [
            ('CLI-f-external', f'-f {WORK}/external.conf', 2224, 'EXTERNAL'),
            ('CLI-o-first-wins', '-oVersionAddendum=CLI_FIRST -oVersionAddendum=CLI_SECOND', 2222, 'CLI_FIRST'),
            ('systemd-real-quoted-expansion', '-o "VersionAddendum=CLI SPACE" -p 2225 -p 2226', 2225, 'CLI SPACE'),
        ]:
            reset(); ENV.write_text("SSHD_OPTS='" + opts + "'\n")
            rec = experiment(name, port=port, banner=banner, semantic='FAILED')
            if name == 'systemd-real-quoted-expansion': assert 'CLI SPACE' in handshake(2226)
            rec['late_proc_cmdline_is_not_argv_proof'] = True
        reset(); MAIN.write_text('InvalidFicDirective yes\n')
        syntax = run(['/usr/sbin/sshd', '-t'], check=False); assert syntax.returncode != 0
        experiment('sshd-t-and-real-restart-failure', expected=('RestartFailed', 'TimedOut'), network=False)
        reset(); ENV.write_text('SSHD_OPTS=-Z\n')
        experiment('real-sshd-argv-restart-failure', expected=('RestartFailed', 'TimedOut'), network=False)
        for fault, expected in [('contract-before', ('InterferenceDetected',)), ('contract-after', ('InterferenceDetected',)),
                                ('inode', ('InterferenceDetected',)), ('aba', ('InterferenceDetected',)),
                                ('ro-write', ('Success',)), ('original-write', ('Success',)),
                                ('busy', ('CleanupFailed',)), ('foreign', ('CleanupFailed',)), ('crash', ('SIGKILL',))]:
            reset()
            req = request()
            experiment(fault, action=fault, req=req, expected=expected, persistent='FAILED' if fault == 'original-write' else 'ANY')
            if fault in ('busy', 'foreign', 'crash'):
                again = drive('activate', req)
                assert again['status'] == 'ResidualMounts', again
                result['cases'][-1]['repeat_refusal'] = again
                if fault == 'foreign': assert result['cases'][-1]['activation']['foreign_preserved']
                drive('cleanup', req)
                result['cases'][-1]['persistent_after_admin_cleanup'] = 'PROVEN' if reference_matches(req) else 'FAILED'
        reset()
        fifo = WORK / 'blocked.conf'
        os.mkfifo(fifo)
        ENV.write_text(f'SSHD_OPTS=-f {fifo}\n')
        req = request(); req['timeout_ms'] = 5000
        blocked = experiment('new-real-sshd-blocked-before-READY', action='no-ready', req=req,
                             expected=('TimedOut', 'RestartFailed'), network=False)
        assert blocked['activation']['fifo_reader_connected']
        fifo.unlink()
        reset()
        # Independent production adapter gate. References come from this known
        # synthetic fixture only; production never adopts observed files.
        result['adapter_cases'] = []
        def adapter_reset(extra=''):
            for attr in os.listxattr(KEY): os.removexattr(KEY, attr)
            KEY.chmod(0o600)
            os.chown(MAIN, 0, 0)
            DROP.chmod(0o755)
            reset()
            MAIN.write_text(config(extra='MaxAuthTries 3\n' + extra).replace('PubkeyAuthentication no', 'PubkeyAuthentication yes').replace('UsePAM no', 'UsePAM yes'))
        def adapter_case(name, action='adapter', req=None, success=False, drift=False, restarted=None, unknown=False):
            req = req or request()
            before = state(); data = drive(action, req); after = state()
            assert 'adapter_success' in data, (name,data)
            assert data['adapter_success'] == success, (name, data)
            if name in ('disabled-active-no-activation','disabled-inactive-no-activation','enabled-inactive-no-pending-job'):
                assert not data['activation_invoked'], (name,data)
                assert request() == req, (name,'persistent fixture inputs changed during refusal')
            if restarted is not None:
                assert (before['InvocationID'] != after['InvocationID']) == restarted, (name, data)
            if success or drift or unknown:
                assert data['A'] == data['C'] == 'Proven' and data['readinessConfirmed'], (name, data)
                assert data['status'] == 'Success' and not data['cleanupErrors'] and not data['residualPaths'], (name, data)
                assert before['MainPID'] != after['MainPID'] and before['InvocationID'] != after['InvocationID']
                if name.startswith('metadata-') and (drift or unknown):
                    assert data['protected_handshake_confirmed']
                else:
                    assert 'FIC_VERIFIED' in handshake(2222)
                # Link the observed listening socket to the newly promoted PID.
                listeners = run(['ss', '-lntp']).stdout
                assert any('127.0.0.1:2222' in line.split() and f'pid={after["MainPID"]},' in line for line in listeners.splitlines()), (name, listeners)
                data['listener_pid_confirmed'] = True
            if unknown: assert data['P'] == 'NotProven' and data['adapter_status'] == 2
            if name.startswith('metadata-') and drift:
                for target in req['paths']:
                    if target.get('directory'):
                        actual = {str(p.relative_to(target['path'])): sha(p) for p in Path(target['path']).rglob('*') if p.is_file()}
                        assert actual == target['manifest'], (name, 'manifest changed')
                    else:
                        assert sha(target['path']) == target['sha256'], (name, 'bytes changed')
                data['metadata_only_bytes_unchanged'] = True
            if success: assert data['P'] == 'Proven'
            if drift: assert data['P'] == 'NonCompliant' and data['adapter_status'] == 3
            result['adapter_cases'].append({'name': name, 'before': before, 'after': after, 'result': data})
            (OUT / 'results.json').write_text(json.dumps(result, indent=2))
            return data
        adapter_reset()
        run(['systemctl','disable','ssh.service'])
        adapter_case('disabled-active-no-activation',restarted=False)
        run(['systemctl','stop','ssh.service'])
        adapter_case('disabled-inactive-no-activation',restarted=False)
        run(['systemctl','enable','ssh.service'])
        adapter_case('enabled-inactive-no-pending-job',restarted=False)
        run(['systemctl','start','ssh.service'])
        adapter_reset()
        data=adapter_case('pending-native-ready',action='adapter-pending-ready',success=True)
        assert data['admission_wait_observed'],data
        for fault in ('pending-timeout','pending-failed'):
            adapter_reset();data=adapter_case(fault,action='adapter-'+fault)
            assert data['admission_wait_observed'] and not data['activation_invoked'],data
        adapter_reset(); adapter_case('all-five-empty-glob-public', success=True, restarted=True)
        adapter_reset()
        captured=drive('capture-reference',request())
        assert captured['reference_capture_succeeded'], captured

        service_bad=json.loads(json.dumps(captured['reference']))
        service_bad['expected_service']['MainPID']='0'
        adapter_case('stale-caller-service-proof',req=service_bad,restarted=False)
        metadata_bad=json.loads(json.dumps(captured['reference']))
        metadata_bad['observed_metadata'][str(MAIN)]='0'*64
        adapter_case('stale-caller-metadata-proof',req=metadata_bad,restarted=False)
        adapter_case('production-reference-builder',req=captured['reference'],success=True,restarted=True)
        bad=request()
        for p in bad['paths']:
            if p['path']==str(MAIN): p['sha256']='0'*64
        assert not drive('capture-reference',bad)['reference_capture_succeeded']
        adapter_reset('Include /opt/evil/*.conf\n')
        assert not drive('capture-reference',request())['reference_capture_succeeded']
        adapter_reset()
        adapter_case('repeat-same-reference', success=True, restarted=True)
        adapter_reset('Match User backup\n X11Forwarding no\n')
        adapter_case('unrelated-Match', success=True, restarted=True)
        adapter_reset()
        run(['ssh-keygen','-A'])
        MAIN.write_text(MAIN.read_text().replace(f'HostKey {KEY}\n',''))
        implicit = request()
        for kind in ('rsa','ecdsa','ed25519'):
            for suffix in ('','.pub'):
                key = Path('/etc/ssh/ssh_host_'+kind+'_key'+suffix)
                if not any(p['path']==str(key) for p in implicit['paths']):
                    implicit['paths'].append({'path':str(key),'sha256':sha(key)})
        adapter_case('implicit-Debian-HostKeys', req=implicit, success=True, restarted=True)
        adapter_reset()
        safe_dir=Path('/etc/systemd/system/ssh.service.d')
        safe_dir.mkdir(exist_ok=True)
        safe_file=safe_dir/'fic-compatible.conf'
        safe_file.write_text('[Unit]\nDescription=Compatible SSH test\n[Service]\nCPUWeight=100\n')
        run(['systemctl','daemon-reload'])
        adapter_case('compatible-administrative-drop-in',success=True,restarted=True)
        safe_file.unlink()
        run(['systemctl','daemon-reload'])
        adapter_reset(); (DROP / '10-nested.conf').write_text(f'Include {DROP}/nested.inc\n')
        (DROP / 'nested.inc').write_text('MaxAuthTries 3\nPermitRootLogin no\n')
        adapter_case('nested-literal-Include', success=True, restarted=True)
        adapter_reset('PermitRootLogin yes\n'); adapter_case('scalar-first-wins', success=True, restarted=True)
        for name, opts in [('CLI-f-external', f'-f {WORK}/external.conf'), ('CLI-o-first-wins','-oUsePAM=yes'), ('systemd-real-quoted-expansion','-o "VersionAddendum=CLI SPACE" -p 2225')]:
            adapter_reset(); ENV.write_text("SSHD_OPTS='" + opts + "'\n")
            adapter_case(name, restarted=False)
        for name, extra in [('uncovered-external-Include',f'Include {WORK}/external.conf\n'),
                            ('unsupported-Match','Match all\n PermitRootLogin yes\n'),
                            ('multiple-Port','Port 2223\n'), ('ListenAddress-other-port','ListenAddress 127.0.0.1:2223\n'),
                            ('unsupported-syntax','UnknownFicDirective yes\n')]:
            adapter_reset(extra); refused=adapter_case(name, restarted=False)
            if name=='multiple-Port':
                assert refused['C']=='NonCompliant' and refused['adapter_diagnostic'].startswith('NonCompliant:'),refused
        adapter_reset('PermitRootLogin invalid-value\n')
        unknown=adapter_case('native-syntax-proof-unknown',restarted=False)
        assert unknown['C']=='NotProven' and unknown['adapter_diagnostic'].startswith('Unknown:'),unknown
        adapter_reset(); adapter_case('unguarded-new-glob', req=request(False), restarted=False)
        adapter_reset(); adapter_case('guarded-new-glob', action='adapter-new-glob', drift=True, restarted=True)
        adapter_reset(); adapter_case('original-write', action='adapter-original-write', drift=True, restarted=True)
        for fault, restart in [('contract-before',False), ('contract-after',True), ('contract-preflight',False), ('source-before',False), ('source-inode-before',False), ('source-mode-before',False), ('glob-before',False), ('directory-before',False)]:
            adapter_reset(); raced = adapter_case(fault, action='adapter-'+fault, restarted=restart)
            assert raced['activation_invoked'] and raced['status'] in ('InterferenceDetected', 'ChecksumMismatch'), (fault, raced)
        for fault in ('ready-stop','ready-disable','ready-foreign-restart','final-disable','final-restart'):
            adapter_reset()
            data=adapter_case(fault,action='adapter-'+fault)
            assert not data['adapter_success'] and data['readinessConfirmed'],data
            assert data['A']==data['C']=='Proven' and data['P']=='Proven',data
            run(['systemctl','stop','ssh.service'],check=False)
            run(['systemctl','enable','ssh.service'])
        adapter_reset(); data = adapter_case('cleanup-EBUSY', action='adapter-busy', restarted=True)
        assert data['status'] == 'CleanupFailed' and data['primaryStatus'] == 'Success'
        drive('cleanup', request())
        adapter_reset(); bad = request(); bad['paths'][0]['sha256'] = '0'*64
        adapter_case('wrong-trusted-reference', req=bad, restarted=False)
        adapter_reset(); bad = request(); bad['policies'] = {'unknown': 'yes'}
        adapter_case('unknown-policy', req=bad, restarted=False)
        adapter_reset(); missing_env = request(); ENV.unlink(); adapter_case('missing-optional-env', req=missing_env, restarted=False)
        adapter_reset(); untrusted = request(); untrusted['untrusted_sshd'] = True
        adapter_case('untrusted-sshd', req=untrusted, restarted=False)
        adapter_reset(); ENV.write_text(' # verified empty options\n\tSSHD_OPTS=  \n')
        adapter_case('empty-options-whitespace-comments', success=True, restarted=True)
        adapter_reset(); (DROP / '10-link.conf').symlink_to(WORK / 'external.conf')
        adapter_case('symlink-Include', restarted=False)
        for fault in ('key-mode', 'config-mode', 'config-uid', 'config-gid', 'directory-mode', 'included-inode'):
            adapter_reset()
            if fault == 'included-inode': (DROP / '10-inode.conf').write_text('# identical inode fixture\n')
            adapter_case('metadata-' + fault, action='adapter-' + fault, drift=True, restarted=True)
        adapter_reset(); KEY.chmod(0o644)
        denied = adapter_case('metadata-initial-key-0644', restarted=False)
        assert not denied['activation_invoked']
        adapter_reset(); os.setxattr(KEY, 'user.fic-test', b'x')
        denied = adapter_case('metadata-initial-key-xattr', restarted=False)
        assert not denied['activation_invoked']
        adapter_reset()
        acl = struct.pack('<I', 2) + b''.join(struct.pack('<HHI', *e) for e in
            [(1,6,0xffffffff), (2,4,123), (4,0,0xffffffff), (16,0,0xffffffff), (32,0,0xffffffff)])
        os.setxattr(KEY, 'system.posix_acl_access', acl)
        assert stat.S_IMODE(KEY.stat().st_mode) == 0o600
        denied = adapter_case('metadata-initial-key-ACL', restarted=False)
        assert not denied['activation_invoked']
        adapter_reset(); adapter_case('metadata-unreadable-key-xattr', action='adapter-key-xattr', unknown=True, restarted=True)
        adapter_reset(); KEY.chmod(0o400)
        adapter_case('metadata-key-0400-public-0644', success=True, restarted=True)
        adapter_reset()
        # This section calls the real Ssh::apply, journal and policy classes,
        # without daemon startup or synthetic M1 lifecycle state.
        result['module_cases'] = []
        def module_reset():
            adapter_reset()
            MAIN.write_text(config())
            shutil.rmtree(WORK / 'module-state', ignore_errors=True)
        def module_case(name, operations):
            req=request(); req['operations']=operations
            data=drive('module',req)
            result['module_cases'].append({'name':name,'result':data})
            (OUT / 'results.json').write_text(json.dumps(result,indent=2))
            return data['module']
        selected=[{'policy':p,'value':v} for p,v in (
            ('ssh_root_login','no'),('ssh_use_pam','yes'),('ssh_pubkey_auth','yes'),
            ('ssh_max_auth_tries','3'),('ssh_port','2244'))]
        module_reset()
        rows=module_case('real-policy-apply-and-receipt',selected*3)
        assert all(row['applied'] for row in rows), rows
        assert rows[0]['main_unchanged'] and not rows[0]['records'], rows[0]
        assert rows[0]['before_invocation']!=rows[0]['after_invocation'], rows[0]
        assert all(row['before_invocation']==row['after_invocation'] for row in rows[-5:]), rows
        assert all(row['main_unchanged'] for row in rows[-5:]), rows
        assert 'FIC_VERIFIED' in handshake(2244)
        listeners=run(['ss','-lntp']).stdout
        assert any('127.0.0.1:2244' in line and f'pid={rows[-1]["after_pid"]},' in line for line in listeners.splitlines()), listeners
        assert len(rows[-1]['records'])==4, rows[-1]
        for change in ('restart','main-comment'):
            module_reset()
            rows=module_case('receipt-invalidated-'+change,[
                {'policy':'ssh_root_login','value':'no'},
                {'policy':'ssh_root_login','value':'no'},
                {'policy':'ssh_root_login','value':'no','before':change},
                {'policy':'ssh_root_login','value':'no'}])
            assert all(row['applied'] for row in rows),rows
            assert rows[1]['before_invocation']==rows[1]['after_invocation'],rows
            assert rows[2]['before_invocation']!=rows[2]['after_invocation'],rows
            assert rows[3]['before_invocation']==rows[3]['after_invocation'],rows
        for name, mutate in (
            ('disabled-active',lambda:run(['systemctl','disable','ssh.service'])),
            ('enabled-inactive',lambda:run(['systemctl','stop','ssh.service'])),
            ('external-empty-Include',lambda:MAIN.write_text(config(extra='Include /opt/evil/*.conf\n'))),
            ('conditional-policy',lambda:MAIN.write_text(config(extra='Match User root\n PermitRootLogin yes\n'))),
            ('orphan-markers',lambda:MAIN.write_text('#@FIC_SSH_BLOCK_BEGIN version=1@\n#@FIC_POLICY_BEGIN name=ssh_root_login@\nPermitRootLogin no\n#@FIC_POLICY_END name=ssh_root_login@\n#@FIC_SSH_BLOCK_END@\n'+config()))):
            module_reset(); mutate()
            row=module_case(name,[{'policy':'ssh_root_login','value':'no'}])[0]
            assert not row['applied'] and row['main_unchanged'] and row['journal_unchanged'] and not row['records'], row
            assert row['before_invocation']==row['after_invocation'],row
            run(['systemctl','stop','ssh.service'],check=False)
            run(['systemctl','enable','ssh.service'])
        module_reset()
        (DROP / '10-foreign-port.conf').write_text('Port 2223\n')
        row=module_case('foreign-included-Port',[{'policy':'ssh_port','value':'2244'}])[0]
        assert not row['applied'] and row['main_unchanged'] and row['journal_unchanged'],row
        assert row['before_invocation']==row['after_invocation'],row
        for fault in ('disable','foreign-input','main-cas'):
            module_reset()
            row=module_case('pre-CAS-'+fault,[{'policy':'ssh_use_pam','value':'yes','fault':fault}])[0]
            assert not row['applied'] and not row['records'],row
            assert row['before_invocation']==row['after_invocation'],row
            if fault!='main-cas': assert row['main_unchanged'],row
            run(['systemctl','stop','ssh.service'],check=False)
            run(['systemctl','enable','ssh.service'])
        for fault in ('after-save-stop','after-save-disable','after-save-input','after-save-main','durability','unknown-writer'):
            module_reset()
            rows=module_case(fault,[{'policy':'ssh_use_pam','value':'yes','fault':fault},
                                   {'policy':'ssh_root_login','value':'no'}])
            assert not rows[0]['applied'] and not rows[0]['main_unchanged'] and len(rows[0]['records'])==1,rows
            assert not rows[1]['applied'] and rows[1]['main_unchanged'] and rows[1]['records']==rows[0]['records'],rows
            # No restore of historical bytes after saved/uncertain effect.
            assert 'UsePAM yes' in MAIN.read_text(),fault
            if fault=='after-save-main': assert '# foreign saved edit' in MAIN.read_text()
            run(['systemctl','stop','ssh.service'],check=False)
            run(['systemctl','enable','ssh.service'])
        module_reset()
        rows=module_case('journal-commit-failure',[
            {'policy':'ssh_use_pam','value':'yes','fault':'journal-commit'},
            {'policy':'ssh_root_login','value':'no'}])
        assert not rows[0]['applied'] and not rows[0]['main_unchanged'] and rows[0]['journal_unusable'],rows
        assert rows[0]['before_invocation']!=rows[0]['after_invocation'],rows
        assert not rows[1]['applied'] and rows[1]['main_unchanged'] and rows[1]['journal_unusable'],rows
        assert rows[0]['journal_sha']==rows[1]['journal_sha'],rows
        assert rows[1]['before_invocation']==rows[1]['after_invocation'],rows
        launch_override=Path('/etc/systemd/system/ssh.service.d/95-fic-negative.conf')
        for name,content in (
            ('ExecStart-f','[Service]\nExecStart=\nExecStart=/usr/sbin/sshd -D -f /run/foreign.conf\n'),
            ('ExecStart-o','[Service]\nExecStart=\nExecStart=/usr/sbin/sshd -D -oUsePAM=no\n'),
            ('ExecStartPre','[Service]\nExecStartPre=/usr/bin/true\n'),
            ('EnvironmentFile','[Service]\nEnvironmentFile=/run/foreign-env\n'),
            ('PrivateMounts','[Service]\nPrivateMounts=yes\n')):
            module_reset()
            launch_override.parent.mkdir(exist_ok=True)
            launch_override.write_text(content)
            run(['systemctl','daemon-reload'])
            try:
                row=module_case('unsupported-launch-'+name,[{'policy':'ssh_root_login','value':'no'}])[0]
                assert not row['applied'] and row['main_unchanged'] and row['journal_unchanged'],row
                assert row['before_invocation']==row['after_invocation'],row
            finally:
                launch_override.unlink()
                run(['systemctl','daemon-reload'])
        module_reset()
        result['final_mounts'] = drive('cleanup', request())
        result['unit_bytes_unchanged'] = all(sha(p) == h for p, h in original_units.items())
        assert result['unit_bytes_unchanged']
        result['limitations'] = ['VM/kernel matrix NOT_TESTED', 'general SSH semantic closure NOT_PROVEN',
                                 'Match at authenticated connection NOT_TESTED', 'shared-root provisioning BLOCKED_BY_MOUNT_TOPOLOGY',
                                 'A/B for caller-declared inputs do not imply C', 'late /proc cmdline not initial argv evidence']
    finally:
        (OUT / 'module-service-journal.log').write_text(run(['journalctl','-u','ssh.service','-n','100','--no-pager'],check=False).stdout)
        run(['systemctl', 'stop', 'ssh.service'], check=False)
        run(['systemctl', 'unset-environment', 'FIC_OPENSSH_TEST_CHANGE'], check=False)
        drive('cleanup', {'paths': []})
        if DROP != STOCK_DROP and DROP.exists(): shutil.rmtree(DROP)
        for i, path in enumerate(originals):
            if path.is_symlink() or path.is_file(): path.unlink()
            elif path.is_dir(): shutil.rmtree(path)
            if existed[str(path)]:
                if (backup / str(i)).is_dir(): shutil.copytree(backup / str(i), path, symlinks=True)
                else: shutil.copy2(backup / str(i), path, follow_symlinks=False)
        Path('/run/sshd').mkdir(exist_ok=True)
        result['restored_sshd_t'] = run(['/usr/sbin/sshd', '-t'], check=False).returncode == 0
        (OUT / 'results.json').write_text(json.dumps(result, indent=2))
    print(json.dumps({'cases': len(result['cases']), 'unit_bytes_unchanged': result['unit_bytes_unchanged'],
                      'restored_sshd_t': result['restored_sshd_t']}))


def self_test():
    # No subprocess, root, system mutation or Docker required for CTest.
    import ast
    for name in ("release_cases.py", "release_plan_cases.py", "remote_package_cases.py"):
        path=Path(__file__).with_name(name)
        ast.parse(path.read_text(),filename=str(path))
    assert not covered('/etc/ssh-extra.conf', [{'path': '/etc/ssh', 'directory': True}])
    assert covered('/etc/ssh/sshd_config.d/new.conf', [{'path': '/etc/ssh/sshd_config.d', 'directory': True}])
    assert not covered('/etc/ssh/sshd_config.d', [{'path': '/etc/ssh/sshd_config.d'}], directory=True)
    assert covered('/etc/default/ssh', [{'path': '/etc/default/ssh'}])
    assert config().startswith('Include /etc/ssh/sshd_config.d/*.conf\n')
    # Public boundary must refuse absent explicit runner opt-in before any writes.
    saved = os.environ.pop('FIC_OPENSSH_DISPOSABLE', None)
    try:
        try: guard()
        except AssertionError: pass
        else: raise AssertionError('unsafe host entry accepted')
    finally:
        if saved is not None: os.environ['FIC_OPENSSH_DISPOSABLE'] = saved
    print('OpenSSH harness guard/coverage self-test PASS')


if __name__ == '__main__':
    if sys.argv[1:] == ['--self-test']: self_test()
    elif not sys.argv[1:]: main()
    else: raise SystemExit('unsupported arguments')
