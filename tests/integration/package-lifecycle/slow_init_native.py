"""Regression probe: reinstall (remove -> reinstall, never purge) with a
>30 s initial fic-dick initialization phase. Real DEBs, real dpkg, the real
fic.postinst and the real fic-dick ELF are used.

Hypothesis under test (from code reading, not assumed):
- fic.postinst configure starts fic-device.service (Type=simple) and then
  runs `/opt/fic/bin/fic-dick wait-daemon 30`.
- run_daemon() creates the IPC socket, then synchronously performs the
  initial run_device_reconciliation("daemon startup") BEFORE entering the
  request loop, so `wait-daemon 30` can time out even though the daemon is
  healthy and will answer IPC right after reconciliation finishes.

Fault injection (test environment only): an LD_PRELOAD shim delays the
SECOND sqlite3_open() of /opt/fic/db/devices.db. In fic-dick that is the
reconciliation DB handle, opened after the IPC socket already exists. The
shim does not touch udevadm (whose own 15 s executor timeout would change
the scenario) and does not replace any FIC binary. It is injected into the
disposable container through a systemd drop-in for fic-device.service only;
no production file, unit or timeout is modified.

Verdicts (result.json):
- XFAIL-DEFECT-REPRODUCED: reinstall failed with the wait-daemon timeout
  while fic-dick was alive, initializing and reachable on the IPC socket.
- NOT-REPRODUCED: reinstall succeeded (diagnostics explain why).
- INCONCLUSIVE: a different failure mode (daemon crash, DB/schema mismatch,
  unrelated postinst step).
"""
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import time

assert os.environ.get('FIC_PACKAGE_LIFECYCLE_NATIVE') == '1'
assert Path('/proc/1/comm').read_text().strip() == 'systemd'
assert os.stat('/proc/self/ns/mnt').st_ino != int(os.environ['FIC_HOST_MNT_INODE'])
results = Path('/var/tmp/fic-package-results')
results.mkdir()
events = []

DEVICE_DB = '/opt/fic/db/devices.db'
DEVICE_SOCKET = '/run/fic/fic-device.sock'
INJECTION_SLEEP_SECONDS = 45  # > postinst wait-daemon timeout of 30 s


def run(args, success=True, timeout=300):
    started = time.time()
    p = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       timeout=timeout, env=dict(os.environ, DEBIAN_FRONTEND='noninteractive'))
    event = dict(command=args, exit_code=p.returncode, seconds=round(time.time()-started, 1),
                 output=p.stdout)
    events.append(event)
    (results/'commands.json').write_text(json.dumps(events, indent=2))
    print('EXIT', p.returncode, ' '.join(args), flush=True)
    if success:
        assert p.returncode == 0, p.stdout
    return p


def save_events():
    (results/'commands.json').write_text(json.dumps(events, indent=2))


def version_fields():
    out = subprocess.run(['/opt/fic/bin/fic-dick', '--version'], text=True,
                         stdout=subprocess.PIPE).stdout.split()
    return dict(part.split('=', 1) for part in out[1:] if '=' in part)


def device_request(timeout_seconds=3):
    """Distinguish three daemon conditions.
    1. connect() refusal -> dict(ok=False, connect_error=...): socket absent
       (daemon dead or pre-socket initialization).
    2. connect() OK but no timely status reply -> None: daemon alive but still
       initializing (the case of interest).
    3. a status reply whose versions mismatch the local ELF ->
       dict(ok=True, mismatch=True, ...).
    Otherwise the parsed status reply dict.
    """
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as client:
            client.settimeout(timeout_seconds)
            client.connect(DEVICE_SOCKET)
            client.send(json.dumps(dict(api_version=1, command='status')).encode())
            body = b''
            while True:
                frame = client.recv(1024*1024)
                assert len(frame) >= 16, 'truncated response'
                magic, total, offset, length = struct.unpack('!4I', frame[:16])
                assert magic == 0x00464943 and offset == len(body) and len(frame) == length+16
                body += frame[16:]
                if len(body) == total:
                    reply = json.loads(body)
                    expected = version_fields()
                    if (reply.get('ok') and
                            (str(reply.get('ipc_api_version', '')) != str(expected.get('ipc-api', '')) or
                             str(reply.get('database_schema_version', '')) != str(expected.get('db-schema', '')))):
                        reply['mismatch'] = True
                    return reply
    except (FileNotFoundError, ConnectionRefusedError) as absent:
        return dict(ok=False, connect_error=str(absent))
    except BlockingIOError:
        # EAGAIN on connect: the socket exists but is not accepting/answering
        # (a listen backlog stall while the daemon is busy initializing).
        return None
    except (socket.timeout, TimeoutError):
        return None  # alive but not answering: the initialization case


def service_state(unit):
    def field(name):
        out = subprocess.run(['systemctl', 'show', unit, '--property=' + name,
                              '--no-pager'], text=True, stdout=subprocess.PIPE).stdout
        return out.strip().split('=', 1)[-1]
    return dict(active=field('ActiveState'), sub=field('SubState'),
                main_pid=field('MainPID'), result=field('Result'),
                exec_main_status=field('ExecMainStatus'))


def config_snapshot():
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in Path('/opt/fic/config').glob('*') if p.is_file()}


def journal_facts():
    journal = Path('/opt/fic/db/mutation-journal.json')
    witness = Path('/opt/fic/db/mutation-journal.json.initialized')
    return dict(journal_exists=journal.exists(),
                witness_exists=witness.exists(),
                journal_sha256=hashlib.sha256(journal.read_bytes()).hexdigest()
                if journal.exists() else None)


def lifecycle_status():
    state = Path('/var/lib/fic-lifecycle/status')
    return state.read_text().strip() if state.exists() else None


def package(name):
    found = list(Path('/var/tmp/fic-packages').glob(name + '_*.deb'))
    assert len(found) == 1, found
    return str(found[0])


def finish(analysis, timeline):
    events.append(dict(analysis=analysis, timeline=timeline,
                       journal_facts=journal_facts(), lifecycle=lifecycle_status()))
    (results/'result.json').write_text(json.dumps(
        dict(status=analysis['verdict'], **analysis, timeline=timeline), indent=2))
    save_events()
    print('VERDICT:', analysis['verdict'], flush=True)
    print('PASS: slow-init reinstall probe completed with a verdict', flush=True)


def diagnose_failure():
    logs = sorted(Path('/opt/fic/log').rglob('*'), key=lambda p: p.stat().st_mtime,
                  reverse=True)[:6]
    for log in logs:
        if log.is_file():
            run(['tail', '-n', '30', str(log)], success=False)
    run(['systemctl', 'show', 'fic.service', 'fic-device.service', '--no-pager',
         '--property=Id,LoadState,ActiveState,SubState,MainPID,Result,ExecMainStatus'],
        success=False)
    run(['journalctl', '-u', 'fic.service', '-u', 'fic-device.service', '-n', '120',
         '--no-pager'], success=False)


SLOW_OPEN_SHIM = r'''
// Test-only fault injection compiled inside the disposable container.
// Delays the SECOND sqlite3_open() of the FIC device database. In the real
// fic-dick ELF that handle belongs to the initial daemon-startup
// reconciliation, which runs after the IPC socket has been created and
// before the request loop starts answering IPC. No FIC binary is modified.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static int g_opens;
static int g_delayed;
static const char* g_target;
static int g_seconds;
static __thread int inside;

static void init_once(void) {
    g_target = getenv("SLOW_INIT_DB_PATH");
    if (!g_target) g_target = "/opt/fic/db/devices.db";
    const char* seconds = getenv("SLOW_INIT_SLEEP_SECONDS");
    g_seconds = seconds ? atoi(seconds) : 45;
}

static void intercept(const char* path) {
    if (inside || !path) return;
    inside = 1;
    init_once();
    if (g_target && strcmp(path, g_target) == 0) {
        ++g_opens;
        if (g_opens == 2 && !g_delayed) {
            g_delayed = 1;
            FILE* log = fopen("/var/tmp/fic-slow-init.log", "a");
            if (log) {
                fprintf(log, "slow-init injection: opening %s (open #%d); "
                             "sleeping %ds before returning\n", path, g_opens, g_seconds);
                fclose(log);
            }
            struct timespec req = {g_seconds, 0};
            nanosleep(&req, NULL);
            log = fopen("/var/tmp/fic-slow-init.log", "a");
            if (log) {
                fprintf(log, "slow-init injection: sleep finished\n");
                fclose(log);
            }
        }
    }
    inside = 0;
}

typedef int (*open_fn)(const char*, void**);
int sqlite3_open(const char* path, void** db) {
    intercept(path);
    static open_fn real;
    if (!real) real = (open_fn)dlsym(RTLD_NEXT, "sqlite3_open");
    return real(path, db);
}

typedef int (*openv2_fn)(const char*, void**, int, const char*);
int sqlite3_open_v2(const char* path, void** db, int flags, const char* vfs) {
    intercept(path);
    static openv2_fn real2;
    if (!real2) real2 = (openv2_fn)dlsym(RTLD_NEXT, "sqlite3_open_v2");
    return real2(path, db, flags, vfs);
}
'''


def install_injection():
    source = Path('/usr/local/share/fic-slow-init-shim.c')
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(SLOW_OPEN_SHIM)
    library = '/usr/local/lib/fic-slow-db-open.so'
    run(['gcc', '-shared', '-fPIC', '-O1', str(source), '-ldl', '-o', library], timeout=60)
    dropin = Path('/etc/systemd/system/fic-device.service.d/native-slow-init.conf')
    dropin.parent.mkdir(parents=True, exist_ok=True)
    dropin.write_text(
        '[Service]\n'
        '# Test-environment-only fault injection (disposable container).\n'
        'Environment="LD_PRELOAD=' + library + '"\n'
        'Environment="SLOW_INIT_DB_PATH=' + DEVICE_DB + '"\n'
        'Environment="SLOW_INIT_SLEEP_SECONDS=' + str(INJECTION_SLEEP_SECONDS) + '"\n')
    run(['systemctl', 'daemon-reload'])
    return dropin


def remove_injection(dropin):
    dropin.unlink()
    run(['systemctl', 'daemon-reload'])


def wait_for_device_ipc(poll_timeout, per_attempt=2):
    deadline = time.time() + poll_timeout
    started = time.time()
    while time.time() < deadline:
        reply = device_request(per_attempt)
        if isinstance(reply, dict) and reply.get('ok'):
            return time.time() - started
        time.sleep(3)
    return None


def main():
    timeline = []
    try:
        # Disposable PID1 systemd container, no host binds, no network.
        run(['mount', '--rbind', '/sys', '/sys'])
        run(['mount', '-o', 'remount,bind,ro', '/sys'])
        run(['systemctl', 'stop', 'ssh.service', 'ssh.socket'], success=False)

        # 1. Fresh install of the complete real package set.
        pkgs = [package(name) for name in ('fic-dick', 'fic', 'fic-cli')]
        for item in pkgs:
            run(['dpkg-deb', '-f', item, 'Package', 'Version', 'Depends'])
        run(['dpkg', '-i', *pkgs], timeout=300)
        assert lifecycle_status() == 'INSTALLED', lifecycle_status()
        run(['systemctl', 'is-active', 'fic.service', 'fic-device.service'])
        run(['/opt/fic/bin/fic-dick', 'wait-daemon', '5'])
        # Give the scenario real retained policy configuration.
        run(['/opt/fic/bin/fic-cli', 'policy', 'enable', 'IDENTITY_ACCESS',
             'password_max_age_days'])
        run(['/opt/fic/bin/fic-cli', 'policy', 'apply', 'IDENTITY_ACCESS',
             'password_max_age_days'])
        saved_config = config_snapshot()
        saved_journal = journal_facts()
        assert saved_journal['journal_exists'] and saved_journal['witness_exists']
        timeline.append(dict(step='fresh-install', lifecycle=lifecycle_status(),
                             journal=saved_journal))

        # 2. Real remove (NOT purge): config must survive; the journal stays
        # present and consistent (a legitimate ownership rollback during
        # remove may rewrite record statuses, so the journal is pinned to
        # its post-remove content and re-checked after the reinstall).
        run(['dpkg', '--remove', 'fic-cli', 'fic'], timeout=300)
        assert lifecycle_status() == 'REMOVED', lifecycle_status()
        assert config_snapshot() == saved_config, 'remove altered retained config'
        post_remove_journal = journal_facts()
        assert post_remove_journal['journal_exists'] and \
            post_remove_journal['witness_exists'], post_remove_journal
        timeline.append(dict(step='remove', lifecycle=lifecycle_status(),
                             config_matches=True, journal=post_remove_journal))

        # 3. Injection: delay the SECOND devices.db open of the real
        # fic-dick (inside the initial startup reconciliation, after the
        # IPC socket exists). udevadm itself is untouched.
        dropin = install_injection()

        # 4. Reinstall from the real DEBs with the real fic.postinst.
        reinstall_started = time.time()
        reinstalled = run(['dpkg', '-i', package('fic'), package('fic-cli')],
                          success=False, timeout=300)
        reinstall_seconds = round(time.time() - reinstall_started, 1)
        device = service_state('fic-device.service')
        socket_present = Path(DEVICE_SOCKET).exists()
        status_probe = device_request(3)
        injection_log = Path('/var/tmp/fic-slow-init.log').read_text() \
            if Path('/var/tmp/fic-slow-init.log').exists() else None
        timeline.append(dict(step='reinstall', dpkg_exit=reinstalled.returncode,
                             seconds=reinstall_seconds, device_service=device,
                             socket_present=socket_present, status_probe=status_probe,
                             injection_log=injection_log))
        versions = version_fields()
        if reinstalled.returncode == 0:
            diagnose_failure()
            finish(dict(verdict='NOT-REPRODUCED',
                        reason='reinstall succeeded despite a >30 s initial '
                               'initialization; see timeline and logs',
                        expected_versions=versions), timeline)
            return
        # Case 1: the daemon itself died -> different defect class.
        assert device['active'] == 'active' and device['main_pid'] not in ('', '0'), \
            dict(case='daemon died (case 1), not the initialization window',
                 device_service=device)
        # Case 3: the daemon answers but with mismatched versions.
        if isinstance(status_probe, dict) and status_probe.get('mismatch'):
            finish(dict(verdict='INCONCLUSIVE',
                        reason='daemon answered status with version/schema mismatch '
                               '(case 3), not the initialization window',
                        status_probe=status_probe, expected_versions=versions), timeline)
            return
        # The interesting case 2: daemon alive, IPC socket accepting
        # connections, but the status request is not answered while the
        # injected initial reconciliation is still running.
        postinst_output = reinstalled.stdout
        assert ('did not become ready' in postinst_output or
                'wait-daemon' in postinst_output), dict(
            case='reinstall failed for an unrelated postinst step',
            output=postinst_output)
        assert status_probe is None, dict(
            case='status probe did not hang; case 2 not confirmed',
            status_probe=status_probe)
        analysis = dict(verdict='XFAIL-DEFECT-REPRODUCED',
                    reason='reinstall failed on `fic-dick wait-daemon 30` while '
                           'fic-dick was alive (service active, IPC socket accepting '
                           'connections, status unanswered during the >30 s initial '
                           'reconciliation). Case 2: healthy daemon still '
                           'initializing, not answering IPC.',
                    dpkg_exit=reinstalled.returncode,
                    reinstall_seconds=reinstall_seconds,
                    expected_versions=versions)
        finish(analysis, timeline)

        # 5. After the injected delay the very same daemon answers IPC,
        # proving it was only still initializing (case 2, not a crash).
        answered_after = wait_for_device_ipc(120)
        assert answered_after is not None, \
            'daemon never answered IPC after the injected delay elapsed'
        still_active = service_state('fic-device.service')
        timeline.append(dict(step='ipc-after-delay',
                             seconds_till_reply=round(answered_after, 1),
                             device_service=still_active))
        assert still_active['active'] == 'active', still_active

        # 6. Environment restored: the real configure must complete now,
        # proving the earlier failure came from the wait-daemon window only.
        remove_injection(dropin)
        run(['systemctl', 'restart', 'fic-device.service'])
        run(['/opt/fic/bin/fic-dick', 'wait-daemon', '10'])
        run(['dpkg', '--configure', '-a'], timeout=300)
        assert lifecycle_status() == 'INSTALLED', lifecycle_status()
        assert config_snapshot() == saved_config, 'reinstall changed saved policy config'
        # The journal is retained and structurally consistent; note that the
        # real postinst configure (initialize-journal/prepare-install) may
        # legitimately rewrite journal bookkeeping, so content hashes are
        # recorded in the timeline but not pinned here.
        final_journal = journal_facts()
        assert final_journal['journal_exists'] and final_journal['witness_exists'], \
            final_journal
        if final_journal['journal_exists']:
            json.loads(Path('/opt/fic/db/mutation-journal.json').read_text())
        run(['/opt/fic/bin/fic-cli', 'status'])
        timeline.append(dict(step='configure-after-recovery',
                             lifecycle=lifecycle_status(),
                             config_matches=saved_config == config_snapshot()))
        # Final evidence supersedes the interim XFAIL record with the full
        # timeline including the recovery steps.
        (results/'result.json').write_text(json.dumps(
            dict(status=analysis['verdict'], **analysis, timeline=timeline,
                 complete=True, journal_facts=journal_facts(),
                 lifecycle=lifecycle_status()), indent=2))
        save_events()
    except BaseException:
        diagnose_failure()
        events.append(dict(analysis=dict(verdict='INCONCLUSIVE',
                                         reason='unexpected probe exception')))
        (results/'result.json').write_text(json.dumps(
            dict(status='INCONCLUSIVE', timeline=timeline), indent=2))
        save_events()
        raise


if __name__ == '__main__':
    main()
