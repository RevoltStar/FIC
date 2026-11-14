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
- XFAIL-DEFECT-REPRODUCED (exit 0): published ONLY after every mandatory
  check: the injection provably activated in the startup-reconciliation
  phase (after the IPC socket existed), postinst failed on the wait-daemon
  timeout, the daemon stayed alive with the SAME PID, IPC recovered after
  the injected delay, and `dpkg --configure -a` completed successfully.
- NOT-REPRODUCED (exit 0): reinstall succeeded while the injection provably
  activated; diagnostics explain why the timeout window was not hit.
- INCONCLUSIVE (exit != 0): injection did not activate or fired in the
  wrong phase, the daemon crashed/restarted, a version/schema mismatch was
  answered, the recovery configure failed, or an unexpected probe error.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import struct
import subprocess
import sys
import time

results = Path('/var/tmp/fic-package-results')
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


def parse_version_tokens(output):
    """Parse `fic-dick --version` output:
    'fic-dick <product_version> ipc-api=<N> db-schema=<M>'."""
    tokens = output.split()
    fields = dict(part.split('=', 1) for part in tokens[2:] if '=' in part)
    fields['product_version'] = tokens[1] if len(tokens) > 1 else ''
    return fields


def version_fields():
    return parse_version_tokens(subprocess.run(
        ['/opt/fic/bin/fic-dick', '--version'], text=True,
        stdout=subprocess.PIPE).stdout)


def classify_status_reply(reply, expected):
    """Mirror the production wait_for_daemon() readiness contract exactly:
    `ok` plus `product_version` and `database_schema_version` equal to the
    values the local fic-dick ELF reports via --version. The status reply
    carries no ipc_api_version field, so it is never compared.
    """
    if reply.get('ok') and (
            reply.get('product_version') != expected.get('product_version') or
            str(reply.get('database_schema_version')) !=
            str(expected.get('db-schema'))):
        reply['mismatch'] = True
    return reply


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
                    reply = classify_status_reply(json.loads(body), version_fields())
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


def write_result(analysis, timeline, complete):
    events.append(dict(analysis=analysis, timeline=timeline,
                       journal_facts=journal_facts(), lifecycle=lifecycle_status()))
    (results/'result.json').write_text(json.dumps(
        dict(status=analysis['verdict'], **analysis, timeline=timeline,
             complete=complete, journal_facts=journal_facts(),
             lifecycle=lifecycle_status()), indent=2))
    save_events()
    print('VERDICT:', analysis['verdict'], flush=True)


def inconclusive(reason, timeline, extra=None):
    """Publish an INCONCLUSIVE verdict and fail the gate (exit != 0)."""
    diagnose_failure()
    analysis = dict(verdict='INCONCLUSIVE', reason=reason, **(extra or {}))
    write_result(analysis, timeline, complete=False)
    sys.exit(1)


def injection_facts(log_text, socket_mtime):
    """Prove the injection actually activated and started AFTER the IPC
    socket was created (i.e. inside the post-socket startup reconciliation,
    not the pre-socket daemon init). The sleep may still be running at
    probe time, so `finished_at` is optional here; the full duration is
    re-checked after IPC recovery (see injection_completion)."""
    if not log_text:
        return dict(activated=False, reason='injection log is missing')
    started = re.search(r'started_at=(\d+)', log_text)
    if not started:
        return dict(activated=False, reason='injection log lacks started_at',
                    log_text=log_text)
    started_at = int(started.group(1))
    facts = dict(activated=True, started_at=started_at,
                 requested_seconds=INJECTION_SLEEP_SECONDS,
                 socket_mtime=int(socket_mtime),
                 after_socket_creation=started_at > socket_mtime - 2)
    return facts


def injection_completion(log_text, facts):
    """After IPC recovery: verify the injected sleep actually finished and
    lasted the requested duration (>= requested - 1 s of wall-clock)."""
    if not log_text:
        return dict(completed=False, reason='injection log is missing')
    finished = re.search(r'finished_at=(\d+)', log_text)
    started = re.search(r'started_at=(\d+)', log_text)
    if not finished or not started:
        return dict(completed=False, reason='injection log lacks finished_at',
                    log_text=log_text)
    duration = int(finished.group(1)) - int(started.group(1))
    return dict(completed=True, duration_seconds=duration,
                requested_seconds=INJECTION_SLEEP_SECONDS,
                duration_ok=duration >= INJECTION_SLEEP_SECONDS - 1)


def self_check():
    """Host-runnable pure-logic checks (no container, no 45 s cycle):
    version parsing and the production wait_for_daemon() classification
    incl. genuine version/schema mismatch detection."""
    tokens = parse_version_tokens('fic-dick 0.1.0 ipc-api=1 db-schema=2')
    assert tokens == {'ipc-api': '1', 'db-schema': '2', 'product_version': '0.1.0'}, tokens
    good = classify_status_reply(dict(ok=True, message='m', product_version='0.1.0',
                                      database_schema_version=2), tokens)
    assert good.get('ok') and 'mismatch' not in good, good
    wrong_version = classify_status_reply(dict(good, product_version='9.9.9'), tokens)
    assert wrong_version.get('mismatch'), wrong_version
    wrong_schema = classify_status_reply(dict(good, database_schema_version=99), tokens)
    assert wrong_schema.get('mismatch'), wrong_schema
    missing_fields = classify_status_reply(dict(ok=True, message='m'), tokens)
    assert missing_fields.get('mismatch'), missing_fields
    # Injection evidence classification without any container:
    # a missing log or a missing timestamp must never be classified as a
    # provably activated injection.
    missing_injection = injection_facts(None, 0)
    assert missing_injection['activated'] is False, missing_injection
    no_timestamps = injection_facts('slow-init injection: opening x', 0)
    assert no_timestamps['activated'] is False, no_timestamps
    before_socket = injection_facts('started_at=100', 500)
    assert before_socket['activated'] and not before_socket['after_socket_creation'], \
        before_socket
    after_socket = injection_facts('started_at=1000', 500)
    assert after_socket['after_socket_creation'], after_socket
    unfinished = injection_completion('started_at=1000', {})
    assert unfinished['completed'] is False, unfinished
    finished = injection_completion('started_at=1000; finished_at=1046', {})
    assert finished['completed'] and finished['duration_ok'], finished
    too_short = injection_completion('started_at=1000; finished_at=1030', {})
    assert too_short['completed'] and not too_short['duration_ok'], too_short
    print('slow_init_native self-check PASS')


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
                             "sleeping %ds before returning; started_at=%ld\n",
                       path, g_opens, g_seconds, (long)time(NULL));
                fclose(log);
            }
            struct timespec req = {g_seconds, 0};
            nanosleep(&req, NULL);
            log = fopen("/var/tmp/fic-slow-init.log", "a");
            if (log) {
                fprintf(log, "slow-init injection: sleep finished; finished_at=%ld\n",
                        (long)time(NULL));
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
    if '--self-check' in sys.argv:
        self_check()
        return
    timeline = []
    analysis = None
    try:
        # Disposable PID1 systemd container preflight (no host mounts, no
        # network, no reuse of the host mount namespace).
        assert os.environ.get('FIC_PACKAGE_LIFECYCLE_NATIVE') == '1', \
            'FIC_PACKAGE_LIFECYCLE_NATIVE=1 required'
        assert Path('/proc/1/comm').read_text().strip() == 'systemd', \
            'PID 1 must be systemd'
        assert os.stat('/proc/self/ns/mnt').st_ino != \
            int(os.environ['FIC_HOST_MNT_INODE']), 'must run in a new mount ns'
        results.mkdir()
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
        socket_mtime = Path(DEVICE_SOCKET).stat().st_mtime if socket_present else None
        facts = injection_facts(injection_log, socket_mtime or 0)
        timeline.append(dict(step='injection-evidence', **facts))
        if reinstalled.returncode == 0:
            # NOT-REPRODUCED is admissible only with a provably activated
            # injection in the right phase and a successful reinstall.
            if not facts.get('activated') or not facts.get('after_socket_creation'):
                inconclusive('reinstall succeeded but the injection was not '
                             'provably active in the startup-reconciliation phase',
                             timeline, dict(injection=facts, expected_versions=versions))
            diagnose_failure()
            write_result(dict(verdict='NOT-REPRODUCED',
                              reason='reinstall succeeded despite a provably active '
                                     '>30 s initialization; see timeline and logs',
                              expected_versions=versions), timeline, complete=True)
            return
        # Case 1: the daemon itself died -> different defect class.
        if device['active'] != 'active' or device['main_pid'] in ('', '0'):
            inconclusive('device daemon is not running after the failed reinstall '
                         '(case 1: daemon failure, not the initialization window)',
                         timeline, dict(device_service=device, injection=facts))
        # Case 3: the daemon answers but with mismatched versions.
        if isinstance(status_probe, dict) and status_probe.get('mismatch'):
            inconclusive('daemon answered status with a version/schema mismatch '
                         '(case 3), not the initialization window',
                         timeline, dict(status_probe=status_probe,
                                        expected_versions=versions))
        # The interesting case 2: daemon alive, IPC socket accepting
        # connections, but the status request is not answered while the
        # injected initial reconciliation is still running.
        postinst_output = reinstalled.stdout
        if 'did not become ready' not in postinst_output and \
                'wait-daemon' not in postinst_output:
            inconclusive('reinstall failed for an unrelated postinst step',
                         timeline, dict(postinst_output=postinst_output[-1500:]))
        if status_probe is not None:
            inconclusive('status probe was answered during the wait window; '
                         'case 2 (initializing, not answering IPC) not confirmed',
                         timeline, dict(status_probe=status_probe))
        if not facts.get('activated') or not facts.get('after_socket_creation'):
            inconclusive('injection was not provably active in the '
                         'post-socket startup reconciliation phase',
                         timeline, dict(injection=facts,
                                        postinst_output=postinst_output[-1500:]))

        # Mandatory continuity check: remember the daemon PID right after the
        # failed install; the XFAIL verdict requires the SAME process to
        # answer IPC after the injected delay (Restart=on-failure untouched).
        pid_after_failure = device['main_pid']

        # 5. After the injected delay the very same daemon answers IPC,
        # proving it was only still initializing (case 2, not a crash).
        answered_after = wait_for_device_ipc(120)
        if answered_after is None:
            inconclusive('daemon never answered IPC after the injected delay '
                         'elapsed', timeline)
        still_active = service_state('fic-device.service')
        # The injected sleep must have provably completed with the requested
        # duration by the time IPC answers again.
        completion = injection_completion(
            Path('/var/tmp/fic-slow-init.log').read_text()
            if Path('/var/tmp/fic-slow-init.log').exists() else None, facts)
        timeline.append(dict(step='ipc-after-delay',
                             seconds_till_reply=round(answered_after, 1),
                             device_service=still_active,
                             injection_completion=completion))
        if not completion.get('completed') or not completion.get('duration_ok'):
            inconclusive('the injected initialization delay did not provably '
                         'run for the requested duration', timeline,
                         dict(injection_completion=completion))
        if still_active['active'] != 'active' or \
                still_active['main_pid'] != pid_after_failure:
            inconclusive('device daemon restarted or changed state after the '
                         'delay; XFAIL continuity not proven',
                         timeline, dict(pid_after_failure=pid_after_failure,
                                        device_service=still_active))

        # 6. Environment restored: the real configure must complete now,
        # proving the earlier failure came from the wait-daemon window only.
        remove_injection(dropin)
        run(['systemctl', 'restart', 'fic-device.service'])
        run(['/opt/fic/bin/fic-dick', 'wait-daemon', '10'])
        configured = run(['dpkg', '--configure', '-a'], success=False, timeout=300)
        if configured.returncode != 0:
            inconclusive('dpkg --configure -a failed after the injection was '
                         'removed', timeline,
                         dict(configure_output=configured.stdout[-1500:]))
        if lifecycle_status() != 'INSTALLED':
            inconclusive('lifecycle state is not INSTALLED after configure',
                         timeline, dict(lifecycle=lifecycle_status()))
        if config_snapshot() != saved_config:
            inconclusive('reinstall/recovery changed the saved policy config',
                         timeline)
        # The journal is retained and structurally consistent; note that the
        # real postinst configure (initialize-journal/prepare-install) may
        # legitimately rewrite journal bookkeeping, so content hashes are
        # recorded in the timeline but not pinned here.
        final_journal = journal_facts()
        if not final_journal['journal_exists'] or not final_journal['witness_exists']:
            inconclusive('journal/witness did not survive the reinstall',
                         timeline, dict(journal=final_journal))
        json.loads(Path('/opt/fic/db/mutation-journal.json').read_text())
        run(['/opt/fic/bin/fic-cli', 'status'])
        timeline.append(dict(step='configure-after-recovery',
                             lifecycle=lifecycle_status(),
                             config_matches=saved_config == config_snapshot(),
                             journal=final_journal))

        # Every mandatory check passed: only now is the XFAIL verdict
        # published, with the complete timeline including the recovery.
        write_result(dict(verdict='XFAIL-DEFECT-REPRODUCED',
                          reason='reinstall failed on `fic-dick wait-daemon 30` while '
                                 'fic-dick was alive with an unchanged PID (service '
                                 'active, IPC socket accepting connections, status '
                                 'unanswered during the >30 s initial reconciliation '
                                 'started after socket creation). Case 2: healthy '
                                 'daemon still initializing, not answering IPC.',
                          dpkg_exit=reinstalled.returncode,
                          reinstall_seconds=reinstall_seconds,
                          injection=facts,
                          pid_continuity=dict(pid_after_failure=pid_after_failure,
                                              pid_after_recovery=still_active['main_pid']),
                          expected_versions=versions), timeline, complete=True)
        print('PASS: slow-init reinstall probe completed with a verdict', flush=True)
    except BaseException as probe_error:
        diagnose_failure()
        write_result(dict(verdict='INCONCLUSIVE',
                          reason='unexpected probe exception: '
                                 + type(probe_error).__name__ + ': '
                                 + str(probe_error)[:500]), timeline, complete=False)
        raise


if __name__ == '__main__':
    main()
