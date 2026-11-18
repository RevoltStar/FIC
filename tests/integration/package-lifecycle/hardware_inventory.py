"""Hardware assertions shared by the real DEB/RPM systemd package gates."""
from pathlib import Path
import sqlite3

UNIT = 'fic_get_device_info.service'
STATE = Path('/var/lib/fic-lifecycle/status')
DB = Path('/opt/fic/db/devices.db')


def rejected_while_installing(run):
    assert STATE.read_text() == 'INSTALLING\n'
    before = {p.name: p.read_bytes() for p in DB.parent.glob('devices.db*')}
    refused = run(['/opt/fic/bin/fic-dick', 'cpu_board_memory'], success=False)
    assert refused.returncode != 0 and 'refusing device writer admission: package lifecycle: INSTALLING' in refused.stdout
    assert run(['systemctl', 'start', UNIT], success=False).returncode != 0
    assert run(['systemctl', 'show', UNIT, '-p', 'ExecMainStatus', '--value']).stdout.strip() != '0'
    assert {p.name: p.read_bytes() for p in DB.parent.glob('devices.db*')} == before


def collected(run):
    assert STATE.read_text() == 'INSTALLED\n'
    assert run(['systemctl', 'is-enabled', UNIT]).stdout.strip() == 'enabled'
    facts = dict(line.split('=', 1) for line in run([
        'systemctl', 'show', UNIT, '-p',
        'LoadState,ActiveState,SubState,Result,ExecMainStatus,InvocationID,ExecMainStartTimestampMonotonic,Type,RemainAfterExit'
    ]).stdout.splitlines())
    for key, value in dict(LoadState='loaded', ActiveState='active', SubState='exited',
                           Result='success', ExecMainStatus='0', Type='oneshot', RemainAfterExit='yes').items():
        assert facts[key] == value, facts
    assert int(facts['ExecMainStartTimestampMonotonic']) > 0 and facts['InvocationID'], facts
    # Parent categories alone do not prove that any collector ran.
    with sqlite3.connect(f'file:{DB}?mode=ro', uri=True) as db:
        rows = db.execute("SELECT DISTINCT subsystem FROM devices WHERE notes IN "
                          "('cpu_concrete','board_concrete','memory_concrete')").fetchall()
    assert {row[0] for row in rows} == {'cpu', 'board', 'memory'}, rows
    return facts['InvocationID']


def oneshot_semantics(run):
    first = collected(run)  # Must have run automatically, before any manual start.
    run(['systemctl', 'start', UNIT])
    assert collected(run) == first, 'start of active RemainAfterExit unit ran again'
    run(['systemctl', 'restart', UNIT])
    second = collected(run)
    assert second != first, 'restart did not run the collector'
    # A new boot has no retained active state. Stop/start models that aspect;
    # the enabled multi-user.target link proves the boot activation mechanism.
    run(['systemctl', 'stop', UNIT])
    assert Path('/etc/systemd/system/multi-user.target.wants', UNIT).is_symlink()
    run(['systemctl', 'start', UNIT])
    assert collected(run) != second


def stopped(run):
    facts = dict(line.split('=', 1) for line in run([
        'systemctl', 'show', UNIT, '-p', 'ActiveState,MainPID,ControlPID'
    ]).stdout.splitlines())
    assert facts == dict(ActiveState='inactive', MainPID='0', ControlPID='0'), facts
