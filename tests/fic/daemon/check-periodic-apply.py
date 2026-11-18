#!/usr/bin/env python3
"""Wiring guards complement model-time scheduling/configuration unit tests."""
from pathlib import Path
import sys

root = Path(sys.argv[1])
main = (root / 'fic/src/main.cpp').read_text()
loop = main[main.index('    while (!g_stop) {', main.index('PeriodicApplySchedule periodicSchedule')):]
periodic = loop[loop.index('if (mayMutate && periodicSchedule.due(now))'):loop.index('if (mayMutate && now >= nextSshCheck)')]
assert main.count('readPeriodicApplySettings(') == 1
assert 'readPeriodicApplySettings(' not in loop
assert main.index('const auto periodicSettings = loadedPeriodicSettings;') < main.index('PeriodicApplySchedule periodicSchedule')
assert 'if (!uninstallMode && !fic::daemon::readPeriodicApplySettings(' in main
assert 'if (mayApply)\n                run_daemon_apply_all_pass(' in periodic
assert periodic.index('periodicSchedule.attempted(now);') < periodic.index('bool mayApply')
assert periodic.index('recomputeAccessReadiness(') < periodic.index('periodicSchedule.finished(')
assert 'if (mayApply)\n                periodicSchedule.finished(std::chrono::steady_clock::now());' in periodic
assert 'sleep' not in periodic
assert 'nextSshCheck = now + std::chrono::seconds(30);' in loop
assert 'auto nextSshCheck = std::chrono::steady_clock::now() + std::chrono::seconds(30);' in main
assert 'intervalSeconds' not in loop[loop.index('if (mayMutate && now >= nextSshCheck)'):]
registration = (root / 'fic/src/daemon/main_function.cpp').read_text()
for key in ('check_interval', 'periodic_apply_min_pause'):
    assert f'cafArr.push_back(std::make_unique<GLOBAL_{key}>());' in registration
    for language in ('ru', 'en'):
        strings = (root / f'fic/src/resources/lang/{language}.lang').read_text()
        assert f'[module:GLOBAL][policy:{key}]=' in strings
        assert f'[module:GLOBAL][policy:{key}][description]=' in strings
unit = (root / 'fic/src/resources/service/fic.service.in').read_text()
assert 'ExecStart=@FIC_PRIVATE_BINDIR@/fic\n' in unit
assert '--interval' not in unit
for builder in ('packaging/deb/build-fic-debian12-deb.sh', 'packaging/rpm/build-fic-alt-p11-rpm.sh'):
    assert '--interval 1800' not in (root / builder).read_text()
# Neither configuration validation policy invokes an OS mutator or journal.
policy = (root / 'fic/src/modules/global/system_settings/policies/GLOBAL_periodic_apply_settings.cpp').read_text()
for forbidden in ('ProcessExecutor', 'systemctl', 'MutationJournal', 'saveConfig', 'AtomicFileWriter'):
    assert forbidden not in policy
print('PASS periodic wiring, independent SSH checks, registration, localization and service contract')
