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
assert 'if (mayApply) {\n                periodicSchedule.attempted(std::chrono::steady_clock::now());\n                run_daemon_apply_all_pass(' in periodic
assert periodic.count('periodicSchedule.attempted(') == 2
assert periodic.index('bool mayApply') < periodic.index('periodicSchedule.attempted(std::chrono::steady_clock::now());')
refused = periodic[periodic.index('} else {'):periodic.index('if (!periodicRegistryReloadFailed)')]
assert 'periodicSchedule.attempted(now);' in refused
assert 'periodicSchedule.finished(' not in refused
assert 'ensurePeriodicApplyDefaults(' not in main
assert 'ConfigSchemaManager::verifyConfigs(' in main
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

# Fresh install, upgrade/reconfigure both run the existing package migration.
for script in ('packaging/deb/lifecycle/fic.postinst', 'packaging/rpm/lifecycle/fic.post'):
    text = (root / script).read_text()
    assert 'config_command=ensure-config\n' in text
    assert 'config_command=ensure-config-first-install\n' in text
    ensure = text.index('/opt/fic/bin/fic --maintenance "$config_command"')
    assert ensure < text.index('/opt/fic/bin/fic --maintenance complete-install')
    assert ensure < text.index('systemctl start fic.service')
readme = (root / 'fic/README.md').read_text()
assert 'ExecStart=/opt/fic/bin/fic\n' in readme
assert 'ExecStart=/opt/fic/bin/fic --interval' not in readme
print('PASS periodic timing, read-only startup, package migration and independent SSH contracts')
