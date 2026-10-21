#!/usr/bin/env python3
"""Check the production startup boundary without executing policy mutations."""
import pathlib
import sys
root = pathlib.Path(sys.argv[1])
source = (root / 'fic/src/main.cpp').read_text().split('int main(int argc, char* argv[]) {', 1)[1]
assert '    fic::daemon::DaemonInstanceLock daemonInstance;' in source
acquire = source.index('daemonInstance.tryAcquire(')
assert source.index('FicRuntimePaths::initializeProduction') < acquire
for marker in ('DaemonMutationJournal::instance()', 'ConfigSchemaManager::verifyConfigs(',
               'blockSshBeforeStartupFailure(', 'initPolicyRegistry(',
               'incidentController().reconcile()', 'run_daemon_apply_all_pass(',
               'create_admin_server_socket('):
    assert acquire < source.index(marker), f'lock acquired after {marker}'
assert source.index('const bool daemonMode =') < acquire
mode = source[source.index('const bool daemonMode ='):acquire]
assert '"--maintenance"' in mode and '!packageTrustSync' in mode and '!affectedPackageTrustSync' in mode
assert 'socket' not in mode.lower(), 'custom socket must not bypass singleton'
assert 'return 1;' in source[acquire:source.index('if (get_arg_value(argc, argv, 1) == "--maintenance") {')]
print('PASS: daemon lock precedes journal/containment/apply, independent of socket; maintenance scope unchanged')
