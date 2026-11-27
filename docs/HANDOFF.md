# DM inventory optimization

Branch main. Task base a0fae90b073321ea8bb07c00d664d033ac91f19f.

## Completed

Task 1 commit 4735f8b4 moves unit-file enumeration to systemctl --root=/.
No server fallback, prelogin timeout or IPC changes.
Task 2 commit ade599b4 adds SelectedAndRunning mode to the same inventory.
Only observational compliance uses it and never invokes PackageQuery.
Autologin and transaction pre/post inventories retain InstalledAndRuntime;
SDDM native version proof remains. Ownership/journal/rollback are unchanged.

Task 3 is research only. Report docs/dm-inventory-optimization-research.md
recommends future show batching over the complete existing unit set. No
production show batching, filtering, caching or D-Bus replacement was added.

## Accepted invariants

The shipped daemon sees the same system root/unit-file view as PID1. Custom
root/mount/unit lookup overrides require separate validation. Live systemd,
default selection and logind discovery remain, including nonstandard DM unit
names and greeters. Relevant executable identity checks remain fail-closed.
Inactive installed out-of-scope managers remain compliant. Scope Required
dependencies and autologin installed-manager semantics remain.

## Validation

Logs /tmp/fic-dm-opt/. Fixture/evidence tests/integration/dm-inventory/.
Target builds display_manager_transaction_tests, policy_save_dependency_tests,
policy_execution_planner_tests passed. Root DM suite and five targeted
planner/save/static CTests passed. Task 2 adds deterministic unavailable-package,
systemd/logind, selected/running/headless, custom name, known/unknown greeter
and inactive out-of-scope regressions; PackageQuery call count is zero for
observation and nonzero/failing for full/autologin inventory.

Native systemd PID1 equivalence passed ALT p11 258.9, Ubuntu24 255.4,
Ubuntu26 259.9. All compared unit names/states matched, including enabled,
enabled-runtime, disabled, masked, alias, generated, transient, templates;
concrete instance discovery via loaded units remains. Selected show fields
also matched for individual calls versus batches of 32. Server-list probe
maxima 386–445 ms; client-list maxima 14–22 ms. Three repeat listing samples,
one warm show pass per transport. JSON records exact measurements.
Versioned upstream v252/255/257/258/259 implementation was inspected.

## Limits

Debian12/13 native images could not finish APT main index downloads via HTTP,
HTTPS/CA and direct-index retry. Own stalled clients were cancelled; no native
PASS is claimed for Debian. Three completed test containers were removed.
No host service/config changes, real graphical login, full CI, cold HDD or
packet-level D-Bus message counts were tested. Custom vendor patchsets were
not exhaustively audited. Native latency measurements do not prove correlation
with every historical prelogin unavailable event. No push.
