# FIC handoff

## Current base

* main; task base `76273c79781fd783c777b0577be316221d8c4270`.
* Snapshot accompanies the completed DC new/all lifecycle commit; actual HEAD: `git log -1`.

## Current task

* Completed three DC category policies new/all and removed exclusive DC rollback.

## Accepted architecture / invariants

* all is absolute category DENY; explicit identity/placement precedes new; hierarchy/default follow. DISABLE removes category intent without deleting device rules or physical undo.
* Schema 2 uses disabled/new/all and durable known identity/attribute snapshots independent of occurrence deletion. BEGIN IMMEDIATE + FULL synchronization captures epoch on disabled/all → new; identical new, restart/crash/reconnect/regeneration preserve epoch.
* USB physical parent serial/vendor/product and block WWN/serial match safely in runtime/snapshot/compiler. Missing/unsafe identity cannot receive known exception. Partition/USB interface occurrence does not define a new physical identity.
* DC.conf is authoritative; successful reload precedes full three-mode sync, including all DISABLE. Failed sync preserves config and pending desired revision for periodic/startup repair. Current-device enforcement uses current udev inventory and bounded existing sysfs backend; no global trigger.
* Three known categories NotEnrolled, unknown DC policy Unsupported. Exclusive DeviceControl journal/undo/backend removed; other rollback contracts preserved.

## Completed / changed areas

* Shared device DB/schema/category helpers; fic DC/orchestration; fic-dick collector, IPC/audit, effective policy, snapshot/compiler/enforcement; config/localization.
* CMake/CI regressions and existing DC static/VM tests; reusable Docker/native gate.
* `docs/device-control-validation.md` contains commands, tested image IDs, precedence/transition tables and evidence boundaries. `docs/rollback.md` and fic-dick README updated.

## Validation

* Five distro Docker matrix PASS: ALT p11, Debian12/13, Ubuntu24.04/26.04. Each production build + 10/10 targeted tests + real CLI/IPC/SQLite fault/crash/periodic gates + native udev parser/matcher.
* Debian12 full project build PASS; final full CTest 171/171 PASS excluding permission-sensitive mutation_journal_tests. Journal suite separately PASS UID65534.
* Earlier process_cancellation cleanup assertion was flaky: isolated and final full reruns PASS; no unrelated ProcessExecutor changes.
* git diff --check PASS.

## Remaining / limits

* Physical hardware and real udevd/systemd reboot E2E untested. Activation/inventory fixtures are distinguished from native udevadm test, which does not execute RUN; sysfs writes occur only in test fixtures.
* Reported device identifiers are not cryptographic authentication. Disabling/all → new does not reconnect physically deactivated devices; reconnect/rescan may be necessary.
* No schema/config/journal migration or obsolete-format compatibility added.
