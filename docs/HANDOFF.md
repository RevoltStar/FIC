# FIC handoff

## Current base

* Branch: `main`; task base: `f8bb2919eb780850676fe2cbffeb1031ea632e24`.

## Current task

Focused follow-up hardening of the Incident Response core and package lifecycle.

## Accepted architecture and invariants

* `/opt/fic/lockstatus` and its parent `/opt/fic` form one provenance boundary. Only exact, securely proven severity content is trusted; missing, malformed or unsafe state is effective ISOLATE.
* Package normalization may change children of `/opt/fic`, but must not repair the parent or `lockstatus` during upgrades or auxiliary package scripts. RPM manifests must not own `/opt/fic`: `%dir` restores its metadata during upgrade. Main package first-install bootstrap may prepare the parent only before `incident-init` when state is absent.
* Ordinary raise is monotonic and cannot repair malformed state. Administrative clear may replace a proven malformed object using its exact precondition. Clear from absence uses exclusive creation; repeated clear from proven UNLOCKED is a persistent no-op.
* Successful clear requires durable UNLOCKED. Failed clear may restore the prior severity or encode durable BROKEN/ISOLATE; the controller reports the resulting severity and `brokenState`.
* Emergency containment precedes persistence-failure audit. Notifications map SOFT/STANDARD to WARN, HARD to ERROR, ISOLATE to FATAL, and a successful transition to UNLOCKED to INFO.

| Observation | Effective state | Ordinary raise | Administrative clear |
|---|---|---|---|
| Proven UNLOCKED | UNLOCKED | monotonic | persistent no-op |
| Proven SOFT/STANDARD/HARD/ISOLATE | proven severity | monotonic max | conditional UNLOCKED |
| Proven absence | BROKEN/ISOLATE | never lowers | exclusive UNLOCKED create |
| Malformed, exact object proven | BROKEN/ISOLATE | never repairs | exact conditional UNLOCKED replace |
| Symlink, unsafe metadata/parent, proof race | BROKEN/ISOLATE | fail closed | refuse |

## Completed

* Excluded `/opt/fic` from generic ownership and mode normalization in Debian and ALT RPM package generators, and from RPM `%files` ownership.
* Hardened state-store clear, write preconditions, failure reporting, controller audit order and notifications.
* Added incident and packaging lifecycle regressions.

## Changed areas

* `packaging/deb/`, `packaging/rpm/`, `fic-common/fic-core/src/fs/`, `fic/src/incident/`, `fic/src/main.cpp`, and related tests.

## Validation

* `bash -n` for both package generators: passed.
* `python3 tests/integration/packaging/IncidentStateLifecycleChecks.py`: passed.
* `cmake --build build-check --target incident_state_store_tests incident_controller_tests fic -j2`: passed for the affected targets.
* `ctest --test-dir build-check -R 'incident_(state_store|controller)_tests' --output-on-failure`: 2/2 passed.
* RED-before packaging fixture from `f8bb2919`: old generic `find` selected `/opt/fic` and ordinary children while excluding only `lockstatus`; the new lifecycle check failed on the base generators.
* Isolated Debian 12 `dpkg -i` fixture preserved existing `/opt/fic` mode 0777 during upgrade. Isolated ALT RPM fixture changed 0777 to 0755 when `%dir /opt/fic` was listed and preserved 0777 after excluding that manifest entry.
* Fresh `/tmp/fic-incident-core-20261006-check` configure and full build passed; `ctest -N` registered 125 tests, including all incident tests and lifecycle checks.
* First sandbox full CTest: 2 failures (`session_agent_static_checks` still expected the old `find`; `session_event_server_tests` could not bind a Unix socket). Updated the static check and passed it separately.
* Full CTest outside sandbox after that fix: 125/125 passed, with `command_hash_batch_tests` skipped by its own gate.

## Remaining

* Actual FIC DEB/RPM install or upgrade was not run; only isolated minimal package fixtures were installed. No host policy apply or PAM/logind/nftables runtime validation was run.
* Production PAM access gate, session backend, network quarantine, early guard, recovery, greeter/display gate, Device Control integration and GUI remain outside this task. Product default `violation_severity` decisions remain unspecified.
