# FIC handoff

## Current base

* Branch `main`; task base `a405b3c11717c02fc9c78f6ecc0a75e02e21979d`.

## Current task

* Close the administrative IPC ACTIVE preflight bypass through module aliases.

## Accepted architecture / invariants

* `canonical_module_name(policyRegistry, module)` defines module identity for policy mutation. After request parsing and schema validation, preflight and mutation must see the same canonical module. Policy names and values stay case-sensitive.
* Managed ACTIVE transitions block declared SSH entry points before configuration write. OFF/PASSIVE behavior, readiness proof, journal and rollback remain unchanged.

## Completed

* Canonicalized the validated IPC request module before ACTIVE preflight and `handle_request`.
* Added alias cases to the guarded transition test and a production source ordering check. The ordering check failed on the task base before the fix.

## Changed areas

* `fic/src/main.cpp`, `fic/src/incident/IncidentModeTransition.h`, `tests/fic/incident/IncidentModeTransitionTests.cpp`, `tests/fic/modules/net/ssh/static_checks.py`.

## Validation

* RED before fix: `python3 tests/fic/modules/net/ssh/static_checks.py /home/admsys/FIC` failed: `IPC must canonicalize module before ACTIVE preflight`.
* GREEN after fix: same check passed; `git diff --check` passed.
* Fresh Debian 12 container configure and targeted `fic` / `incident_mode_transition_tests` build passed; targeted test passed.
* Full container build passed; CTest passed 133/133 (excluding `mutation_journal_tests`).
* `mutation_journal_tests` passed by direct binary execution as UID 1000. A CTest attempt with read-only `/build` could not create `LastTest.log`, so it was rerun directly.

## Remaining

* No live host SSH/PAM or policy mutation was performed.
