# Current workspace

## Current base / task
* main; HEAD `85acc312b285a0a0ec717519494289d7f429c5d1`.
* Follow-up: strengthen severity CLI and GUI regression coverage.

## Accepted architecture / invariants
* CLI `policy severity` routing fixed: checks `argv[3] == "set"` instead of `argv[5]`.
* Strict argument count validation: severity view needs exactly 5 args, severity set needs exactly 7 args.
* Bash completion fixed for both `severity <module> <policy>` and `severity set <module> <policy> <severity>`.
* GUI `PolicyDescriptor` requires `violation_severity`, `default_violation_severity`, `violation_severity_values` with strict validation (token set, non-empty, no duplicates, effective/default in list).
* GUI `PolicyEditorWidget` no longer falls back to hardcoded severity list.
* GUI parser clears `policies` on severity validation failure.
* Incident Response rules unchanged.

## Completed / changed areas
* CLI: `fic-cli/src/main.cpp` strict argc checks for severity view/set.
* CLI: `tests/fic-cli/PolicySeverityCommandTests.cpp` rewritten to test production `makePolicySeveritySetRequest()` directly, using `require()` instead of `assert()` for NDEBUG safety.
* Completion: `fic/src/resources/completion/fic` fixed for cword 3/4/5/6.
* GUI: `PolicyDescriptor.cpp` clears `policies` on `validateViolationSeverity` failure.
* GUI: `PolicyEditorWidget.cpp` hardcoded fallback removed.
* Tests: `PolicyDescriptorTests.cpp` extended with two-descriptor regression test (valid + unknown severity).
* Tests: `PolicyServiceTests.cpp` `severityOnly` fixture fixed: `valueChanged=false`.
* Tests: `PolicyEditorSeverityTests.cpp` Qt offscreen test.
* Docs: `fic-cli/README.md`, `fic-gui/README.md` updated.

## Validation
* `policy_descriptor_tests`, `policy_service_tests`, `cli_policy_severity_tests`, `cli_policy_set_tests`, `policy_violation_severity_tests`, `policy_editor_severity_tests` all PASS.
* `bash -n fic/src/resources/completion/fic` PASS.
* `git diff --check` PASS.

## Remaining / limits
* Daemon IPC schema tests (unknown policies, unexpected fields) not added — existing `PolicyViolationSeverityTests` cover core mutation scenarios.
* Full CTest not re-run after CMake reconfiguration.
* GUI end-to-end test (clicking save in PolicyEditorWidget and verifying IPC) not added: `PolicyEditorWidget` constructs `PolicyService()` internally without DI, so intercepting the save call would require production constructor changes. Covered at `PolicyService` level instead.
