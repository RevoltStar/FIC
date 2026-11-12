# Current workspace

## Current base / task
* main; HEAD `45d6019183f56ed2c190b8e455606d4e317d26c5`.
* Follow-up: fix violation severity CLI dispatch, GUI validation, and completion.

## Accepted architecture / invariants
* CLI `policy severity` routing fixed: checks `argv[3] == "set"` instead of `argv[5]`.
* Bash completion fixed for both `severity <module> <policy>` and `severity set <module> <policy> <severity>`.
* GUI `PolicyDescriptor` requires `violation_severity`, `default_violation_severity`, `violation_severity_values` with strict validation (token set, non-empty, no duplicates, effective/default in list).
* GUI `PolicyEditorWidget` no longer falls back to hardcoded severity list.
* Incident Response rules unchanged.

## Completed / changed areas
* CLI: `fic-cli/src/main.cpp` severity routing fixed.
* CLI: `tests/fic-cli/PolicySeverityCommandTests.cpp` rewritten to test routing logic.
* Completion: `fic/src/resources/completion/fic` fixed for cword 3/4/5/6.
* GUI: `PolicyDescriptor.cpp` mandatory severity fields + validation.
* GUI: `PolicyEditorWidget.cpp` hardcoded fallback removed.
* Tests: `PolicyDescriptorTests.cpp` extended with 15+ validation cases.
* Tests: `PolicyEditorSeverityTests.cpp` new Qt offscreen test.
* Docs: `fic-cli/README.md`, `fic-gui/README.md` updated.

## Validation
* `policy_descriptor_tests`, `policy_service_tests`, `cli_policy_severity_tests`, `cli_policy_set_tests`, `policy_violation_severity_tests`, `policy_editor_severity_tests` all PASS.
* `bash -n fic/src/resources/completion/fic` PASS.
* `git diff --check` PASS.

## Remaining / limits
* Daemon IPC schema tests (unknown policies, unexpected fields) not added — existing `PolicyViolationSeverityTests` cover core mutation scenarios.
* Full CTest not re-run after CMake reconfiguration.
* Early exploratory failures (missing ss/image CMD/staging metadata/stale native assertions/one runner edited while active) were followed by successful final reruns; final source code/scripts frozen for accepted runs. Existing source-bound PAM receipts remain stale and require a separately authorized rerun if current PAM matrix is needed.
