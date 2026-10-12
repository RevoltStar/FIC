# FIC handoff

## Current base
* Branch `main`; task base `bd9e20d4b58dcf984dd8a0bb16931dab208e7f77`.

## Current task
* GUI Incident Response, exactly two commits. Commit A contains status/admin controls; commit B must add audit history after A is committed.

## Accepted architecture / invariants
* GUI is only an existing daemon IPC client; no enforcement/state machine changes.
* Permanent incident page survives dynamic module reload/errors. One persistent worker serializes polling/admin requests; no polling backlog.
* Invalid/failed acquisition retains the last valid in-memory snapshot and acquisition timestamp, with prominent STALE warning. First failure has no invented snapshot.
* Clear/raise require confirmation; no optimistic state changes; status refresh follows every action. DEGRADED with reachable daemon keeps controls available.
* History must use existing current-boot `boot_id`/`log_records`, separately parsing structured IncidentController audit rather than Logger text/admin audit.

## Completed
* A: strict incident status parsing, acquisition sequencing, offline fallback RU/EN resources, nonblocking polling/admin UI, independent MainWindow tab.
* Offscreen injected-IPC tests cover invalid fields, proofs, degraded, first failure, stale/recovery, rejected actions, confirmations, module/policy load failures, coalescing and in-flight destruction.

## Changed areas
* `fic-gui/src/features/incidents`, MainWindow, localization/resources; RU/EN lang files; GUI tests/CMake; GUI README.

## Validation
* Native Ubuntu-24.04-target configure; `fic-gui` and `incident_gui_tests` builds passed.
* Targeted CTest passed 6/6: incident GUI/offscreen, incident static RU/EN/ownership, module UI static, module/policy descriptors and PolicyService. `git diff --check` passed.
* Docker CLI exists but daemon unavailable even with sandbox escalation (no `/var/run/docker.sock`). Native mock/offscreen validation used; no host incident/policy/system changes.

## Remaining
* Commit B: bounded structured audit history, filters, cursor/rotation/boot/stale tests and documentation.
* Final full build/CTest required because tests CMake changed. Real graphics and live administrative operations intentionally unverified.
