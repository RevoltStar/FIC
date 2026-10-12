# FIC handoff

## Current base
* Branch `main`; follow-up base `d06ac87e5c839d44dfcf11d12692dcdf56aff46a`.
* This snapshot accompanies `Fix duplicate incident history events and status polling audit noise`.

## Current task
* Incident history multiplicity and read-only incident_status audit noise corrected in one follow-up commit.

## Accepted architecture / invariants
* Each valid physical audit record returned by log_records is retained independently, even for identical JSON/source/timestamp. Incremental acquisition relies on cursor, never content deduplication.
* Reload/rotation clears only the candidate snapshot and cursor. A successful bounded reconstruction atomically replaces published history; failure preserves old records/boot/cursor/time with STALE. One automatic restart per refresh; reload control responses do not consume the four-successful-page budget. Pages read before reload still count toward the total bound.
* Qt snapshot generation identifies replacement/eviction boundaries, not physical events. Positional content comparison only optimizes rendering; insert preserves identical neighboring rows, reconstruction/eviction forces reset.
* Valid incident_status is excluded from administrative audit only after real parsing/schema validation. Invalid status requests and mutation/unknown commands remain audited; legacy boot_id/log_records/access_gate_status/prelogin_status exclusion semantics unchanged.
* IncidentController audit sink and always-on SecurityAudit remain independent of administrative request filtering and AUDIT/log_level, including NoLog.
* No changes to busy_, worker/threading, cancellation/timeouts, priorities/polling, enforcement, PAM/FIREWALL/logind/prelogin, rollback or severity/mode semantics.

## Completed / changed areas
* IncidentHistoryService, IncidentAuditModel and HistoryView: content identity/QSet/hash removed, bounded independent reconstruction and explicit model replacement generation.
* AdminAudit classification extracted from main; main passes actual validation result. Audit JSONL format and existing IPC endpoints unchanged.
* Regression tests cover identical records within/across pages and incremental requests, empty reads, reconstruction replacement/failure/repeated reload/page budget, bounds, boot changes, model insert/reset, 10000 status polls, administrative success/refusal, invalid/unknown commands, legacy exclusions and real controller events with NoLog.
* GUI README, relevant audit architecture paragraph and RU/EN reload message corrected.

## Validation
* Native Qt5 builds: fic-gui, fic, incident_history_tests, incident_gui_tests, admin_audit_tests, incident_controller_tests PASS.
* Related CTest 9/9 PASS: GUI/history/static checks, platform/module static checks, admin/security audit, controller and LogRecordsReader.
* Docker CLI via temporary rootless Podman-compatible API; Debian12 existing image, read-only source, network none, DAC_OVERRIDE/DAC_READ_SEARCH dropped. Full configure/build PASS; full CTest 178/178 PASS, 38.63 s.
* git diff --check PASS. Evidence: ignored build-incident-docker/followup-configure.log and followup-final-{build,ctest}.log and /tmp/fic-followup-target-*.

## Remaining / limits
* No unfinished implementation. History bounds remain 200 records/page, 4 successful pages/refresh, 1000 events/4 MiB accounted data, 16 KiB raw lines; partial/truncated/stale handling preserved.
* log_records has no physical offsets/IDs. Reconstruction cannot identify events across independent generations or recover removed log files; reconstruction/rotation and incomplete ranges explicitly show PARTIAL.
* Real host incident operations/desktop/physical containment not exercised; tests use mocks and disposable containers. No packages installed and no host permissions/policies changed.
