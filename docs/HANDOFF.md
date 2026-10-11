# FIC handoff

## Current base
* Branch main; task base `d3e632e0944ef8a31592358e922a92236a7f9cd2`.
* This snapshot accompanies `Preserve release-only DE failure attribution in session-ready incidents`.

## Current task
* Release-only GNOME/FLY attribution and checkpoint failure diagnostics completed; no next implementation stage planned.

## Accepted architecture / invariants
* Desired requirements and failed release obligations are separate. Healthy MutationJournal admission/load validates scalar ownership/identity; coordinator snapshots active owners before any backend mutation, retaining mutation ID/resource/DE. Scope/artifact primary policies and previous scope never establish owners.
* A failed backend preflight/ensure/release/verify publishes unreleased scalar obligations once per owner/mutation, using the snapshot even when progress clears owners or journal health becomes Indeterminate. Completed physical releases do not create false obligations.
* Enabled owners aggregate desired/release/session outcomes into one planner result and one reporter pass with their own severity. Disabled/unproven owners retain global FAIL diagnosis without arbitrary policy incidents. Independent SessionOnly success remains explicit; Required-blocked origin, warnings, ingress validation and dedup unchanged.
* ScopeTransition typed diagnostic phases include checkpoint_state/prepare/commit, separate from global callback phases. Commit persistence failure preserves verified physical requirements without inventing a backend failure; global checkpoint remains failed. No operation reorder or error substring classification.
* Persisted format unchanged: release progress deliberately clears scalar owners. A later invocation with no surviving owner evidence remains UNPROVEN; no guessing from primary policy. Physical ownership-safe recovery remains available.
* KDE/XFCE SessionOnly/NotEnrolled, GNOME/FLY persistent mutation/CAS/fsync/recovery, DM, pure scope validation and LXQt Unsupported unchanged.

## Completed / changed areas
* DesktopGlobalConfigReconciler.{h,cpp}: diagnostic release failures from validated journal snapshots; immutable resource identity check; no physical rollback changes.
* ScopeTransition.{h,cpp}: optional typed failure-phase output; original callback/persistence order preserved. SessionPolicyReconciler.cpp: aggregate release failures by actual owner; checkpoint-only failure does not invalidate confirmed physical enforcement.
* session_ready_incident_tests now links real GNOME/FLY backends and tests actual journaled apply → scope exclusion → rollback conflict → real planner/reporter/controller. Covers NONE/SOFT/HARD/ISOLATE, shared owners, disabled/unproven/corrupt journals, preflight and release failures, session success/failure, repeat dedup, provenance retention/retry and checkpoint-only faults with/without desired globals.
* Shared existing GNOME fake command fixture extracted for reuse. MutationJournal regressions cover prepared/commit persistence phase and crash recovery. CI/static guards and graphical-scope-transactions.md updated.

## Validation
* Docker Debian12 full configure/build PASS; initial focused real-backend/coordinator/journal gate 3/3 PASS.
* Full Debian12 CTest **175/175 PASS**, 216.70s; final targeted gate **11/11 PASS**, 93.37s, covering session-ready, coordinator, GNOME/FLY, screenlock, MutationJournal/ScopeTransition, rollback executor, DM and static architecture.
* After adding explicit mock SessionOnly setting-retention assertion: rebuilt incident target; final focused incident CTest **1/1 PASS**, 37.31s.
* Direct desktop architecture static checks and git diff --check PASS.
* Native GNOME Debian12/Ubuntu24/ALT p11 probes PASS; ALT stock dconf preserved under /tmp inside disposable overlay for fixture isolation. Native Debian12 DM persistent inspection/journal restart/release PASS.
* Related GNOME/FLY/coordinator/session-ready gates PASS on Ubuntu24 and ALT using current Debian-built test binaries against native package environments (no distro-native rebuild claimed).
* Evidence: ignored build-prelogin-validation/dm-evidence/release-session-*. No host /etc or remote-machine modifications.

## Remaining / limits
* No unfinished implementation components. Temporary native snapshot tags removed; original containers/cache retained.
* Real graphical sessions/live DM/physical containment/native Astra FLY NOT VERIFIED. Incident tests use production pipeline with mock containment; physical backend tests use isolated temporary files and controlled command fixtures.
