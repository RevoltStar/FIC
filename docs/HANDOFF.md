# Current working state

## Current base
* `main`; task base `9467b4a7073a999de1a3ac2b6e14c4c2d174ed98`, initially clean. One separate daemon singleton-lock commit, no push.

## Current task / accepted scope
* User deferred SSH Stage 3A: first implement early daemon-wide singleton. Only daemon mode, independent of --socket; maintenance/trust-sync/read-only routes unchanged. Do not implement SSH Stage 3A in this commit.
* Lock before any startup journal/incident containment/apply; held for daemon lifetime. No IPC-based singleton. Root-controlled descriptor traversal + root-owned 0600 single-link regular lockfile + nonblocking flock; no symlinks, metadata repair, PID authority or unlink on exit.
* Singleton serializes daemon processes sharing production runtime directory/filesystem namespace, not ALL FIC writers. Standalone/package coordination explicitly remains separate work.

## Completed / changed areas
* `fic/src/daemon/DaemonInstanceLock.{h,cpp}`; integrated in `fic/src/main.cpp` after memory-only runtime-path initialization and before maintenance routing/config failure containment/journal/registry/apply. Read-only flags still return earlier; daemonMode excludes maintenance/trust sync.
* Root-owned fixtures/process tests use pipes, bounded watchdog, real flock/fork: contention, simultaneous start, release/restart, SIGKILL/restart, exception cleanup, invalid owner/mode/path/symlink/hardlink/FIFO/directory. No sleeps or host apply.
* Production ordering static check and disposable-only real daemon rejection probe added to CTest. Probe compares security-file snapshots for default/custom socket, checks read-only flags/maintenance scope and crash/reacquisition.
* `docs/daemon-singleton.md`: implementation contract + read-only audit of all standalone maintenance/trust-sync actions and Debian/RPM scripts, classifications and mandatory follow-ups. No package script/backend lifecycle changes. Started SSH Stage 3A test edits were removed before this task; SSH production/tests unchanged.

## Validation
* Targeted Debian12 lock CTest PASS; `/tmp/fic-singleton-targeted.log`.
* Debian13 native g++ C++17 -Wall -Wextra -Werror compile and process suite PASS; `/tmp/fic-singleton-debian13.log`.
* Startup boundary static check PASS. Standalone command audit coverage checked against main command selectors. Final diff/scope reviewed; `git diff --check` PASS.
* Full Debian12 configure/build + full CTest PASS with `FIC_DAEMON_SINGLETON_NATIVE=1`: 191 PASS/0 FAIL/1 expected generic native opt-in SKIP (192 total), 170.99s. All three new lock/static/real-startup tests PASS; `/tmp/fic-singleton-full-debian12.log`.

## Remaining / confirmed risks
* No unfinished singleton implementation/validation. One separate daemon singleton commit, no push. SSH Stage 3A not started; maintenance/package coordination requires separate agreement.
* Confirmed by source audit: release commands can write shared MutationJournal/resources while daemon is running; no whole-journal interprocess admission. Some resource locks exist, but journal loads precede them and cross-backend journal remains outside their domain.
* Package preflight entrypoints use operational tryGet/initializeOrLoad, potentially creating journal/witness despite RO backend. RPM erase suppresses stop errors and proceeds to release without stopped proof. Debian checks active after bounded stop, but absent/failing manager, transitional/manual processes remain unproven. These are mandatory separate package/maintenance coordination tasks, not fixed here; see authoritative audit doc.
* Existing SSH Stage 1/2 unchanged. SSH Stage 3A shared process-local mutex/Prepared gate pending; R2 full REFRESH, R3 fingerprints and coordinator remain future work. No global multiprocess journal safety or live SSH/PAM validation claim.
