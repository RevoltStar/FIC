# FIC handoff

## Current base
* Branch main; DE task base `e279c46eb79335b624ac3e00559d051dcd1526bb`.
* This snapshot accompanies the first task commit: `Implement transactional DE scope reconciliation and ownership-safe rollback`.

## Current task
* DE implementation and repository validation complete within the explicit fail-closed backend limits below. DM has not been started.
* Next pass: DM from original attachment fd35e451-1ff5-4136-9215-2e827582de71, second and final task commit `Add controlled display manager scope and rollback-safe autologin enforcement`.

## Accepted architecture / invariants
* Configured intent, committed scope checkpoint and pending/failed/partial state live alongside independent physical provenance in MutationJournal. Only matching Applied/committed scope authorizes dependent apply.
* Scope set_value saves intent and reloads registry; it does not mutate OS resources. Required dependencies guard ordinary, direct-session and compliance paths.
* Root resources use AtomicFileWriter snapshot CAS + FIC locking, with documented residual final-proof-to-rename/unlink/rmdir race against writers ignoring FIC locks. No whole foreign-file snapshots, legacy ownership adoption or migration.
* KDE/XFCE setters strictly fail closed before native mutation. Current FLY has no runtime effectiveness proof: nonempty production enforcement is refused before physical writes. Its persistent inverse is implemented; do not claim native FLY/session enforcement.

## Completed
* Production coordinator collects complete per-key owner sets, preflights all backends, prepares transition, ensures targets, releases obsolete owners, verifies native/resource/durability state and current configuration snapshots, then commits. Failures retain recoverable checkpoint/provenance.
* GNOME exact key/lock inverse and native cache compilation/verification; fixed-route creation provenance for files, groups, profile entry, cache and all missing directories. ID markers, directory device/inode, secure staging and restart/abort recovery. Cleanup preserves foreign contents and detaches transferred containers; unrelated databases remain untouched.
* FLY exact persistent scalar inverse preserves foreign bytes/groups/CRLF. Journaled refresh/release and interrupted-operation recovery use snapshot CAS and owner proofs.
* Joint policy rollback preserves surviving owners even when primary owner is removed. Generic individual DE record undo is refused. Scope checkpoint is invalidated before release.
* Root-only desktop-prerm-prepare preflight/release uses the same coordinator independently of current policy/scope/session. Debian/RPM removal gates preflight before writer stop, release before PAM detach; failures refuse removal.
* Journal schema/status guards, Required/coordinator/intent-version tests, filesystem/native/cache/fsync/journal fault tests, abrupt fork-exit staging resume/abort tests, generated package-hook gates and native GNOME probe updated.

## Changed areas
* DE policies/backends/coordinator, daemon orchestration, MutationJournal/ScopeTransition/RollbackExecutor.
* Minimal shared read-only configuration snapshot access, tests/CMake, DEB/RPM removal hooks.
* Authoritative contract: docs/graphical-scope-transactions.md; rollback enrollment: docs/rollback.md.

## Validation
* Debian12 builder `fic-deb-builder:debian12-final`; source mounted readonly at /src, build at /build (`build-prelogin-validation/final`). Full configure/build PASS, latest full build log `de-scope-full-build-final.log`.
* Latest full `ctest --test-dir /build --output-on-failure`: **173/173 PASS**, 125.61s, log `de-scope-full-ctest-final.log`. Container drops DAC_OVERRIDE/DAC_READ_SEARCH so permission-failure tests are meaningful; Git safe.directory=/src accommodates readonly mount ownership.
* MutationJournal and RollbackExecutor additionally PASS as UID65534. Generated desktop package removal checks, PAM packaging checks and prelogin package lifecycle tests PASS; shell syntax checks PASS. git diff --check PASS.
* Actual native dconf/GSettings existing/created-container lifecycle, shared-owner release, restart, foreign edits/locks/databases and cleanup PASS with latest binary on four disposable root containers:
  * Debian12: dconf 0.40.0-4, schemas43.0-1 (`fic-de-native-gnome:debian12-check`).
  * Debian13: dconf 0.40.0-5, schemas48.0-1 (`fic-de-native-gnome:debian13-check`).
  * Ubuntu24.04: dconf 0.40.0-4ubuntu0.1, schemas46.1-0ubuntu1 (`fic-de-native-gnome:ubuntu2404-check`).
  * Ubuntu26.04: dconf 0.49.0-4, schemas50.0-1ubuntu2 (`fic-de-native-gnome:ubuntu2604-check`).
* Native probe explicitly requires FIC_NATIVE_GNOME_PROBE=container-only, root and /.dockerenv; never ordinary host CTest. No host/remote system policy mutation performed.

## Remaining / limits
* DM is the next task; do not revisit completed DE implementation without a concrete defect.
* ALT p11 native GNOME NOT VERIFIED: package mirror.yandex.ru refused connections on HTTP80 and HTTPS443. No provider test ran; package signatures were not weakened.
* Native FLY, GNOME Shell/live KDE/XFCE sessions and actual package-manager install/erase NOT VERIFIED. Generated removal scripts and native dconf/GSettings probes are distinct evidence levels.
* screenlock_timeout has Supported joint rollback for currently permitted journaled root mutations. Media-controls rollback remains Unsupported; native session writers are unavailable. Unknown DE routes/actions fail closed.
