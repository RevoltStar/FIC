# Current workspace

## Current base
* Branch main; base c7b598c4b717481a0d030a6ecb37ddf1955552e5. Current task is one follow-up commit; no push.

## Current task
* Remove c7b598c's forced sudo/openssh-server/procps dependencies and prove safe no-owner rollback/uninstall in minimal Debian12/13 and Ubuntu24/26.

## Accepted architecture / invariants
* AGENTS17/docs/package-lifecycle.md: existing four-state lifecycle, daemon-owned release, infrastructure-only helper and daemon.lock remain. No new recovery, journal schema, adoption, force or automatic provider installation.
* Only a healthy initialized journal/witness plus physical ownership/staging absence permits no-op. Active ownership uses unchanged strict rollback/CAS; unknown/untrusted physical state fails closed.

## Completed / changed areas
* DEB builder no longer requires sudo, openssh-server or procps. Audit: SysctlRuntime uses direct /proc/sys; profiles use systemd-sysctl; no core/runtime procps command calls found. Strict ELF dependency discovery retained.
* Read-only UnrecordedResourceInspection for SSH/SUDO/SYSCTL checks the whole backend has no active records, trusted ancestors, bounded secure reads, single links and interrupted staging. SSH includes historical paths; SUDO includes current include graph, detached fragments and historical proof paths. SYSCTL reuses existing managed assignment grammar without parsing foreign loader files. Active release paths unchanged; SSH Prepared gate preserved.
* rollback_all projects proven optional-backend no-ops as NOTHING_TO_RELEASE. Orphans are neither adopted nor deleted; failure preserves provenance/configuration.
* Unit/dependency regressions and minimal native driver/runner extended. Test-only optional_owner_fixture seeds typed unresolved state via production journal API under lock, is not installed, and cannot perform rollback/recovery.
* Docs/evidence: docs/package-lifecycle{,-validation}.md, packaging/deb/README.md, native README and evidence/optional-providers-*.json. Historical c7b598c evidence retained and its dependency workaround marked superseded.

## Validation
* Matching affected production builds + rollback_executor_tests/optional_owner_fixture and five focused CTest PASS on Debian12/13 Ubuntu24/26. Four other direct RollbackExecutor consumers build and CTest PASS on Ubuntu24 (SUDO scoped lifecycle, PAM wiring, identity login.defs/concrete).
* Eight real minimal native APT gates PASS: four ordinary remove-from-INSTALLED/purge runs; four no-owner/physical/active negatives. All three optional packages/executables absent, all five shipped ELF resolve, daemons/readiness and configured package status/audit pass.
* Negative gates reject orphan SSH/SUDO markers, SYSCTL staging, unsafe parent mode, hardlink and symlink without adoption. Fresh reinstall plus SSH/SUDO Prepared and drifted SYSCTL Applied fixture retains IDs/undo/config and blocks actual APT removal in UNINSTALLING. Clean remove/purge is proved before this retained negative state; no journal rewrite/reset to manufacture success.
* Shell/Python syntax, standalone dependency regression and git diff --check PASS. Raw logs: build-optional-uninstall/; per-run container/commands/results: build-package-lifecycle/native-fic-optional-runtime:*. Source/archive/ELF/log/image digests in committed evidence.

## Remaining boundaries
* No task blocker. Active negative records are test-seeded production-API fixtures, not real optional-provider apply. No new full project build/CTest, ALT native matrix, live SSH, real-user PAM or hardware enforcement claim. Runtime /sys and /proc/sys read-only; native isolation does not prove physical enforcement. Existing cooperative locking cannot isolate arbitrary privileged external writers.
* Initial Ubuntu procps assertion was base-image contamination; runtime fixture now purges preinstalled optional providers. Failed runs preserved separately. Earlier readiness-timeout root cause remains unproved and timeout unchanged.
* Docker used by user authorization. Runtime containers removed by runner; build images/caches retained; unrelated volumes untouched. No host security/resource mutations.
