# Current working state

## Current base
* Branch main; initial clean HEAD cf0819dbf86414ffd856a6e0c8852616f5dbb42e.
* No task commits/push. User requires commits A/B/C only after their gates pass.

## Current task
* SUDO global ownership/apply/rollback (A), integration with scoped Defaults (B), reversible authentication (C).
* Original request: attachment e4f55516-ceba-4baf-984e-5b90472dd8ea/Вставленный текст.txt. Provider clarification is in docs/sudo-apply-rollback-design.md.

## Accepted architecture / invariants
* Classic: five globals in fully owned /etc/sudoers.d/99-fic.conf, canonical physical EOF FIC_INCLUDE block; durable Prepared before mutation, file→include protocol; independent rollback, inert file→detach include→validate→conditional delete for last owner.
* Active provider detection must prove executable/version/config/native validator. Unknown semantics fail closed; never switch alternatives in production. sudo-rs env_reset and exempt_group_disable are VerifiedByConstruction without fictitious values/records. Classic exemption checks remain required where relevant.
* Five scoped dependencies are Recommended; authentication exemption dependency is provider-aware. Typed authentication rewrites must preserve commands, arguments and all non-authentication tags, with exact original bytes and journal-backed recovery.
* All native experiments confined to disposable Podman containers. Required matrix: Debian12/13, Ubuntu24.04, Ubuntu26.04 default sudo-rs and classic, ALT p11. No host security state mutation.

## Completed / changed areas
* A implementation in progress: ManagedInclude parser, GlobalDefaultsTransaction, typed UndoReleaseSudoGlobalDefault journal codec/identity guards, independent/shared artifact release, CAS and durability/full-graph proofs, provider rechecks.
* Old global mutation helpers removed. Scalar production apply/rollback use typed ownership. Legacy unproven SUDO records fail Conflict; foreign filename/markers never imply ownership.
* Provider detection admits tested classic versions and sudo-rs0.2.13(-0ubuntu1.2); env/exempt construction paths retire proven prior ownership. New BackendRequiresCapability dependency condition and planner tests.
* Profiles use 99-fic.conf; ALT owned mode0400, other profiles0440. Sudo is now a required verified executable.
* Added native container-only production driver and provider/global gates; focused CMake builds for each platform. Preparation scripts updated for clean Debian12 runtime and ALT package metadata; newest runtime Containerfile changes have not been built yet.
* New tests cover durable-boundary recovery, fault/drift, changed requests, duplicate foreign include conflict, provider-witness switch before include, orphan-include no-record refusal and malformed journal route/fields. Existing configuration/rollback tests migrated.

## Validation
* Current targeted build: fic, global/provider/configuration/rollback/planner/platform/journal tests PASS.
* ctest --test-dir build-check -R '(sudo|mutation_journal|rollback_executor|policy_execution_planner|platform_profile)' --output-on-failure: 12/12 PASS. Additional changed-request recovery test rebuilt and PASS after this run.
* Native global gate PASS on Debian12 classic1.9.13p3, Debian13 classic1.9.16p2, Ubuntu24 classic1.9.15p5, Ubuntu26 classic1.9.17p2, ALT p11 classic1.9.17p2. Real policy apply, repeated apply/value refresh, native explicit EOF/include precedence, contextual coexistence, refusal of foreign suffix, independent/last rollback and exact main bytes verified.
* Logs: build-sudo-native/debian12/global-gate.log and build-sudo-native/min-{debian13,ubuntu2404,ubuntu2604,alt-p11}/global-gate*.log. Ubuntu26 classic log is global-gate-classic.log. Builds are platform-native Podman, not host binaries.
* sudo-rs behavioral native gate PASS (rust-behavior-gate.log): actual secure PATH/env filtering, password attempts3→4, cache timeout10/0, explicit EOF/include precedence, repeated apply, foreign suffix refusal and independent exact rollback. Classic sudo -l-based gate is inapplicable because rs does not show Defaults. Native rs later global timeout overrides earlier contextual timeout; classic precedence differs. See docs/sudo-native-validation.md.
* Earlier provider native probes PASS all six rows: real env_reset behavior, unsupported rs exempt_group syntax, multiline arguments/authorization and PASSWD; rs continuation inside arguments is rejected while command-list continuation preserves restrictions. Preserve specific-version admission.
* ALT native preparation: image restores RPM perms/owners, disposable root directory0755, exact /etc/sudoers.d/99-sudopw0400. Provider user probes use native control sudo wheelonly + fixture user wheel. Global gate adds a separate root query permission because packaged ALT grants no root commands. Host untouched.
* git diff --check PASS. Full final B/C matrix remains pending.

## Remaining
* A implementation/gates ready for commit: scalar native matrix, provider transition, 15 native process-crash boundaries per six rows (90 total), duplicate-include safe release conflict, provider-witness drift, changed-request recovery, journal malformed fields/route/backend rejection. Diff reviewed; commit A next, then B/C remain.
* Other RollbackFailed owner currently blocks reconcile; evaluate safe recovery/liveness without adopting foreign state. Applied clears previousLine; changed-request regression proves no stale transition evidence.
* Last release refuses a still-connected foreign duplicate include (keeps inert owned file + provenance). Added separator digest conservatively rejects modified prefix when original main lacked LF. Document/test these conflicts and scoped/auth interaction.
* B/C not implemented. Authentication remains old irreversible path and enrollment Unsupported; do not claim complete support. Need typed parser/wrapper/undo/recovery, both scoped/auth orders, provider-aware requested-policy rollback guards, and native all-platform gates before B/C commits.
* provider-transition-native-gate.sh PASS Ubuntu26 classic→rs→classic with safe env/exempt release, surviving other owner and exact last release. Docs scalar contract updated in rollback.md/fic README/architecture diagrams; review remains.
* Full project build PASS. Final CTest outside sandbox excluding two root-only tests PASS179/179; root-only display-manager and command-hash tests built/run Debian12 Podman with dropped DAC caps PASS2/2. Initial sandbox failures/skips resolved by suitable access. Final scalar+15 crash cases per six native rows and provider-transition gate rerun after orphan-include hardening: all PASS. Logs final-scalar*.log/crash-gate*.log/provider-transition-gate.log; full CTest /tmp/fic-sudo-final-ctest.log.
* Task containers/images are prefixed fic-sudo-native*. Clean up only owned task containers; never prune unrelated user images/containers. No pending tool sessions.
