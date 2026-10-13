# Current working state

## Current base
* Branch main; initial base cf0819dbf86414ffd856a6e0c8852616f5dbb42e.
* HEAD efbd679f16a913233524ba0ab30cd7752f6a2103 = commit A, Global Defaults ownership/provider capabilities. No push.
* B diff ready for final review/commit; user explicitly requires A/B/C commits only after their gates pass.

## Current task
* Complete SUDO A/B/C request (attachment e4f55516-ceba-4baf-984e-5b90472dd8ea/Вставленный текст.txt) and accepted provider clarification in docs/sudo-apply-rollback-design.md.
* A committed; B implemented/validated; C not started.

## Accepted architecture / invariants
* Five classic globals: fully owned99-fic.conf + canonical physical EOF FIC_INCLUDE, journal before mutation, ordered durable file→include, independent owners, inert→detach→validate→conditional delete on last release.
* Active provider/version/config/validator proof; unknown fails closed; no automatic alternatives switching. sudo-rs env_reset and unavailable exempt_group are VerifiedByConstruction, with no fake value/mutation. Classic exemption dependencies retained; provider-aware dependency condition; five scoped edges Recommended.
* Shared SUDO mutex. Scoped wrappers preserve exact bytes/digest/path/ID and existing recovery/topology protocol. Global ownership checks protect scoped apply/release without adopting global parameters.
* A failed global release on changed unterminated prefix is Conflict before writes. Source editors may preserve RollbackFailed global owners only when their exact target is physically proven; no journal resolution implied. Construction checks remain stricter. Restore scoped prefix, retry global release.
* All live security experiments disposable Podman only; never host sudo/PAM apply. Required six native rows: Debian12/13, Ubuntu24, Ubuntu26 rs+classic, ALTp11.

## Completed / changed areas
* A globals/include/provider/journal/rollback/planner implementation; scalar native+90 process-crash scenarios; provider switch safe artifact release. See docs/sudo-native-validation.md.
* B scoped policy uses provider/mode/mandatory validator, shared global proof before recovery and final journal transitions; rollback proves globals before/after release; no-record SUDO checks now share mutex (follow-up to A).
* Scoped transaction rejects wrappers of an unproven other policy before ownership resolution/mutation. Generic lower-level wrapper format remains unchanged.
* Extended native driver with actual scoped policy/transaction, status persistence on successful disable, failed-release journaling; scoped-native-gate.sh. Four apply/release orders, early/late global drift, unterminated prefix conflict recovery and unknown-owner regression added.
* B docs updated in rollback.md/architecture-diagrams.md/sudo-native-validation.md.

## Validation
* B full cmake --build build-check -j2 PASS (/tmp/fic-sudo-B-final-build.log).
* ctest --test-dir build-check -E '^(display_manager_transaction_tests|command_hash_batch_tests)$' --output-on-failure outside sandbox PASS179/179 (/tmp/fic-sudo-B-final-ctest.log).
* Root-only two targets rebuilt/run Debian12 Podman with DAC_OVERRIDE/DAC_READ_SEARCH dropped PASS2/2; build-sudo-native/debian12/root-tests-B-ctest.log.
* Scoped suite81 functions PASS; related configuration/rollback tests PASS after unknown-wrapper hardening.
* B native gate six rows PASS: classic7 checks each, rs8;43 total,24 apply/release orders, permissions/byte-exact rollback/drift/unknown owner. Logs scoped-gate*.log in build-sudo-native/{debian12,min-debian13,min-ubuntu2404,min-ubuntu2604,min-alt-p11}. Drivers compiled in matching distro containers.
* Native rs rejects unterminated original rules/main; tests assert failure BEFORE mutation and preserve bytes. Classic supports exact no-LF restoration.
* git diff --check PASS; final staged review/commit B next. No live tool sessions expected (interruption may have discarded process handles, all validation logs show completion).

## Remaining
* Commit B after final diff review, then implement C: typed authentication parser, exact original+active replacement wrappers, independent digest/path/ID proofs, durable multi-file journal/compensation/recovery, actual rollback/enrollment.
* Authentication currently old irreversible path, enrollment Unsupported. Do not claim completed task.
* C must coordinate both scoped/auth orders and rollback against OTHER REQUESTED policies, even when those have no mutation records. Inject requested-state checks through daemon registry/rollback deps; never restore a bypass contrary to enabled authentication or contextual suppression. Explicit Conflict allowed when independent release cannot be proven.
* Known sudo-rs command-list continuation preserves args/inherited tags; continuation inside arguments rejected. Do not normalize potentially widening rules or trust validator SUCCESS alone.
* Existing scoped SUDO marker namespace now rejects another policy name. Choose/prove authentication framing that cooperates with scoped transactions; no nested independent owners.
* Last global release refuses a still-connected foreign duplicate include (inert file/provenance retained). Other RollbackFailed owner blocks scalar reconcile; preserve fail-closed proof/liveness in C interactions.
* Native image preparation runtime Containerfile changes added in A match manual preparation but not yet separately rebuilt as recipes. ALT needs disposable root0755/exact99-sudopw0400 and native control wheelonly for user probes; never host repairs.
* Task containers/images prefixed fic-sudo-native*. Clean up only task-owned containers after final evidence; never prune unrelated user state. Full final C/native/docs/report remain.
