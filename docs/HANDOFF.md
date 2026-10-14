# Current working state

## Current base
* main; current commit HEAD is C: `SUDO: reversible authentication ownership and native provider gates`.
* Initial base cf0819dbf86414ffd856a6e0c8852616f5dbb42e; A efbd679f16a913233524ba0ab30cd7752f6a2103; B14863e2df38b66a90c8a70fe29a5cc49caf5201f.
* A/B/C complete; no push. Resolve exact C hash with git log -1.

## Current task
* SUDO apply/rollback A/B/C request and provider clarification completed. No next refactor authorized.

## Accepted architecture / invariants
* Global Defaults: independent journal owners in nonce-bound99-fic.conf + physical EOF FIC_INCLUDE; durable file→include; last release inert→detach→native proof→conditional delete. Foreign duplicate connection or changed unterminated prefix yields Conflict.
* Actual active provider/version/config/validator, unknown fail closed; never automatic alternatives. Proven sudo-rs env_reset/exempt_group guarantees VerifiedByConstruction, no fictitious field/mutation. Classic authentication exemption Required dependency retained conditionally; five scalar→scoped edges Recommended.
* Shared SUDO mutex; FIC_AUTH and FIC_SUDO_DISABLED independent, no nesting. Requested other policy guards release even without a mutation record. Persistent DAC config intent is authoritative, absent/invalid status fails closed.
* Authentication edits only typed physical NOPASSWD/!authenticate tokens. Original/replacement independently hashed, replacement re-derived on every parse; source path/ID proofs include detached paths. Preserve tags/arguments/Runas/negation/aliases/continuations/eol bytes. Unknown grammar refuses before writes.
* Multi-file Prepared/CAS/native/semantic/topology/durability proof; selective compensation preserves foreign changes, unresolved ownership retained on ambiguity. Pre-restore structural proof may omit syntax so rejected native candidate is compensatable; native proof mandatory after restore and before journal resolution.
* All real sudo/PAM/user/alternatives validation disposable Podman only, no host security mounts/apply.

## Completed / changed areas
* A: global container/include/provider/dependency/journal lifecycle. B: scoped shared-resource protection and provenance. C: AuthenticationGrammar/Wrapper/Transaction + typed UndoReleaseSudoAuthentication, byte-coordinate renderer, production apply/rollback/no-record checks; enrollment Supported.
* Removed old irreversible auth mutator. Scoped mechanics rejects auth overlap/reused IDs. Production dispatcher tests verify Conflict on requested no-record scope, RollbackFailed retry, exact restore, NothingToDo and orphan refusal.
* Native auth driver/gates include password/argument semantics, mixed/inherited tags, aliases/Runas/nested includes, foreign comment, classic CRLF/no-final-LF, both scoped/auth orders, requested no-record guards,5 process cuts per row and classic↔rs transitions. Docs/README/design/platform report current.

## Validation
* Final configure/full build PASS; /tmp/fic-C-complete-configure.log and /tmp/fic-C-head-build.log.
* Final non-root full CTest181/181 PASS outside sandbox; /tmp/fic-C-head-ctest.log. Root-only command_hash_batch_tests + display_manager_transaction_tests rebuilt/run Debian12 Podman with DAC_OVERRIDE/DAC_READ_SEARCH dropped PASS2/2; build-sudo-native/debian12/root-tests-C-{build,ctest}.log. All183 cases in appropriate environments, not one root fullCTest.
* Grammar20 checks, lifecycle17 cases; full dispatcher cases PASS (/tmp/fic-C-dispatcher-cases.log).
* Six auth native rows PASS: D12classic1.9.13p3, D13classic1.9.16p2, U24classic1.9.15p5, U26classic1.9.17p2, U26rs0.2.13-0ubuntu1.2, ALTp11classic1.9.17p2. Auth86 checks +2 provider transitions,0 FAIL0 SKIP;30 actual process crash cases.
* A/B regression gates repeated latest driver all6 rows: provider27, scoped43, global40, rs behavior9, global transition2 and90 process crash cases PASS.25 gate processes exit0. Detailed commands/counts/versions in docs/sudo-native-validation.md.
* Logs C-{configure,build}.log, C-auth-gate*.log, C-auth-transition.log, C-regression-*.log under build-sudo-native/{debian12,min-debian13,min-ubuntu2404,min-ubuntu2604,min-alt-p11}. Final runners /tmp/podman-fic-C-final-auth-matrix.log + final-ubuntu24.log; regressions /tmp/podman-fic-C-regressions.log. All gate processes finished, --rm containers.
* Earlier sandbox/NSS/socket failures resolved by outside-sandbox validation. Auto-review timeouts resolved on retry; background runner holds shell with wait, bare shell exit0 was not completion evidence. Native-invalid rs!authenticate/CRLF and includedir directory fixtures corrected as test inputs, with negative refusal cases retained; production was not relaxed.
* Final diff reviewed and git diff --check PASS. C committed after all required gates; no push.

## Remaining / known limits
* No required unfinished work. Unknown provider/version and unsupported parser subset fail closed (additional Host_Spec, command digests/regex, single quotes, ambiguous whitespace lists/unquoted parentheses). See rollback.md.
* sudo-rs rejects authenticate and CRLF Defaults; LF/NOPASSWD supported independently. Safe command-list continuation proven for actual rs version; argument continuation remains native-refused. Never normalize unsupported source to pass validation.
* Conditional atomic writer is not kernel-atomic CAS against arbitrary non-cooperating writers. Process crash gates are not physical power-loss experiments; durability primitives/fault injection separately checked.
* Earlier OCI runtime Containerfile recipes match manual preparation but were not rebuilt separately as recipes. Existing task-owned prep containers/images may remain; never prune unrelated user state. Host security configuration untouched.
