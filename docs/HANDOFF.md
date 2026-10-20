# Current working state

## Current base
* `main`; task base `4d1bafb17f9c391bdfec693143632cf3928341fa`, initially clean. One production completion commit requested, no push.

## Current task
* Stage 1 SSH mutation provenance R1/R1b completed; final frozen-code native/full gates passed. One completion commit, no push.

## Accepted implementation / invariants
* Internal typed transaction facts separate original write (Unknown/NotInstalled/Installed/DurableInstalled), compensation, original/restored legacy runtime and original/restore writer-issued AtomicTargetState receipts. No fresh capture legitimizes an external revision.
* `mayDiscardPrepared(freshRecord)` permits only fresh failed NotInstalled/no receipts/no compensation/no runtime effects. Any installed/unknown write retains Prepared, even durable file restore + LegacyAccepted reconciliation: legacy commands do not prove complete runtime resolution.
* REFRESH requiring re-prepare of active SSH identity refuses before prepare/write, preserving Applied ID/full payload and existing foreign bytes; compliant no-op/fresh apply remain. No half previous/target protocol, no ID concatenation/schema upgrade.
* Any Prepared for the shared SSH config gates apply of all its policies. `finishPrepared` removed: no blind reload, marker-only commit, absent-artifact discard, stale-value activation or new duplicate mutation. Explicit existing administrative rollback routes are not replaced by new automatic recovery.
* Existing conditional CAS restore/symlink/metadata/durability protections remain. Negative state recheck after restore prevents reload of already-drifted restored state; legacy bool projection retained for rollback. No generic/adapter/MutationJournal/schema/incident/platform changes.

## Completed / changed areas
* Production only `fic/src/modules/net/ssh/{Ssh.cpp,SshConfigTransaction.h,SshConfigTransaction.cpp}`.
* Existing SSH test executable: 43 cases, 17 nested transaction/journal fault outcomes; actual file/markers, durable IDs/status/full payload, foreign content, retry behavior and runtime calls checked. Recovery assertions intentionally strengthened, not skipped.
* Test-only save-outcome observation seam (`FIC_SSH_TRANSACTION_TESTING`), compiled out of production fic.
* Shared 96-source CMake list extracted unchanged for root/focused native target; native also includes root's existing late Sudo authentication dispatcher dependency. Root CTest still same target. New `tests/integration/ssh-provenance` runner/README avoids Qt and host SSH.
* Design document §22 describes implemented Stage 1; older audit remains historical. Coordinator/checkpoints/grants/public Deferred stay future work.

## Validation
* RED at original production HEAD: all three permanent R1/R1b tests fail by lost journal records (fresh, REFRESH pre-install and post-install). Log `/tmp/fic-ssh-stage1-red.log`.
* GREEN typed matrix: 14 transaction faults + 3 journal persist faults; separate policy-level unknown receipt, install/restore durability, cross-policy/changed-value retry guards and malformed journal tests. No sleep races.
* Initial completed native gates Debian12/13, Ubuntu24.04/26.04, ALT p11 each 43 PASS/0 FAIL/0 SKIP; identical complete SSH fixture executable, fake runner, no real SSH/systemd changes. Final frozen-code repetition after success-flag ordering review also passed. Logs `build-ssh-provenance/<row>/native.log`.
* Full Debian12 configure/build + full CTest completed: 188 PASS/0 FAIL/1 expected generic native opt-in SKIP (189 total), 173.24s. Final frozen-code configure/build/CTest also PASS: 188 PASS/0 FAIL/1 expected SKIP, 171.22s; `/tmp/fic-ssh-stage1-full-debian12-final.log`.
* Initial matrix setup issues (missing Qt, focused CMake Threads/link dependency, Ubuntu26 runner git assumption) fixed without distro SKIPs; automatic permission review timeouts retried successfully. No package installation/host SSH operations.
* Shared source-list equivalence checked (96 original entries); production fic symbol scan confirms no save-outcome test setter. `git diff --check` PASS.

## Remaining / limitations
* No unfinished Stage 1 work. Final diff reviewed and `git diff --check` clean; no push.
* Full safe REFRESH (R2), wrapper body fingerprints (R3), shared locking (R4) and unchanged scalar compliance (R5) remain separate stages. R2's unsafe admission is blocked, not implemented as a full transition.
* Schema 2 cannot distinguish failed compensation/crash runtime histories; unresolved Prepared requires explicit administrative resolution. A restored file may leave all SSH apply for that config blocked; this is intentional until typed durable recovery exists.
* Legacy value-change release→fresh apply and rollback behavior remain; no verified activation/coordinator/service checkpoints/authority grants/public API migration. No live SSH/PAM/native activation claim; five userspaces on one WSL2 kernel, not five distro VM kernels.
