# Current working state

## Current base
* `main`; task base `01694bc47d1ced9d393aa61181b02a49653ed352`, initially clean. One completion commit requested, no push.

## Current task
* SSH Verified Activation Adapter persistent metadata proof hardening; completed; one completion commit, no push.

## Accepted architecture / invariants
* Authorized SHA/exact manifests remain caller input. Immutable initial Capture is operation-local identity/metadata evidence, never a desired reference or ownership record.
* P requires both authorized bytes/manifests and stable roots/entries: exact keys, mount/dev/inode/type/mode, UID/GID, nlink/size/mtime/ctime; ignore atime. Unsupported/unreadable capture => NotProven; observed mismatch => NonCompliant.
* Private HostKey: root regular 0600/0400 only, no special bits/symlinks/xattrs/ACL, trusted parents. Reuse validateClosure().hostKeys; companion .pub may be 0644.
* A/B/C/P separate; retain original B including CleanupFailed/primaryStatus/READY/errors/residuals. Runtime success + observed persistent drift => RuntimeActivatedButPersistentDrift; no compensation/restart/extra cleanup.
* Generic engine/public API, SSH policy apply/rollback, ownership and MutationJournal unchanged. Existing accepted launch/Include/env/executable/readiness boundaries remain.

## Completed / changed areas
* service/ssh/SshVerifiedActivationAdapter.cpp and internal SshPersistentMetadata.h: compare initial/final evidence; FD-based bounded readTree plus visible-root identity recheck; final digest uses bytes from that same capture. Errors acquiring metadata cannot establish a mismatch.
* Unit tests: 145 contract checks, including metadata/map keys, SHA/manifest, atime, P error classification, private key modes and existing exact policy values/bounds/IDs.
* Existing real OpenSSH harness: 11 new deterministic metadata cases per Debian; preopened FD mutation after Watching, original Include child replacement with unchanged bytes. Protected-window ssh-keyscan before cleanup; old handshake assertions unchanged.
* Adapter docs and historical native report follow-up; new sanitized ssh-verified-activation-metadata-evidence.json preserves historical evidence.

## Validation
* Real OpenSSH Docker Debian12/13 final gates: each 30 old generic + 41 adapter PASS, 0 FAIL/SKIP; six metadata-only drift cases each preserve A/C Proven, B Success, P NonCompliant. Added post-publication xattr => P NotProven/B Success; initial unsafe key mode/xattr/ACL refuse before engine; 0400 key/.pub0644 stable success.
* Final logs: build-openssh-native/logs/metadata-debian{12,13}-final.log. Evidence collector checks 41 unique adapter cases, 6 overall Success/8 drift, actual metadata-only unchanged bytes, protected handshakes/listeners, runner IDs, unchanged unit/caller SSH and restored sshd -t.
* Generic standalone Docker: Debian12/13 201 PASS/0 SKIP each; Ubuntu24.04/26.04 202 PASS/0 SKIP each; ALT p11 201 PASS/1 existing stock Include copy-up SKIP. Ubuntu26.04 first run stopped on existing observer InterferenceDetected; unchanged full repeat PASS (metadata-ubuntu2604-repeat.log). No assertions weakened.
* Full Debian12 build PASS. First full CTest: one new unit fixture failure (manifest bytes changed without corresponding metadata map); corrected fixture, direct final unit executable 145 PASS. Final full configure/build + CTest PASS: 188 PASS, 0 FAIL, 1 expected native opt-in SKIP, 189 total, 184.97s; build-openssh-native/logs/metadata-full-debian12-final.log.
* harness.py --self-test, sanitized evidence collector, git diff --check PASS.

## Remaining / limits
* No unfinished implementation. Fourteen-point security review recorded in the native report; final diff reviewed. No push authorized.
* One WSL2 kernel, not distro VM/kernel matrix. Momentary post-cleanup P, no post-return monitoring; hidden privileged/coarse-ctime ABA and race after last check remain documented.
* READY/selected-policy C do not prove later connections/authentication/PAM semantics. Debian12 can reread unsafe original key after cleanup; new handshake is therefore measured while snapshot is published. Debian13 ssh-keyscan banner goes to stdout, Debian12 stderr; both formats verified from cached exact sources.
