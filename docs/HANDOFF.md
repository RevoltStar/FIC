# Current working state

## Current base
* `main`, task base `3a6029586f96e3896093901d6f62ed923a543b65`; initially clean. One completion commit requested, no push.

## Current task
* SSH-specific verified activation adapter v1 completed; independent production component, not called by SSH policies.

## Accepted architecture / invariants
* Caller supplies authorized reference SHA/manifests and selected policy expectations; observed files never become desired references/ownership automatically.
* Debian12/13 only: stock ssh.service notify/main, exact sshd -D $SSHD_OPTS and sshd -t Pre with stock root User/Group, existing explicit empty /etc/default/ssh, no env overrides/drop-ins. Entire Match rejected; conservative ASCII Include grammar, protected exact glob roots/negative sets.
* User approved internal activateWithProof entrypoint in the SAME generic perform engine, replacing literal public-function call for adapter. Public generic API unchanged. Bind expected launch/source identity/attributes before mounts; validate published RO semantics before restart; verify ready executable; retain existing observer/readiness/cleanup.
* A/B/C/P separate. C Proven only for request.policies; no full SSH/auth/PAM proof. B original status/primary/READY/cleanup/residuals preserved. Runtime success + P mismatch is RuntimeActivatedButPersistentDrift; no compensation/reload.
* Existing SSH policies, runtime/audit/syntax implementations, transaction/rollback, ownership and MutationJournal unchanged. No new journal/ownership source.

## Completed / changed areas
* service/ssh/: adapter API/implementation, pure bounded reference/Include/env/profile classifiers; test-only access header excluded from production.
* service/VerifiedConfigActivationProof.h and generic activator internal checks/callbacks. Snapshot/restart/cleanup engine not duplicated.
* Existing root/standalone native CMake, new SSH adapter unit target, old native suite's unsupported-profile negatives; real OpenSSH harness retains old 30 cases and adds 30 independent adapter cases per Debian.
* New docs/ssh-verified-activation-adapter.md and compact evidence; appended historical native report and generic docs, updated native README/collector. Historical JSON evidence unchanged.

## Validation
* `bash tests/integration/verified_config_service/openssh_native/run-native.sh fic-ssh-audit:debian{12,13} debian-{12,13}`: each 30 old generic + 30 new adapter PASS, 0 FAIL/SKIP. Five real overall adapter Success, two distinct runtime-success/persistent-drift outcomes. New MainPID/InvocationID, real READY, loopback socket-to-new-MainPID, cleanup, unchanged unit bytes/caller SSH and restored sshd -t verified.
* Managed beforeActivation/Watching/RestartQueued barriers cover source SHA/inode/mode/directory identity, new glob, manager contract before/after; no restart for pre-restart detection. CLI/env/Match/include/symlink/unknown-policy/untrusted-sshd preflight negatives; real EBUSY preserves primary Success without overall Success.
* `bash tests/integration/verified_config_service/run-native.sh fic-ssh-audit:<tag> <profile>`: Debian12/13 each 201 PASS/0 SKIP; Ubuntu24.04/26.04 each 202 PASS/0 SKIP; ALT p11 201 PASS/1 SKIP (existing stock empty SSH Include copy-up fixture unavailable). 0 FAIL. Unsupported-profile cases use ssh.service and assert exact distro refusal diagnostic before capture/mount/restart.
* Docker Debian12 full configure/build (-j6, source RO, no network, dropped DAC_OVERRIDE/DAC_READ_SEARCH), full CTest: 188 PASS, 0 FAIL, 1 expected native opt-in SKIP, 189 total, 129.55s. Initial native target link error fixed by adding adapter sources; final full gate PASS.
* Final full rebuild after native test assertion refinement PASS; CTest -R 'ssh_verified_activation_tests|verified_config_service|openssh_native_harness_contract': 3 PASS/1 expected native SKIP. Python harness --self-test, evidence collector and git diff --check PASS.
* Review found std::filesystem path equality accepted doubled slash; dedicated regression failed before fix, strict native-string normalization fixed it. Final full build/CTest and both 30+30 Debian real gates repeated successfully after fix and final root-credentials/reference-limit checks. Timeout arithmetic follows validation; unknown object kinds fail before capture.
* Logs: build-openssh-native/logs/ssh-adapter-debian{12,13}-final.log; build-verified-config/ssh-adapter-<tag>-final.log, ssh-adapter-completion.log, ssh-adapter-targeted-final.log. Full sanitized collection: build-openssh-native/ssh-adapter-full-evidence.json; tracked compact artifact includes run/image identities/log hashes.
* Exact cached Debian OpenSSH source trees inspected: servconf Include/glob/cache, scalar first-wins/additive Port. Real binaries verify subset; no claim of executable rebuild/signing-chain attestation.

## Remaining / limitations
* No remaining implementation for this task; do not integrate into SSH apply automatically. No push.
* All userspaces share WSL 6.6.87.2, not independent distro kernels/VMs. Arbitrary Match/options/includes, authenticated login/full KEX/PAM, hidden privileged/coarse-clock ABA and permanent post-cleanup protection remain outside proof.
* Assumes trusted OS/kernel/loader/libraries and established executable hash store. Explicit HostKey/private+pub reference coverage required; no secret bytes exported. Unsupported unknown dependencies fail closed.
* Future transaction wiring must derive references from existing durable authorized backend state, preserve ownership/CAS and distinguish saved/applied/runtime/persistent outcomes; no migration or alternate journal path added here.
