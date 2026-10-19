# Current working state

## Current base
* `main`, `d3bcba86614173d6b7143326df407794cdca8699`; initially clean. One research/test completion commit requested over this base, no push.

## Current task
* Completed native real-OpenSSH end-to-end research on Debian12/13; no production integration or fixes.

## Accepted architecture / invariants
* Production activator/SSH/ownership/rollback/MutationJournal/packaging remain unchanged. Stock container ssh.service units/drop-ins unchanged; host SSH never called or mounted into runtime containers.
* A = declared snapshot inputs; B = verified new real sshd; full C = SSH effective semantics. A+B do not prove C. `C_selected` records only bounded fixture observations; full C normal positives NOT_PROVEN, demonstrated counterexamples FAILED.
* Private-root Docker topology accepted without new boundaries; shared-root provisioning still BLOCKED_BY_MOUNT_TOPOLOGY. Existing private/non-shared-slave/peer protections unchanged.
* Research uses fresh synthetic config/env/key files, initial empty stock Include directory. Nonempty Include tests use explicit fresh /etc/ssh/fic-native-inputs because stock OverlayFS directory copy-up triggers existing noXattrs refusal. Not a production workaround.

## Completed / changed areas
* `tests/integration/verified_config_service/openssh_native/`: guarded Docker runner, production-source C++ driver, safe input preparation/diagnostics/Include analyzer/network tests, exact-source collector, sanitized evidence collector, README and native-only image recipe.
* Real public activate() on stock ssh.service: new MainPID/InvocationID/starttime, READY, stable launch contract, successful cleanup and live loopback server identification + KEXINIT. Auth/full KEX intentionally absent.
* 29 expected scenarios per Debian: positive/nested/Match/missing Include, wrong SHA/missing/env/symlink, external/glob/CLI semantic counterexamples, syntax/restart/contract/inode/RO/original-FD/ABA/EBUSY/foreign/SIGKILL/no-READY. Residual repeat refusal; explicit fixture-admin cleanup only.
* New no-READY test synchronizes real sshd FIFO reader with pipe barrier and captures activating/start MainPID before timeout. Post-probe errors never overwrite ActivationResult. Results tied to runner identity hash to reject stale evidence.
* `tests/CMakeLists.txt`: safe read-only Python harness contract in normal CTest. Report + JSON: docs/verified-config-openssh-native-{validation.md,evidence.json}.

## Validation
* Final Debian12/13 OpenSSH runners exit 0: each 29 PASS / 0 FAIL / 0 SKIP, unit bytes unchanged, restored sshd -t PASS. Logs build-openssh-native/logs/{debian12,debian13}-final.log; raw sanitized results/mountinfo under each profile/evidence.
* Existing standalone native matrix: Debian12/13, Ubuntu24.04/26.04, ALT all 132 PASS / 0 FAIL / 0 SKIP. Ubuntu26 first loaded run refused a mount event; fresh final run PASS, no assertion/observer/retry changes. Logs regression-*.log (Ubuntu26 final suffix).
* Full Debian12 configure/build PASS, full CTest 187 PASS / 0 FAIL / 1 expected native opt-in SKIP (188 total, 177.92s). Log full-debian12.log. Final harness CTest/self-test and bash syntax PASS.
* Full build uses existing build-env-full-debian12, source RO, Docker fic-ssh-audit:debian12, no network, -j6, offscreen Qt, DAC_OVERRIDE/DAC_READ_SEARCH dropped; safe.directory only inside container, build-root owner restored.
* Exact Debian OpenSSH sources downloaded, archive SHA/size checked, distro patches applied. Descriptor hashes pinned; PGP signer keys unavailable (NOT_VERIFIED). WSL kernel OverlayFS source inspected for size-only vs actual-name filtering.
* Collector stale-run fault injection PASS (wrong run_id rejected before writing report).
* Production diff against base empty; git diff --check PASS. Caller SSH files/unit paths stayed absent. All five userspaces share 6.6.87.2-microsoft-standard-WSL2, not separate kernels.

## Remaining / next tasks (not implemented)
* Requested research complete. No pending implementation work for this task.
* Reproduced compatibility blocker: copied-up OverlayFS file/dir flistxattr size query=23, actual bounded list=0; existing noXattrs rejects. Separate future task: bounded actual-name retrieval + metadata stability, retaining rejection of real xattrs/ACL/labels.
* Before policy integration: SSH-specific authority/argv/Include/negative-glob closure adapter, safe shared-root deployment boundaries, split persistent/runtime results and ownership-safe CAS recovery using existing transactions/journal.
* NOT_TESTED/NOT_PROVEN: VM/distro kernels, authenticated Match/PAM/login, full KEX/host-key client verification, arbitrary vendor/Include/argv/dependency closure, enforcing SELinux/ACL providers, executable rebuild/PGP signing-chain proof, privileged hidden ABA and post-cleanup permanent protection.
