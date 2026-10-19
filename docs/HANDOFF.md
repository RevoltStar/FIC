# Current working state

## Current base
* `main`, task base `692d34a6f6b3595e088b30b35ced4193b6be77fd`; initially clean. One completion commit, no push.

## Current task
* Bounded xattr enumeration fix for VerifiedConfigServiceActivator; implementation and requested validation complete.

## Accepted architecture / invariants
* Production changes only `VerifiedConfigMountSupport.cpp/.h`; no SSH policies, launch/systemd contracts, ownership, apply/rollback, journal, public API, mount publication/observer/readiness/cleanup changes.
* No xattr preservation/filter/removal. Actual bounded FD list must be empty; all errors including ENOTSUP fail closed. Root/effective CAP_SYS_ADMIN in initial user namespace required for trusted-name visibility; namespace verified through proc/nsfs and reserved initial inode.
* Second actual list after capture, existing stat/identity/CAS checks retained. This is not atomic exclusion of privileged/coarse-clock ABA; kernel/filesystem/LSM visibility assumptions are explicit. ACL/security labels remain unsupported.
* Historical OpenSSH report/JSON preserved. A+B do not prove full SSH semantics C; fixture C_selected remains bounded.

## Completed / changed areas
* MountSupport: fixed 65536-byte actual-list enumeration instead of size-query; no retries, allocations based on returned size or sensitive-name diagnostics; second-list presence gives InterferenceDetected.
* Unit coverage: sizes 0/1/23/65536/65537, actual overlay-looking names refused, no size-query/retries/name leak, error errno matrix.
* Existing native suite: real user/trusted/security.capability/access+default ACL on file/dir OverlayFS/tmpfs, zero values, many names, deterministic appearance/replacement/removal/ACL/content/path races, capability/userns refusals, actual stock lower-layer copy-up + verifyTree/RO snapshots.
* Real SSH harness: removed fresh-main/env/new-Include-dir workaround; stock copied-up main/env + nonempty stock Include exact manifest public activation added; previous scenarios unchanged.
* Docs: activator API/security review, historical report follow-up, compact new `docs/verified-config-xattr-evidence.json` (old JSON unchanged), harness README/collector.

## Validation
* `bash tests/integration/verified_config_service/run-native.sh fic-ssh-audit:<tag> <profile>`: Debian12/13, Ubuntu24.04/26.04 each 201 PASS / 0 FAIL / 0 SKIP; ALT p11 200 PASS / 0 FAIL / 1 SKIP (stock empty SSH Include copy-up fixture absent). All real attribute/ACL/security/userns cases ran on ALT too. Logs `build-verified-config/xattr-<tag>-final.log`.
* Stock file+directory in both Debian/Ubuntu: before size/actual 0/0, after normal copy-up 23/0; verifyTree + full RO snapshot PASS.
* `bash tests/integration/verified_config_service/openssh_native/run-native.sh fic-ssh-audit:debian{12,13} debian-{12,13}`: each 30 PASS / 0 FAIL / 0 SKIP. New public stock-copy-up case confirms new MainPID/InvocationID, READY, cleanup/no residuals. Unit bytes unchanged; restored sshd -t PASS; caller SSH untouched. Logs `build-openssh-native/logs/xattr-debian{12,13}.log`.
* Collector current evidence validation PASS; full sanitized current output `build-openssh-native/xattr-followup-full.json`; compact tracked artifact includes run/image identities, cases and log hashes.
* Docker Debian12 full `cmake -S /src -B /build -DFIC_TARGET_PLATFORM=debian-12`, `cmake --build /build -j6`, offscreen full CTest: build PASS; 187 PASS / 0 FAIL / 1 expected native opt-in SKIP (188 total, 125.69s). Source RO, no network, DAC_OVERRIDE/DAC_READ_SEARCH dropped; build-root owner restored. Log `build-verified-config/xattr-full-debian12.log`.
* Final `cmake --build /build --target verified_config_service_tests -j4` and `ctest --test-dir /build -R "verified_config_service_tests|openssh_native_harness_contract" --output-on-failure`: 2/2 PASS (0.07s), log xattr-unit-final.log. Python harness --self-test and git diff --check PASS. Production diff reviewed and restricted to xattr validation.

## Remaining / limitations
* No remaining implementation for this task. No push.
* All userspaces ran on one WSL 6.6.87.2 kernel; ext4/XFS/SELinux-enforcing/native distro VM kernels NOT_TESTED; no host block devices formatted. Unknown metadata-hiding providers are outside supported trust model; empty list is not universal security metadata attestation.
* SSH Include/argv authority closure, authenticated login/full KEX, hidden privileged ABA and permanent post-cleanup protection remain separate tasks.
