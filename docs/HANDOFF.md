# Current workspace

## Current base
* Branch main; follow-up base a7c22005cb30ec4d92f9dad9731fd9e8f0ce6614. This snapshot belongs to the single `fix(sssd): tighten I1 identity and admission race proofs` commit. No push.

## Current task
* Attachment 44148bba: I1 follow-up — ALT effective consumer identity, genuine nested-mount gate, deterministic first-admission TOCTOU. Completed; do not start I2/I3 automatically.

## Accepted architecture / invariants
* Production I1 is read-only observation, no service jobs, mount/write/journal/ownership authority or policy callers. No completed A/B/C/P, runtime receipt, ConfigDB-generation or authentication-success claim.
* Existing generic PIDFile restrictions, SSH activation, SSSD policy/runtime/rollback and package lifecycle unchanged. Full bounded `/etc/sssd` scan retained; optimistic revalidation is not a linearizable/privileged-ABA guarantee.
* Closed ALT profile requires explicit effective `[sssd] user=_sssd`, including absent services. Missing/root/unknown user Unsupported. Packaged privileged-control alternatives are outside this profile, not an ALT OS defect. Debian/Ubuntu optional-user rules unchanged.

## Completed / changed areas
* service/sssd: factored existing identity check into pure helper, required ALT user before services early return. Initial admit has operation-local FIC_SSSD_I1_TESTING-only checkpoint after initial launch/env/UnitPath observations and before final confirmation. Production sequence otherwise unchanged.
* tests/fic/service/SssdInputClosureTests.cpp: missing-user platform distinction, ordered effective identities with/without services.
* tests/integration/sssd-i1: first-admit control/unit-comment/env-bytes/env-inode/absent-env-create/unloaded-dropin injections; no timing sleeps. Older systemd's precise UnitPath Unsupported refusal retained, not coerced into InterferenceDetected.
* Genuine nested tmpfs fixture: root:root mode0700, empty, independently different fdinfo mount ID, exact mount-boundary diagnostic, finally unmount. Generic reader/check order unchanged.
* ALT persistent-input gates retain original active monitor; native lazy responder independently reproduces missing/root exit3 with active monitor, effective _sssd startup and unknown-user failed monitor. Nonexistent-user PAM failure is not authentication success.
* New evidence generated from actual five native reruns. Source review includes patched ALT monitor defaults/bus identity, PAM unit template and packaged config hashes/excerpts; monitor hash agrees with unchanged R1. Exporter preserves measured launch fixtures by default. Historical R1/R2 and existing launch-fixtures byte-identical to base.
* Authoritative boundaries in docs/sssd-native-compatibility.md and docs/sssd-verified-activation-design.md; harness README updated.

## Validation
* Native runner exit0 on all five, real systemd PID1, stock packages, disposable Docker, network none/loopback, no runtime host binds, different mount namespace. 40 retained observations each on Debian/Ubuntu, 55 on ALT. No leftover I1 containers.
* Debian12 SSSD 2.8.2-4+deb12u1/systemd252.39-1~deb12u2; Debian13 2.10.1-2+b1/257.13-1~deb13u1; Ubuntu24 2.9.4-1.1ubuntu6.8/255.4-1ubuntu8.18; Ubuntu26 2.12.0-1ubuntu5.5/259.9-0ubuntu0.1; ALT 2.9.8-alt3/258.9-alt1.
* `cmake --build /build --target fic sssd_input_closure_tests ssh_verified_activation_tests verified_config_service_tests sssd_uninstall_inspection_tests -j2` PASS in fic-sssd-i1:full (Debian12), source RO/build RW. Production admission object nm/flags confirms no test entrypoint/callback parameter/definition. Log build-sssd-i1/full/followup-build.log.
* `ctest --test-dir /build -R '^(sssd_input_closure_tests|sssd_i1_evidence_checks|sssd_uninstall_inspection_tests|sssd_research_evidence_checks|ssh_verified_activation_tests|verified_config_service_tests|ssh_policy_static_checks)$' --output-on-failure`: PASS 7/7, 0.39s. Log build-sssd-i1/full/followup-tests.log.
* Existing identity_configuration_editors_tests, identity_concrete_policies_tests, ssh_runtime_tests, ssh_apply_rollback_tests rebuilt and CTest PASS 4/4, 3.32s. Logs build-env-full-debian12/i1-followup-regression-{build,tests}.log.
* collect-evidence.py and check-evidence.py PASS; Python AST/bash syntax included. git diff --check PASS. Native raw reports/container metadata: build-sssd-i1/<platform>/native; export tests/integration/sssd-i1/evidence.json. Ordinary CTest never launches privileged native gates.

## Remaining / limits
* No unfinished follow-up components. Full project build/full CTest not repeated; focused production/test builds and related regressions passed.
* I2 semantics/domain/default/provider/relation interpretation and I3 protected negative dependencies, PIDFile/precommand/metadata handling, responder generation, activation/readiness/P/cleanup remain unimplemented. I1 still needs revalidation at future I3 boundaries.
* Native Docker/WSL shared-kernel observations do not certify other kernels, bare metal, Podman, enforcing LSM or real AD/IPA/authentication. Initial-user-namespace CAP_SYS_ADMIN/xattr visibility and narrow ASCII/closed launch/profile boundaries remain.
