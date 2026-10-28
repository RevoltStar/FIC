# Current workspace

## Current base
* Branch main; task base d1b00069aa9982fea3d7a34ea11eeaabe1c3604b.
* R1 commit 696a4575e55b125617613fa212317c5b76636151. This snapshot belongs to the second R2 research commit; no push.

## Current task
* SSSD research R1 + R2 (attachment b6926bcd) completed as bounded research. Production integration/policies/journal were not implemented. Do not begin I1–I6 automatically.

## Accepted architecture / invariants
* Docker explicitly authorized instead of Podman; real stock SSSD/systemd PID1, disposable privileged runtime with network none/loopback only, no host binds/ports/security changes. Five userlands share WSL kernel.
* Future integration reuses existing engine; one FIC-owned zzzz-fic.conf, per-policy keys, offline→cache Recommended, never Required. Generic snapshot/notify Success is not consumer/P proof. No adoption, uncertain Prepared promotion, foreign rollback restore or automatic cache deletion.
* Preserve native config/runtime/functional vs source proof levels. Inconclusive/unsupported/unexecuted findings remain explicit.

## Completed / changed areas
* R1: native package/unit/input/READY/source audit all five, RO metadata, actual generic probes, admission and deterministic race counterexamples; 190 named observations. Debian13/Ubuntu26 demonstrate snapshot+notify success, older three reject nonempty stock PIDFile. TriggeredBy is empty on all five (precision clarified in R2).
* R2: 273 observations, native six-combination LDAP/proxy relations all five, ranges/defaults/domain and lazy responder fixtures. Real TLS LDAP/native pam_sss online/offline password auth all five, wrong-password negative control, cache false/re-enable, synthetic aged expiry 1 reject/0 accept, online cached old password while LDAP rejects it, lastLogin vs lastOnlineAuth distinction.
* LDAP rejects conflict with EINVAL despite config-check success; proxy accepts. AD/IPA source loads separate options, lacks the same LDAP relation check; failed no-directory constructors do not prove functional support. Source inheritance of cache bool is not a dynamic-trust runtime receipt.
* ALT root monitor fixture leaves stock _sssd lazy responder failing while monitor active; packaged user=_sssd fixture succeeds. Both captured, no OS defect claimed. Discovery-based lazy tests account for absent priv socket on Debian13/Ubuntu26.
* Authoritative docs: sssd-native-compatibility.md, sssd-verified-activation-design.md, sssd-policy-semantics.md, sssd-domain-scope-design.md, sssd-cross-policy-validation-design.md (detailed I1–I6 components/journal/tests/risks).
* Evidence JSONs in docs; exact distro archive/patch hashes and numbered source excerpts in tests/integration/sssd-research/source-r1.json and source-r2.json. Repro README, native scripts and CI evidence guard there. No production changes.

## Validation
* Actual generic research target built all five; R1/R1_MORE/R1_ABSENT and R2/R2_AUTH/R2_LAZY collected all five. Final negative-control auth and ALT root/user switch repeated successfully. All disposable runtime containers removed.
* Debian12 full project configure PASS; affected identity_concrete_policies_tests, identity_policy_hierarchy_tests, rollback_executor_tests, sssd_uninstall_inspection_tests targets rebuilt/up-to-date. Targeted CTest plus sssd_research_evidence_checks PASS 5/5 (final 4.14s); final guard rerun after evidence export. Full project build/full CTest intentionally not repeated for research-only changes.
* Python AST, shell syntax, JSON/evidence assertions and git diff --check PASS. Source exports regenerated from exact distro sources. Initial fixture EXDEV/config_file_version issues and concurrent runner-edit harness errors were corrected; final native runs replaced those failed collections.

## Remaining / limits
* Research gaps: real AD/IPA/trust/smartcard/passkey, enforcing LSM, shared-peer propagation, concurrent enumeration/live unit race and days-long periodic cleanup not tested. Source findings are not native functional certification.
* Frozen-monitor restart exceeded 20s outer harness deadline; cleanup/deadline result INCONCLUSIVE, not PASS. Cleanup may run past activator deadline by existing contract. No precise cause or production fix claimed. Native mount interference can correctly reject an attempt; independent successes do not promise unconditional availability.
* Existing source-only production discrepancies documented, not fixed: inactive/same-value persistent-only apply, foreign override blocking release, uncertain Prepared recovery. Future implementation boundary and open product choices in I1–I6 plan; none started.

## Environment
* DOCKER_CONFIG=/tmp/fic-package-docker-config; fic-sssd-research:debian12/debian13/ubuntu2404/ubuntu2604/alt-p11; absent bases fic-ssh-lifecycle-native same tags. build-sssd-research/<platform> has ignored binaries/raw results/exact sources. Container runtimes have no host mounts.
* Full configure/targeted CTest cache build-env-full-debian12 with fic-followup-build:debian12, source /src:ro, build cache /build:rw. Logs /tmp/fic-sssd-* and build/sssd-r2-target-build.log (inside cache).
