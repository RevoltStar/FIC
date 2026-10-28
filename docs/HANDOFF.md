# Current workspace

## Current base
* Branch main; I1 base 19a97e7e1a7ef1179b3f3be0d2d893dcd7c3f91d. This checkpoint belongs to the single I1 implementation commit; no push.

## Current task
* Attachment d785bfd2: implement SSSD I1 native input closure and closed read-only launch admission. I1 completed; I2/I3 must not start automatically.

## Accepted architecture / invariants
* Admission separate. A=Inputs, B=Activation, C=Semantics, P=Persistent. Returned I1 references prove neither completed A nor B/C/P, ConfigDB generation, runtime receipt, policy Success, ownership or journal finalization.
* Production I1 is read-only, has no policy callers, lifecycle jobs, mounts, writes, MutationJournal or legacy-runtime fallback. Existing SSSD policy/runtime/rollback and package lifecycle unchanged.
* Five closed platform profiles require reviewed exact vendor-unit bytes, typed commands/env/identity/sandbox fields, full trusted source fingerprints, UnitPath negative set, stable active MainPID/invocation/process/root/namespace. Unknown loaded/pending overrides fail; only proven empty native .d directories allowed. Generic PIDFile rejection unchanged.
* Full bounded tree/source manifests and optimistic two-pass identity/metadata/bytes/absence revalidation. Root/CAP_SYS_ADMIN in initial user namespace required by reused xattr visibility guard. No privileged ABA guarantee; future I3 must revalidate references again. Native PATH forms and C/C.UTF-8/POSIX manager locales only.
* Existing sources become ActivationRequest inputs. Missing main/conf.d/optional env remain explicit negatives with engine gap, never fake files. Any later eligible foreign snippet marks applyConflict independent of content; FIC-named file remains observable but its name grants no ownership. Narrow INI projection; unknown syntax Unsupported. I2 handles providers/domains/defaults/relations.

## Completed / changed areas
* service/sssd/SssdServiceAdmission and SssdVerifiedInputClosure; narrow read-only extension of existing typed generic systemd reader. Reused descriptor/tree/unit fingerprint/digest/ActivationRequest primitives; no second scanner/snapshot engine.
* Exact native tool aliases include usr-merge, stock sh and Ubuntu26 uutils. ALT full native provider/LDB fixture closure and empty .d support confirmed.
* New CTest sssd_input_closure_tests and saved-evidence-only sssd_i1_evidence_checks. New opt-in runner/checkpoints/evidence/fixtures under tests/integration/sssd-i1. Historical R1/R2 artifacts unchanged.
* Debian12 pending drop-in could evade NeedDaemonReload alone; fixed with UnitPath negatives. Source unit digest pins reject changes even in unprojected directives. Config modes stricter on older profiles; later files never adopted.

## Validation
* Final native runner exit 0 on all five: Debian12 SSSD 2.8.2-4+deb12u1; Debian13 2.10.1-2+b1; Ubuntu24 2.9.4-1.1ubuntu6.8; Ubuntu26 2.12.0-1ubuntu5.5; ALT p11 2.9.8-alt3. Docker explicitly authorized, real systemd PID1, stock packages, no runtime host binds/network, shared WSL kernel. Containers removed.
* Native gates: stable/stopped admission; ordered duplicates vs config-check/monitor/ConfigDB; main absent/both absent; optional env absent/hostile variable; three later snippets; six deterministic capture races; unloaded drop-in/env/vendor-source changes; symlink/hardlink/owner/modes/directory/nested mount negatives. ALT config-check exit1 on exactly two ignored-file warnings retained distinctly.
* cmake configure/build FIC and affected targets PASS in fic-sssd-i1:full Debian12 builder, source read-only. Native runner compiles actual I1 per platform with test-only hooks; production FIC has no hooks.
* identity_configuration_editors_tests, identity_concrete_policies_tests, ssh_runtime_tests, ssh_apply_rollback_tests: CTest PASS 4/4 in existing Debian12 cache (3.14s).
* Final CTest PASS 7/7 (0.30s): sssd_input_closure_tests, sssd_i1_evidence_checks, sssd_uninstall_inspection_tests, sssd_research_evidence_checks, ssh_verified_activation_tests, verified_config_service_tests, ssh_policy_static_checks. Log build-sssd-i1/full/final-tests.log. Evidence guards, Python AST/bash syntax and git diff --check PASS. Full project build/full CTest not repeated; no GUI/CLI/policy/journal changes.

## Remaining / limits
* I2–I6 unimplemented. No service activation, full semantics/domain/default/provider support, ownership transaction/release or runtime receipt. PIDFile profiles need I3-specific handling, generic engine remains strict. Missing source publication/negative proofs and RO metadata/consumer/cleanup proofs are I3 work.
* Native Docker/WSL results do not prove Podman, other kernels, bare metal, enforcing LSM, real AD/IPA/trust/token/authentication. Historical NOT_TESTED/INCONCLUSIVE statuses unchanged.
* Raw new commands/results/container inspections: ignored build-sssd-i1/<platform>/native; reviewable export tests/integration/sssd-i1/evidence.json and measured launch-fixtures.json. collect-evidence.py exports only new I1 evidence; check-evidence.py validates saved evidence, never reruns native gates.
* ALT ftp/yandex network failed; signed native packages fetched through accessible French mirror. Missing samba-dc-libs initially broke fixture LDB startup; corrected test image without modifying native units/production behavior.
