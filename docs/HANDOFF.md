# Current workspace

## Current base
* main; follow-up base ad41b954b009989cf9b12bed6fade17c1b7d2e9e. This snapshot belongs to the single `fix(sssd): defer input proof until verified runtime consumption` commit. No push.

## Current task
* Attachment 1396e5a5: correct premature I3 Input Proof A. Completed; do not start I4/I5/I6.

## Accepted architecture / invariants
* Protected publication is a local prerequisite, not completed A. A requires validated publication and a complete successful existing source-causal proveRuntime (new monitor, ConfigDB generation, selected backends/required responders).
* Restart dispatch/activationAttempted alone cannot establish input consumption. Partial B facts without full consumer proof can coexist with A NotProven.
* A records historical protected-input consumption: retain it after P drift, cleanup failure or later current-runtime B/C invalidation. Overall success remains strict. Existing bounded source-causal C, B/C/P, tool/metadata/topology/support limits remain authoritative in docs/sssd-verified-activation-design.md.
* No generic/SSH/I1/I2/runtime-proof/policy/journal/package implementation changes or new public API/state machine.

## Completed / changed areas
* Production diff only service/sssd/SssdVerifiedActivationAdapter.cpp: publishedValidated local flag; move result.inputs=Proven from published to after full proveRuntime. No other production files changed.
* Existing I3 hooks reused; timeout-published now executed on every platform. Native assertions cover pre-dispatch A/B/C, attempted-but-unproven consumers, success, all five P-drift cases, cleanup failure and historical A/current B/C separation.
* Saved-evidence checker RED before production edit retained as tests/integration/sssd-i3/input-proof-red.txt; it is the old defect reproduction, not a current failure.
* Fresh I3 reports/index bound to actual tested source hashes. Guard compares baseline common scenarios: only seven expected A states change (unit-before/unit-after/mount-change/stop-monitor/stop-pam/stop-backend/stale-configdb); B/C/P/admission, success, engine outcomes, cleanup/residuals and interference diagnostics remain unchanged.
* R1/R2/I1/I2 evidence and retained I1 regression reports untouched. README/design/native compatibility updated for the corrected A semantics/current matrix.

## Validation
* `cmake --build /build --target fic sssd_verified_activation_tests sssd_input_closure_tests sssd_domain_semantics_tests verified_config_service_tests ssh_verified_activation_tests -j2`: PASS in isolated Debian12 builder. Configure/build logs build-sssd-i1/full/i3-input-proof-{configure,build}.log.
* Final CTest PASS9/9 (0.69s): I3 unit/evidence; I1/I2 unit/evidence; generic/SSH verified; R1/R2 evidence guard. Log build-sssd-i1/full/i3-input-proof-final-tests.log. Ordinary CTest does not start containers.
* Real Docker/systemd/SSSD I3 matrix exit0 on all five, existing LDAP/PAM functional fixtures PASS. 56 observations Debian12/Ubuntu24; 58 Debian13/Ubuntu26/ALT. Reports build-sssd-i3/<platform>/native; logs /tmp/sssd-i3-input-proof-<image-tag>.log. Versioned current results tests/integration/sssd-i3/{evidence.json,reports/}.
* unit-before/mount-change: A/B/C NotProven, dispatch=false, InterferenceDetected. timeout-published: A/B/C NotProven, dispatch=false, TimedOut after published. Four incomplete-consumer cases: dispatch=true, A/C NotProven; B retains actual partial proof.
* Positives A/B/C/P Proven, clean cleanup/no residuals. P drift retains A/B/C Proven. CleanupFailed retains A/B/C, primary Success and residual evidence. stop-pam-after retains historical A and P while current B/C become NotProven.
* collect/check-evidence, historical guards, Python syntax, shell syntax and git diff --check PASS. Native task containers removed.

## Remaining / limits
* No unfinished follow-up work. Full unrelated all-project CTest, fresh I1 native research, native SSH/package-manager E2E and bare-metal/LSM/Podman validation were not repeated; this follow-up changes only A completion timing.
* Existing limits unchanged: exact native package/tool trust, private publication boundaries/prepared metadata, missing external EnvironmentFile and lazy-only selected PAM Unsupported; ALT positive fixture has explicit environment and separate stock-absence refusal. C is not direct memory/auth/LDAP-health/cleanup-execution proof. PolicyCoverage remains NotEvaluated.
* I4 ownership/journal/CAS/Apply/REFRESH/recovery, I5 release and I6 policy/client integration remain future work.
