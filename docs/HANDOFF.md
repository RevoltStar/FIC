# Current workspace

## Current base
* Branch main; follow-up base fed7e32acfb0b77fc6d96fa7e77f11959c4b98c1. This snapshot belongs to the single `fix(sssd): enforce canonical domain scope in I2 previews` commit. No push.

## Current task
* Attachment e33dd86b: close the I2 forged DomainScopeReference trust-boundary defect and distinguish semantic consistency from policy coverage. Completed; do not start I3–I6.

## Accepted architecture / invariants
* Variant B: retain the public immutable data-container API; it grants no authority. Stored fingerprints alone cannot establish integrity of caller-supplied derived fields.
* sameScopeReference compares complete structural facts: generations/fingerprints/platform, all root vectors including expectedBackends, every domain's providers/classification/flags/consumers/issues, global issues and recomputed binding of the stored I1 input. Null/substituted input is not equivalent to canonical observed scope.
* previewConfiguration recomputes canonical scope from its input, rejects hypothetical/stale/inconsistent references as NotProven without a candidate configuration, then uses only canonical domain/selected/enabled facts for admissibility. No new scanner, tokens or cryptographic protocol.
* SemanticStatus::Validated remains configuration consistency. ConfigurationPreview explicitly has PolicyCoverage::NotEvaluated. Future I4/I6 must separately prove every required (section,key), effective value and ownership over the complete canonical policy scope before policy SUCCESS. I2 neither generates that target set nor enables sibling cache keys automatically.
* Existing I2 support/default/range/ownership/ordered-merge/release contracts remain authoritative in the SSSD design docs. I1/I2 remain read-only; no runtime receipt, completed C/A/B/C/P, policy/runtime/journal/package integration or ownership authority.

## Completed / changed areas
* service/sssd/SssdDomainScope.{h,cpp}: full structural equivalence, explicit data-container boundary. SssdEffectiveConfiguration.{h,cpp}: canonical decision source, explicit hypothetical rejection, typed coverage-not-evaluated output. RelationValidator source/formula unchanged.
* tests/fic/service/SssdDomainSemanticsTests.cpp: ghost/inactive/disabled/provider/issue/backend/consumer/input and isolated-field forgeries with unchanged fingerprints; hypothetical Apply/Refresh refusal; partial multi-domain consistency versus unevaluated coverage. Existing positive Apply/Refresh/release/siblings/late snippets/foreign-conflict/source-drift cases retained.
* Original defect reproduced BEFORE production edits: CTest exit8, ghost gave projectionAvailable=true and semanticStatus=Validated. Actual failing log retained in tests/integration/sssd-i2/scope-red.txt. Final tests pass; that RED is historical baseline evidence, not a current failure.
* Existing five-platform I2 native runner repeated. New evidence exported from those actual reports; baseline commit/evidence digest retained via git history without duplicating large JSON. R1/R2/I1 evidence/fixtures and production I1 byte-identical to base. README/checker/exporter and scope/relation/activation docs updated.

## Validation
* `cmake --build /build --target fic sssd_domain_semantics_tests sssd_input_closure_tests ssh_verified_activation_tests verified_config_service_tests sssd_uninstall_inspection_tests package_state_store_tests package_release_support_tests uninstall_lifecycle_tests package_trust_selection_tests -j2`: PASS in fic-sssd-i1:full Debian12 builder, source RO/build RW. Log build-sssd-i1/full/i2-scope-final-build.log.
* CTest PASS15/15, 0.69s: I2 unit/evidence; I1 unit/evidence; R1/R2 guard; SSSD uninstall; SSH verified/static; generic verified; prelogin/desktop package checks; package trust/state/release/uninstall. Log build-sssd-i1/full/i2-scope-final-tests.log.
* Existing identity_configuration_editors_tests, identity_concrete_policies_tests, ssh_runtime_tests, ssh_apply_rollback_tests rebuilt and CTest PASS4/4, 3.56s. Logs build-env-full-debian12/i2-scope-regression-{build,tests}.log.
* All five native runners exit0, 37 observations/platform: provider scope, six LDAP/proxy relations, false-cache/multi-domain conflicts, defaults/booleans and scope changes. Real stock systemd PID1/SSSD, disposable private namespaces, loopback only, no host binds/ports; containers removed.
* Versions unchanged: Debian12 SSSD2.8.2-4+deb12u1/systemd252.39-1~deb12u2; Debian13 2.10.1-2+b1/257.13-1~deb13u1; Ubuntu24 2.9.4-1.1ubuntu6.8/255.4-1ubuntu8.18; Ubuntu26 2.12.0-1ubuntu5.5/259.9-0ubuntu0.1; ALT2.9.8-alt3/258.9-alt1.
* collect-evidence.py and check-evidence.py PASS; AST/bash syntax included. git diff --check PASS. Raw new reports: build-sssd-i2/<platform>/native; versioned evidence: tests/integration/sssd-i2/evidence.json. Ordinary CTest does not launch native containers. In-memory forgery scenarios are unit-tested; existing native gates check distro regressions.

## Remaining / limits
* No unfinished follow-up work. Full project/all-CTest, R1/R2 research, I1 native race matrix, native SSH activation and package-manager E2E not repeated; corresponding production implementations unchanged. I1/SSH and package contract regressions passed.
* I3 still needs verified activation, actual monitor/backend/late-responder identities/readiness and use of current config generation, persistent proof, negative-publication/mount/cleanup and PIDFile/precommand/metadata support. I4/I6 must add complete required-target coverage proofs, trusted ownership/CAS/journal and policy integration; I5 physical release/runtime outcome separation remains future work.
* AD/IPA realm/trust, proxy functional password/cleanup, hardware mechanisms, enforcing LSM/bare metal/other kernels remain outside Docker/WSL evidence. Canonical scope consistency is neither live runtime proof nor policy coverage.
