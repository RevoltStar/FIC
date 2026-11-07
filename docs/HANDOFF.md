# Current workspace

## Current base
* main; PAM R1/I3 task base `8a1c24bc0c356a908230a6e2e406b04f20651a22`. No push.

## Current task
* Attachment a6a92742: exactly R1 research and I3 Required dependencies, two sequential commits with specified names. R1 complete; I3 production edits not started.

## Accepted architecture / findings
* Keep Structural activation, C2 joint password topology, ALT managers/blocks, existing provider ownership/rollback and package lifecycle. No enforcement policies, writer for ALT passwdqc, new migrations/recovery or arbitrary foreign adoption.
* R1 production source unchanged. Actual registry driver: 16 option policies per D12/D13/U24/U26,12 ALT; graphs valid. Current options only Recommend activation; ALT6 Supported passwdqc/root options have none and activation absent.
* ALT bug is TWO gates: StaticVerifyOnly returns Supported for its bindings, but representative PasswordMinLength is Unsupported for passwdqc. Merely replacing equality RequiresTopologyActivation is insufficient.
* Minimal I3: collect capabilities from actually registered supported options via existing pamPolicyCapability; append one existing activation per used capability. Parent PamOptionPolicy adds Required for every supported/read-only registered feature, preserves Recommended disable_nopasswdlogin. No Q↔H/A artificial edges.
* StaticVerifyOnly apply/factory already exists, Structural only/no journal. Unrecorded static rollback AlreadyReleased; no backend/rollback redesign needed unless a concrete test proves otherwise.
* Four D/U selected profiles currently C2 mutable=true; stale older docs/comments are not current contract. D12 history uses C2 module args; ALT history options use legacy config transaction/topology lifecycle, not managed-provider entries; ALT passwdqc6 use managed entries.

## Completed / changed areas
* docs/pam-r1-architecture-research.md: full platform/parameter/dependency/ownership/rollback matrix, history, primary documentation and scope limits.
* tests/integration/pam-dependencies/Driver.cpp links actual production source closure and invokes initPolicyRegistry; --audit emits native matrix without policy apply. --alt-control is isolated/narrowed native experiment only.
* tests/CMakeLists adds EXCLUDE_FROM_ALL research target pam_dependency_contract_tests using fic source/link contract, daemon main excluded. Global existing libsystemd test import substitutes daemon-directory-local equivalent.
* build-and-audit.sh, alt-control.sh reproduce disposable Docker probes. Docker used per prior authorization; no host PAM writes.
* r1-evidence.json contains five actual audits, source-harness/image/ELF hashes and native ALT control results. R1 evidence is historical; do not rewrite it as I3 proof.

## Validation
* All5 research target builds and actual registry graph audits PASS. Logs build-pam-r1-i3/r1-{build,audit}-TAG.log; audit-PLATFORM.json.
* ALT native manager + control multi→ldap→local: blocks preserved, Enabled/manageable under scope={system-auth}, RPM pam-config1.10.0-alt0.p11.2/control0.8.0-alt3. Initial invalid root-scope fixture was corrected, not claimed as a production defect.
* Official Linux-PAM and Debian pam-auth-update docs compared. ALT wiki blocked by Anubis; used installed RPM facility/templates instead. No functional PAM auth/password-change claim.
* git diff --check and shell syntax PASS. Production diff empty before R1 commit.

## Remaining
* Create/finish R1 commit then implement I3; do not add a third stage or extra commit.
* Add real registered-policy tests for one unconditional Required/activation ref, disabled/failed/success executor suppression, Structural foreign success, static no-mutation/no-journal, reverse production disable guard, ReadOnly registration, no missing refs/cycles, preserved recommended/nonparam/C2 edges.
* Run relevant native builds/tests all5, C2 history/ALT passwdqc/provider rollback regressions. Update CI CTest target registration; no broad test framework.
* Replace current research target EXCLUDE_FROM_ALL with normal test target for I3 and add --test mode; preserve --audit/R1 data. Existing caches: D12 build-sssd-i1/full; others build-package-release/{debian13,ubuntu2404,ubuntu2604,alt-p11}.
* Final I3 evidence/docs/HANDOFF, diff checks, second named commit; no push. Unrelated ALT SDDM baseline remains outside scope.
