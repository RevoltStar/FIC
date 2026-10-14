# Current working state

## Current base
* Branch main; base `40811135683e566534e755122f6d9234c5973810`. Initially clean tree; completion commit follows this base. No push.

## Current task
* Register lock_exempt_fic_members as GLOBAL/lock_settings status-only policy; one completion commit, no push. User replaced Podman requirement with Docker for Debian12/13, Ubuntu24/26 and ALT p11.

## Accepted architecture / invariants
* Existing IncidentRecoveryConfigReader and standalone PAM unchanged. Shipped default ENABLE is not a permissive fallback for missing/unproven keys. Local root recovery independent; no Required dependencies.
* FixedPolicyTypeValue(ENABLE); read-only apply proves trusted effective status, cached intent and configuration snapshot stability. Explicit NotEnrolled, no previous-state restoration or session recreation.
* Enable/disable reload registry, verify status including DISABLE, then force existing containment reconciliation even for established ACTIVE SOFT/HARD. Failed rebuild skips dependent work. saved/applied distinguish persistence from successful verification/reconciliation. Existing SSH preflight retained.

## Completed / changed areas
* New GLOBAL policy and production registration, RU/EN generic GUI/CLI descriptors, rollback enrollment.
* main.cpp status verification and forceContainment routing; saved/applied survive error responses.
* New policy tests/native gate and routing check; ModelA secure-reader-driven active HARD flag changes, malformed status and independent root; standalone access-gate root recovery and rollback regression.
* fic/README.md and docs/rollback.md describe lifecycle. History reviewed: 90712a5 introduced flag, e171cba unified authority proof, 943b34b added optional containment status.

## Validation
* Docker recovered after user freed disk. Debian12 full project build PASS and full CTest 185/185 PASS; native production reader/status gate PASS. Logs /tmp/fic-recovery-debian12-{final-build,full-ctest}.log.
* Debian13, Ubuntu24/26 and ALT p11: current fic + pam_fic_access builds PASS; focused8/8 and native production gate PASS on each. Logs /tmp/fic-recovery-{debian13,ubuntu2404,ubuntu2604}-restored.log and /tmp/fic-recovery-alt-final.log.
* Native gate is restricted to disposable root Docker; creates root:fic production /opt/fic/config and verifies actual default reader plus status writes and malformed-config rejection. Does not run daemon or alter host security state.
* git diff --check, direct routing Python and bash -n native-gate.sh PASS.

## Remaining / limits
* Implementation and requested Docker matrix complete; one completion commit, NO PUSH. No remaining implementation blockers.
* No real PAM login or live logind containment validation; controller tests use fake transport. Full CTest only Debian12, other rows focused tests.
* Docker builders remain available: fic-deb-builder:debian12-final, fic-recovery-builder:{debian13,ubuntu2404,ubuntu2604,alt-p11-ctest}. ALT cache build-recovery-alt-p11; other caches build-recovery-policy/<row>; Debian12 build-prelogin-validation/final.
* Ubuntu26 temporary builder uses official HTTPS archive with trusted host CA after HTTP libpng failures. ALT temporary builder uses existing native ALT p11 base, HTTPS distrib-coffee mirror and separate ctest package. TLS/repository signatures retained; source packaging unchanged. Environment failures were resolved before final validation.
