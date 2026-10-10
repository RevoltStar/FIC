# FIC handoff

## Current base

* main; task base f392306. Snapshot accompanies passwdqc rollback commit.

## Current task

* Completed managed-provider rollback for all six ALT passwdqc assignment policies.

## Accepted architecture / invariants

* ProviderConfigFile + PamPasswdqc + StaticVerifyOnly uses shared managed-entry executor and EOF placement. Enrollment, orphan guards and package release share typed routing and canonical policy mapping.
* Only pam_passwdqc serializes/parses key=value; other providers retain strict spaced assignments. Journal bodies and ownership proofs use the same provider identity. No schema migration/second rollback engine.
* Missing primary remains fail-closed; no automatic creation. Rollback releases proven ownership and preserves current foreign bytes/values. Production capability/semantic postcondition remains mandatory.

## Completed / changed areas

* Managed block/parser/spec, entry executor, canonical policy mapping and journal validation extended; pwquality root flag route and other existing PAM contracts preserved.
* Six-policy lifecycle/enrollment/strict journal regression tests; package primary enumeration and malformed passwdqc preflight updated.
* Dedicated native ALT gate/probe/runtime Dockerfile, existing production driver extended with capability/semantic proof and integration-only fault injection. docs/rollback.md updated.

## Validation

* Debian12 full build PASS; final directly affected tests 8/8 PASS. Related selection 31/32 as root, with journal suite subsequently PASS under UID65534.
* Full CTest excluding separately checked root-sensitive journal suite: 169/170 initially; sole Git safe.directory infrastructure failure rerun PASS. All 171 distinct tests passed with suitable invocations; initial broad CTest exit was nonzero.
* Native ALT builder and clean runtime: six native parser/effective/rollback tests, joint/reverse order, config= before/after, refresh, byte preservation, ABA/drift/duplicate/orphan, CAS/shared lock, Prepared/Applied/primary fsync recovery, partial release retry PASS. Real read-only-primary atomic write failure PASS in both.
* bash -n gate and git diff --check PASS. Evidence/report: build-prelogin-validation/passwdqc-alt/REPORT.md; logs/matrices retained outside deleted containers.

## Remaining / limitations

* Native libpasswdqc parser and production PAM capability/semantic inspection verified; no real password-change conversation or host policy apply performed.
* Two ALT p11 environments, not a multi-release ALT matrix. Builder/runtime pam-config versions differ; see evidence. Gate runner requires native libpasswdqc-devel in builder.
