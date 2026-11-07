# Current workspace

## Current base
* main; I1 task base `8ae2ebb84a10084044652594b7fe166e37df0324` (completed R1/I3).
* I1 is the next single commit, subject `refactor(pam): enforce structural capability activation contract`; no push.

## Current task
* Attachment ac9a7544: I1 complete. Do not start I2 or other PAM stages automatically.

## Accepted architecture / invariants
* Structural only, not SecurityEffective. Existing C2 single writer/planner, ALT strict managers/blocks and StaticVerifyOnly passwdqc. I3 Required edges preserved.
* Foreign compliance cannot bypass active ownership. No adoption, marker/schema migration, new writer or recovery mechanism. Explicit rollback/release remains independent of ordinary-apply gates.
* Docker authorized; no host PAM mutation. R1/I3 historical artifacts unchanged.

## Completed / changed areas
* Real manager/verifier RED→GREEN fixes: foreign permanent-slot faillock strategy detection; C2 full Structural pre/post proof; StaticVerifyOnly active-provenance refusal; C2 ordinary-apply ownership postcondition.
* Narrow coordinator preflight callback receives the SAME requested-state snapshot consumed by transition. Requested peer Missing fails before any slot/journal mutation; unrequested peer stays optional.
* Structural C2 legacy history-initial permits producer semantics; parameter/security preflights retain strict use_authtok. No topology writer/planner/recovery/rollback redesign.
* Activation/configuration/wiring regressions cover foreign/no ownership, bypass/unknown controls, weak effect values, idempotency, active Prepared/Applied/RollbackFailed for both C2 members, failed AFTER proof retaining provenance and requested-peer preflight.
* Authoritative detail: docs/pam-r1-architecture-research.md §10. Harness/evidence: tests/integration/pam-dependencies/{run-i1.sh,native-initial-probe.sh,i1-evidence.json}. Platform static guard updated without permitting direct platform commands in policy.

## Validation
* All5 native Docker toolchains: fic +20 targets built;22 unique relevant CTest PASS per platform. Final8 affected apply/C2/rollback/registry/static suites rerun after final code changes:8/8 PASS on each.
* All5 final stable source receipts match current code/tests. Raw logs/receipts retained under build-pam-i1; earlier iteration source drift/static/fixture/stale-object failures are explicitly distinguished from final PASS in report/evidence.
* Native pwhistory initial producer: real pam_chauthtok on disposable users D12/D13/U24/U26; two changes succeed, reuse rejected. Narrow consumer probe, not FIC policy E2E.
* D12 nonroot registry/Structural fixture PASS uid65534, read-only source/build/rootfs. Harness syntax, platform static checks and git diff --check PASS.

## Remaining / limits
* No unfinished I1 implementation. Full I6 functional matrix, native ALT passwdqc/history consumers and package/FIC activation E2E not run.
* I2: reconciliation/repair of retained unresolved records or post-proof drift; existing recovery transitions remain unchanged. ALT marker MutationId/legacy causal-ownership ambiguity and broader unsupported foreign topologies remain out of scope. No automatic cleanup/adoption added.
