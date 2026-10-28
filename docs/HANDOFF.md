# Current workspace

## Current base
* Branch main; follow-up base f181c0c4a421b2a5ef8b3e4bfc5464706ecb6cc8. Historical R1 696a4575e55b125617613fa212317c5b76636151 and R2 history preserved.
* This snapshot belongs to the one docs(sssd) corrective follow-up commit; no push.

## Current task
* Attachment 206697cc: align R1/R2 research docs/evidence contracts with existing SSH verified activation. Follow-up completed; I1–I6 not started, production unchanged.

## Accepted architecture / invariants
* Admission is read-only and separate. A=Inputs; B=Activation/runtime-readiness; C=selected effective Semantics; P=post-cleanup Persistent proof. Generic engine Success does not establish full SSSD C/P or policy Success. New transaction needs final journal proof too.
* Stopped/unproven SSSD fails apply before persistent mutation; no install/enable/start. Current revalidated runtime receipt can avoid another restart; files/stale receipt cannot.
* One own zzzz-fic.conf, per-policy section/key; matching foreign value still requires own key, never adoption. Any loaded later foreign snippet blocks apply/REFRESH regardless of content; alone does not block proven ownership release. REFRESH single transition, unresolved Prepared gates conflicts, no blind restore after unknown effects.
* Offline→cache stays Recommended; no hidden cache enablement or automatic value alignment. Provider/scope must be proven for the affected policy; partial domain coverage is not global Success, parent flags do not prove discovered trusts. Domain-set changes require receipt recheck.

## Completed / changed areas
* All five SSSD design/compatibility/semantics/scope/validator docs and research README aligned. Canonical proof table and mandatory I1–I6 native acceptance catalogue: unit changes across admission/snapshot/activation/runtime/P, enumeration mutations, private/shared/shared-slave/topology changes, timeout/no READY/cleanup/residuals/unknown effects, REFRESH/crash/release/package integration.
* Docker approval verified from primary task-conversation reply call_e6b52697b66e4bde805cf319106068f6 question 0, “Да, использовать Docker”. Real systemd PID1/stock packages on shared WSL kernel; Docker results do not prove Podman equivalence, bare metal, enforcing LSM or other kernels.
* New research-contract.json and research_contract.py extend existing evidence guard: stable proof/gate identifiers, retained coverage/unsupported profiles, SHA256 of four historical evidence/source exports, five in-memory negative controls. No new production/native gate or privileged CTest execution.
* Historical R1/R2 native experiments and source exports unchanged; no evidence regenerated, no new runtime outcomes or PASS claims. Validation in this follow-up is saved-evidence validation only.

## Validation
* python3 tests/integration/sssd-research/check-evidence.py PASS, including 5 negative controls, Python AST and bash -n for research scripts.
* Existing CTest sssd_research_evidence_checks PASS 1/1 (final 0.15s) in unprivileged fic-followup-build:debian12 build container, network none, source read-only. This is not native runtime testing or rerunning SSSD/LDAP/PAM.
* All five research JSON files parsed; historical four artifact hashes match the R2 base. Proof table and stage gate IDs validated structurally, not by full prose matching. git diff --check PASS; production/packaging paths unchanged.

## Remaining / limits
* No research blocker to start bounded I1 source/closure/launch implementation under the documented gates; this turn does not start it. Account-policy default and wider provider support remain later explicit decisions.
* Preserved NOT_TESTED: unit/enumeration races, shared-peer propagation, enforcing LSM, real AD/IPA/trust/token infrastructure, periodic cleanup and cached-timeout memory introspection. SIGSTOP-monitor timeout/cleanup and AD/IPA relation runtime remain INCONCLUSIVE. Older stock PIDFile profiles remain UNSUPPORTED by generic engine; no statuses upgraded.
* Existing production SSSD apply/release/Prepared discrepancies are still source-audit findings only. No production fixes, journal schema changes, second engine, fallback or migration added.

## Environment
* Saved artifacts/repro scripts under tests/integration/sssd-research; authoritative native JSONs in docs, source-r1.json/source-r2.json unchanged.
* DOCKER_CONFIG=/tmp/fic-package-docker-config. Existing CTest cache build-env-full-debian12 uses source /src and build /build. Opt-in native runner is separate; no reason to repeat the full native matrix for this docs-only correction.
