# Current workspace

## Current base
* main; I5 implementation base `be53994aca09959965aa7e13ad328989147fe265`. This snapshot belongs to the single `feat(sssd): implement verified ownership release and rollback` commit. No push.

## Current task
* SSSD I5 (attachment da8c4f88) completed under the user's revised administrative boundary. Stop here; I6 is separate.

## Accepted architecture / invariants
* Standalone backend extends SAME I4 coordinator/resource mutex, I1/I2 graph and protected I3. Caller retains daemon admission; no new interprocess/ownership engine, legacy fallback, migration, policy/registry/client/package integration.
* User decision: full surviving FIC-owned assignments come from trusted I4 journal, NOT a claimed full administrative ENABLE set. No IDENTITY_ACCESS.conf reader. ReleaseOnly may finish RolledBack; DisableRelease remains ReleasedAwaitingDisable. Production acknowledgement and fabricated terminal disable documents are prohibited until I6.
* Global schema 3; original I4 v1 meaning preserved. Typed v2 release stores previous/remaining/absence, service/effect/proof facts. Terminal journal publication atomically retires releasing owner and transfers effective container witness to every survivor. Reload authenticates handoff links; old assignments/scope/receipts are not rewritten.
* Last-file removal adapts existing SSSD rename-away engine: original AtomicTargetState, journaled stage, bounded staged identity/body/meta reproof, no-replace foreign restoration, unlink/parent fsync. Existing cooperative privileged-writer races remain documented.
* Active release permits/protects late inputs and requires surviving semantics + I3 A/B/source-causal C/P, clean cleanup and final proofs. Revealed semantic conflict does not justify retaining own key; it leaves physical release explicit and journal unresolved.
* Offline uses same native launch/private-PID1 client + existing RefUnit lease; no start/restart. Requires inactive/dead/MainPID0/no job/cgroup/consumers/live endpoints, verified socket topology and monotonic start/exit epochs. Only empty never-active dependency-free not-found placeholders count as absence. Failed/active/pending/unknown topology refuses; no fake B/C.
* All unresolved release/awaiting-disable states gate sibling mutations. Only exact unarmed no-effect Prepared may resolve. Armed states are never promoted by bytes or blindly retried/cleaned.

## Completed / changed areas
* service/sssd: release API/result, full journal/physical ownership, I2 preview, active/offline execution, effective witness selection and absent-target inspection. Default I3 Apply remains strict; no empty/vacuous C or late-input relaxation for Apply.
* rollback/MutationRecord, SssdJournalPayload, MutationJournal: v2 codec/strict validators and typed release lifecycle, atomic handoff, link validation, generic bypass prevention and v1/legacy readers.
* SssdConfiguration: reused removal primitive with stronger I5 original-state binding and real crash seams; legacy default behavior unchanged. Shared VerifiedConfigLaunchContract: reused unit lease/client, release-only epoch/socket observations.
* Tests: expanded sssd_transaction_tests; new sssd_proven_removal_tests; integration/sssd-i5 driver/runner/fixture/source manifest/collector/guard/lossless reports. I4 probe links shared removal dependencies. Historical I3/I4 guards authenticate accepted historical commits, not changed current sources. Historical reports/indexes untouched.
* Authoritative contract: docs/sssd-verified-activation-design.md. Commands, fixture prerequisites and evidence limits: tests/integration/sssd-i5/README.md.

## Validation
* Full project/production build PASS in `fic-sssd-i1:full`: `cmake --build /build -j4`; build-sssd-i1/full/i5-full-build-final.log. Subsequent all-target freshness build PASS: i5-build-freshness.log; stale common-reader objects rebuilt before final CTest.
* Final full `ctest --test-dir /build --output-on-failure`: 218 listed, 214 executed PASS, zero failures, 4 skips, 129.29s. Log build-sssd-i1/full/i5-full-ctest-final.log. Includes I1–I5, journal, generic activation, SSH, legacy SSSD, SUDO, USER_CREATION/login.defs and package regressions.
* Harness: /src RO, build-sssd-i1/full /build RW; QT_QPA_PLATFORM=offscreen; Git safe.directory /src; DAC_OVERRIDE/DAC_READ_SEARCH dropped for chmod fault tests. Four skips: verified_config_service_native_tests, daemon_singleton_startup_native, maintenance_preflight_native, package_pam_hooks_native.
* Fresh source-bound native matrix PASS on Debian12/13, Ubuntu24.04/26.04 and ALT p11: 265 observations + 21 real termination seams EACH, same 133-file source manifest. Completion/probe/raw hashes verified; collector and retained guard PASS. Reports tests/integration/sssd-i5/reports/*.json.gz; index evidence.json; raw/build logs build-sssd-i5/<platform>/native and /tmp/sssd-i5-*.log.
* Native fixtures explicitly quiesce/reset only failed native responder sockets for offline positives; ALT inactive-unit GC is respected. Production never stops/resets units. Custom lazy responder socket negative proves endpoint absence alone is insufficient.
* Python/shell syntax and git diff --check PASS. New Python sources explicitly staged despite existing *.py ignore; no __pycache__/build artifacts included. Historical retained data unchanged (27 checked files).

## Remaining / limits
* No unfinished I5 implementation. I6 must connect existing offline policy, eliminate competing legacy mutator, register cache/account, wire dependencies/clients and real PolicyRegistry/PolicyDisableFlow with durable config + trusted generation + released/surviving reproof under same mutex. Real daemon/package E2E and explicit legacy compatibility remain separate; no automatic adoption.
* One exploratory Ubuntu26 I4 prerequisite refused after A/B/C/P with `mount namespace event before commit`; no finalization, provenance retained. Cause UNKNOWN (no unit/kernel event trace); complete negative report/source/probe hashes retained under integration/sssd-i5/diagnostics. Later complete source-current matrix PASS; watch/timeout guarantees not weakened.
* Docker/WSL evidence is not bare-metal, enforcing-LSM, Podman, AD/IPA/trust or production authentication certification. Source-causal C does not claim login, future LDAP health or executed periodic cleanup. Existing I3 reviewed-version/private-boundary/environment prerequisites remain.
