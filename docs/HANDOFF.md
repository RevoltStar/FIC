# Current workspace

## Current base
* main; I4 implementation base `2e6b72ae16236a9d871f59cb4e3e845cbc275d73`. This snapshot belongs to the single `feat(sssd): implement journal-backed apply and refresh transactions` commit. No push.

## Current task
* SSSD I4 (attachment 272f32fe) completed. Stop here; I5/I6 require separate work.

## Accepted architecture / invariants
* Standalone backend; no policy/registry/client/package integration, legacy restart fallback or migration. Existing I1/I2/I3/source-causal C and corrected A remain unchanged.
* Closed policy/parameter identities, explicit value (no account default), complete canonical selected/enabled static LDAP target sets. Every sibling owner must also match its complete uniform set; no partial scope or orphan adoption.
* One process-local deadline-bounded coordinator mutex; caller must hold daemon admission. Legacy SSSD mutators are not integrated and must not be mixed with this API before I6.
* Global journal schema remains 3; new version-1 `sssd_journal_ownership` action is separate from legacy scalar records. Active legacy ownership blocks I4 without erasing or fabricating provenance.
* Prepared → MutationArmed → Published → DurablePublished → ActivationArmed → RuntimeVerified → Completed. Same record identity/current permission survives REFRESH. Finalization requires I3 A/B/C/P, clean cleanup and final exact I1 source/runtime reproof. Same-value does not rewrite config but requires new I3 proof.
* Only proven unarmed no-effect Prepared may be explicitly resolved. Armed/unknown states block every sibling; no promotion by bytes, automatic restart/retry/restore or adoption/cleanup of residual mounts. Existing cooperative CAS/root-writer race remains documented.

## Completed / changed areas
* service/sssd/SssdTransactionCoordinator.*: typed API, scope/relations, exact journal/physical ownership, single CAS, native metadata plan, I3 activation and final checks, inspection/no-effect resolution.
* rollback/MutationRecord.h, MutationJournal.*, SssdJournalPayload.h: typed payload/parser/begin/advance/commit/abort; generic prepare/status/discard bypass refused. I4 allocator rejects zero/exhausted IDs; legacy readers/contracts unchanged.
* Legacy SssdConfiguration.* only shares its existing removal-staging name prefix; no apply/rollback behavior change. I4 refuses atomic-write AND legacy removal artifacts.
* New sssd_transaction_tests covers schema, target sets, journal lifecycle/legacy reader, actual mutex concurrency, fork/crash and invalid/exhausted ID regression.
* integration/sssd-i4: native driver/fixture, real partial staged-write interposer (test executable only), 17 termination boundaries, independent physical witnesses, gzip raw reports/index/collector/validator. Normal CTest never launches privileged containers. Existing historical SSSD evidence untouched.
* Authoritative API/ownership/recovery docs: sssd-verified-activation-design.md; relation integration in sssd-cross-policy-validation-design.md; runnable commands/limits in integration/sssd-i4/README.md.

## Validation
* Full production/project build PASS in Debian12 builder: `cmake --build /build -j4`; log build-sssd-i1/full/i4-full-build-final.log.
* Final full CTest: 216 listed, 212 executed PASS, zero failures, 4 native skips; 141.71s. Log build-sssd-i1/full/i4-full-ctest-final.log. Includes I1/I2/I3/I4, legacy SSSD policy, journal, SSH apply/REFRESH/rollback, USER_CREATION, login.defs, SUDO and package checks.
* Correct test environment: source /src RO, build-sssd-i1/full /build RW, fic-sssd-i1:full; QT_QPA_PLATFORM=offscreen; Git trust for /src; DAC_OVERRIDE/DAC_READ_SEARCH dropped so readonly-directory fault tests work. Earlier root-DAC/Git failures were harness issues; unchanged affected tests then PASS3/3.
* Fresh source-bound native matrix PASS all five: Debian12/13, Ubuntu24.04/26.04, ALT p11; 196 observations each, 17 real process-termination phases each. Reports build-sssd-i4/<platform>/native; logs /tmp/sssd-i4-<image-tag>.log; versioned lossless reports tests/integration/sssd-i4/reports/*.json.gz. Collector validates actual probe/raw/source hashes; retained guard PASS.
* Positives: full A/B/C/P, exact own image/witness, complete keys, durable Applied. Failures retain previous/target and sibling gate. No-effect resolution preserves old ownership/fresh absence. Partial staged write, unsafe recovery parent, orphan/unrecorded/partial sibling, legacy artifacts, unknown schema, CAS/metadata/FD/P/cleanup/runtime/finalization errors remain refused/unresolved as required.
* Journal rename before uncertain fsync may load an already Completed document only after NEW witness-aware durability proof; no Prepared promotion by config bytes. Post-I3 source drift prevents finalization even when prior I3 proofs succeeded.
* Python/shell syntax, evidence integrity and git diff --check PASS. Four required Python files force-added because existing *.py ignore rule hides them; .gitignore unchanged.

## Remaining / limits
* No unfinished I4 implementation. I5: verified release/active and stopped rollback/disable acknowledgement/foreign-conflict release. I6: replace legacy paths, connect policies/register new parameters/dependencies/client/real daemon-package E2E.
* Preserved I3 limits: prepared private publication boundaries/native metadata/tool trust/exact reviewed versions; external EnvironmentFile must exist (ALT positive fixture supplies one); lazy-only PAM and unsupported provider/topology/LSM remain refused. C is not functional auth, future LDAP health or executed cache cleanup.
* Production does not reset SSSD start limits; rapid real restarts may fail closed. Fixture counters are reset only for active services; ALT can unload stopped units.
* No bare-metal/enforcing-LSM/Podman/AD-IPA-trust certification or fresh real FIC package E2E claimed. Full CTest skipped generic activator native, singleton startup native, maintenance preflight native and package PAM hooks native; I4's own five-platform real systemd/SSSD matrix was executed separately.
