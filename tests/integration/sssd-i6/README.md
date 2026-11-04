# SSSD I6 production integration gates

Opt-in disposable Docker/systemd tests; ordinary CTest reads retained evidence
and never starts a privileged container. Requires the prepared I3 base images
and the I6 `Containerfile` for each of the five target distributions.

`build-native.sh IMAGE PLATFORM` builds clean actual FIC/CLI/device packages and
records source, package and paired ELF hashes. `build-legacy.sh IMAGE PLATFORM`
builds the exact accepted I5 commit at a lower package version for genuine legacy
upgrade cases. `run-native.sh IMAGE PLATFORM SCENARIO` checks those receipts,
installs real packages and exercises the installed daemon through normal CLI/IPC.
Platforms and required scenarios are enumerated in `contracts.py`.
After every required run, `collect-evidence.py` retains compressed reports.
A missing result, source drift, harness drift or failed scenario refuses collection.
`source-manifest.py`, the native runner and collector continue to bind **new** runs
to the actual current production/build and harness inputs.

`sssd_i6_evidence_checks` is a `historical-evidence;integration` CTest. It pins the
exact `evidence.json` from accepted commit
`96b88d2b40abff5cec9cd4352891401350e26719` (SHA-256
`6dd6fac33b0846d97202dda46f13428bed17622a489ad006b21dddc8ff305306`).
The checker freezes that commit's five platforms, 25 scenarios, 11 positive
assertions and legacy build identities independently of live `contracts.py`.
It still verifies compressed/raw report hashes, complete matrix, historical
source/build bindings, package receipts, scenario outcomes and all retained
container/ownership/release/debugger assertions. No Git history access or native
rerun is needed to check the retained artifacts.

**PASS authenticates only that accepted historical matrix. It does not certify
SSSD compatibility, apply/rollback or package behavior at current HEAD.**
Unrelated SSH changes and changes to current native contracts cannot invalidate
that historical result. New native evidence still requires fresh current-source
builds and the current complete matrix; adopting it as a historical baseline
requires explicit review and an updated pin/frozen contract. Do not replace the
historical pin with hashes of unvalidated working-tree results.
`test-historical-evidence.py` checks source/contract independence and refusal of
changed evidence bytes, missing/corrupt reports and changed gzip encodings.

Fixtures have private PID/cgroup/mount namespaces, no network or host mounts,
read-only sysfs/proc-sys, coldplug disabled and preprepared private configuration
mount boundaries. Two LDAP domains use an unreachable loopback endpoint; these
are consumer/configuration proofs, not successful production authentication,
directory availability or actual days-long cache cleanup tests. No credentials
or cache are erased. Unrelated optional SSH policy is explicitly disabled via
normal FIC administration to isolate this SSSD gate. On ALT, if the native
EnvironmentFile is absent, the fixture explicitly provides
`/etc/sysconfig/sssd` with `DEBUG_LOGGER=--logger=files` before starting SSSD;
this is reported as fixture preparation, not an automatic repair by FIC.

Fault cases use gdb/ptrace against the real installed ELF, checked by Build ID;
there are no production fault-injection hooks or test coordinator substitutes.
Journal/artifact substitution is deliberate fixture corruption and must never
be copied to a real host as a recovery procedure. Diagnostic `native-debug`
results do not satisfy the source-bound collector.

Legacy Applied/Prepared/RollbackFailed cases prove preservation and explicit
production refusal, not automatic migration or safe arbitrary legacy scriptlet
execution. Existing package-lifecycle compatibility boundaries still apply.

The historical scalar producer at I5 requires0600/root configuration; Debian13
and Ubuntu26.04 native precommands use0640/native-group metadata. On those two
platforms the fixture generates authentic old records with SSSD explicitly
stopped, then explicitly starts the native service before upgrading packages.
This does not claim that the old active writer supports those native profiles.
No journal records are synthesized, old binaries changed or historical receipts
reconstructed. I6's active/offline behavior is tested separately by current
production scenarios.

Ownership-coverage regressions distinguish matching foreign effectiveness from
actual OwnWhileEnabled authority. `remaining-enabled-unowned-matching-foreign`
requires refusal before Prepared/file mutation and unchanged config/journal/SSSD
generation, then separately proves ReleaseOnly can free ownership without
requiring an unowned ENABLE sibling to be applied. `remaining-enabled-unowned`
now requires the same early refusal for a foreign value mismatch.
`acknowledgement-unowned-matching-foreign` changes actual administrative intent
at the existing debugger seam, reloads the real registry and checks refusal
before terminal acknowledgement. No records are synthesized or adopted.

`remaining-enabled-scope-drift` applies both offline/cache policies with implicit
LDAP auth providers, then explicitly sets the same provider in foreign config.
A same-value production apply independently confirms canonical scope drift while
assignments remain unchanged. After fixture restart and a control snapshot,
disable must refuse specifically for cache `scope mismatch`, leaving raw journal,
file bytes/object identity, administrative config and SSSD generation unchanged.
The post-publication scope protection and ReleaseOnly contract remain intact.
