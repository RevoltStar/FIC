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
After every required run, `collect-evidence.py` retains compressed reports and
`check-evidence.py` checks the complete current-source matrix. A missing result,
source drift, harness drift or failed scenario refuses collection.

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
