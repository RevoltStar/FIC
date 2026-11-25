# Debian 13 D13-3C SSH MFA

Branch `main`. The production integration follows the first-publication
preflight in `0043d6e3c78b5a22faecf6ad9f1c36726c94f1b7`.

`NET/SshEdit/ssh_mfa_required` is registered on Debian 13 and ships disabled.
`SshMfaPolicy` proves the desired status in the trusted `NET.conf` generation.
Ordinary and periodic apply, Port and verified release share that requirement
and the `release_ssh_mfa` ownership record. The daemon re-proves the persistent
journal and witness against its live records. Adapter receipts supply
runtime evidence only. The selector ships in the Debian 13 DEB.

## D13-3C follow-up: SSH MFA primary apply ordering (current change)

**Fix:** `Ssh` base class constructor (`fic/src/modules/net/ssh/Ssh.cpp`) adds a
`Recommended` dependency on `NET/SshEdit/ssh_mfa_required` for every ordinary
SSH policy (`ssh_port`, `ssh_max_auth_tries`, `ssh_root_login`,
`ssh_pubkey_auth`, `ssh_use_pam`), but only when
`SshPlatformConfig::sshMfaRequiredSupported == true` (Debian 13 only,
set in `Debian13Profile.cpp`). The dependency carries a
`BackendRequiresCapability("ssh_mfa")` condition so it is skipped when MFA
is explicitly disabled in `NET.conf`, eliminating false warnings.

**Why `sshMfaRequiredSupported` not `SshApplyContract::DebianVerified`:**
`SshApplyContract::DebianVerified` is shared by Debian 12 and Debian 13, but
`ssh_mfa_required` is registered only on Debian 13. Using the contract as the
guard caused Debian 12 to declare a dependency on a non-existent policy, which
failed `validatePolicyDependencyGraph()` and blocked daemon initialization.
The new field is set to `true` only in `Debian13Profile.cpp`, so Debian 12
never declares the dependency.

**Why `Recommended` not `Required`:** `Recommended` orders execution (MFA first)
but never blocks the dependent if MFA fails, and never appears in
`enabledRequiredDependents()`, so disabling MFA while ordinary SSH policies
remain enabled is still allowed. `Required` would create the unacceptable
regression of blocking MFA disable.

**Why `BackendRequiresCapability("ssh_mfa")` condition:** The condition decides
whether the dependency is still required. `Ssh::requiresDependencyCapability`
("ssh_mfa") reads the RAW `ssh_mfa_required.status` key via
`ConfigFileHandler::getValue` — `getPolicyStatus()` normalizes every
non-`ENABLE` value to `DISABLE`, so it must not be used here. Only the
literal `DISABLE` value skips the dependency (no execution, no warning).
A missing key, an empty value and an unknown token (`BROKEN`, ...) keep the
dependency active (fail closed). Old configs without the MFA status key keep
the dependency and are not rewritten by this change.

**Why not single-apply expansion:** The dependency is evaluated by the planner
for any apply path that includes an ordinary SSH policy as a root, including
single `apply NET ssh_max_auth_tries`. This is necessary because without MFA
ownership `Ssh::apply()` fails with `RecoveryRequired`; applying MFA first lets
the operation succeed in one pass instead of failing.

**Tests:** `testSshMfaOrdering` in
`tests/fic/policy/PolicyExecutionPlannerTests.cpp` covers the planner
scenarios with explicit dependencies: (A) batch apply with MFA enabled — MFA
applied first, all policies Applied in one pass; (B) MFA disabled — SSH
policies apply independently, no MFA activation; (C) MFA fails — Recommended
does not block dependent, failure visible as warning, not masked; (D)
`enabledRequiredDependents()` returns empty — MFA disable is not blocked.

Production-class regression tests live in the dedicated
`ssh_mfa_dependency_tests` target
(`tests/fic/modules/net/ssh/SshMfaDependencyTests.cpp`, registered in
`tests/CMakeLists.txt`). It compiles the REAL ordinary SSH policy classes
plus BOTH real Debian 12/13 profile sources (each profile source is compiled
with `-DmakeBuildPlatformProfile=makeDebian{12,13}ProfileForTest`, so one
binary covers both distros regardless of the build platform) and drives the
production registry/planner with a recording executor (no real apply runs):
`testSshMfaStatusSemantics` — the exact five-status table of
`Ssh::requiresDependencyCapability` on all five real policies;
`testSshMfaDisabledSkipsDependencyWithoutWarning` — literal DISABLE skips the
conditional dependency with no MFA result and no WARN;
`testSshMfaDebian12ProfileDependencies` — Debian 12 keeps DebianVerified with
`sshMfaRequiredSupported == false`, no policy depends on the unregistered
MFA, `buildPolicyRegistry` + `validatePolicyDependencyGraph` succeed and a
batch apply runs all five roots in one pass;
`testSshMfaDebian13ProfileDependencies` — Debian 13 declares the exact
Recommended `BackendRequiresCapability("ssh_mfa")` edge on every ordinary
SSH policy, the graph validates with `SshMfaPolicy` registered,
`enabledRequiredDependents()` is empty and batch apply executes MFA first in
one pass. Both original defects were reproduced under these tests by
temporarily re-applying the `DebianVerified` guard and the normalizing
status accessor; the tests failed on both and pass on the fixed code.

First activation preflights the projected PAM and SSH configuration, prepares
the journal, publishes the dedicated auth slot and service, then commits the
SSH image and verifies listener activation. Disable proves an explicit
release against the same configuration generation. It verifies SSH with the
ordinary policy blocks preserved, checks for SSH children and foreign PAM
references and removes only the exact owned PAM files. Final acknowledgement
requires durable DISABLE. A clean initial no-effect failure may discard
its intent. Ambiguous effect retains ownership and requires recovery.

Active or unresolved SSH MFA ownership refuses prepare-uninstall before the
irreversible lifecycle fence. D13-3D covers full package-manager integration
for MFA ownership. Prerequisites and current operator behavior are in
[pam-mfa-d13.md](pam-mfa-d13.md). The SSH adapter and rollback contracts
describe the proof boundaries.

Debian 13 build and unit/static evidence is under
`build-d13-3b/d13-3c-complete-{build,adapter}.log`. Native production
results for local UNIX and LDAP/SSSD are in `d13-3c-port-{local,sssd}.log`.
The fixtures exercised an actual port change to 2222 and independent
release in both directions. The local run also verified periodic apply.
PAM observer and faillock evidence is in `d13-3c-pam-preauth-*.log` and the
native directories named there. Package lifecycle end-to-end and the
distro matrix are outside this gate.
