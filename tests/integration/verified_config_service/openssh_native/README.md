# Real OpenSSH native validation

Disposable native validation, including the independent production SSH adapter.
Includes real Debian SSH policy apply/journal/receipt scenarios in the disposable
container. No host SSH operations, host policy apply, host rollback or vendor unit edits. Run from the repository root, using **trusted disposable
systemd images**. Docker must support privileged containers and private cgroups.
The test stops/restarts **container** `ssh.service`; management is `docker exec`.

## Reproduce

The measured images were `fic-ssh-audit:debian12` / `:debian13` with the exact
versions recorded in [the report](../../../../docs/verified-config-openssh-native-validation.md).
To prepare equivalent native-only images (package availability may require an
appropriate Debian snapshot/archive repository):

```sh
docker build -f tests/integration/verified_config_service/openssh_native/Containerfile \
  --build-arg BASE_IMAGE=debian:12 \
  --build-arg OPENSSH_VERSION=1:9.2p1-2+deb12u10 \
  --build-arg SYSTEMD_VERSION=252.39-1~deb12u2 -t fic-openssh:debian12 .
docker build -f tests/integration/verified_config_service/openssh_native/Containerfile \
  --build-arg BASE_IMAGE=debian:13 \
  --build-arg OPENSSH_VERSION=1:10.0p1-7+deb13u4 \
  --build-arg SYSTEMD_VERSION=257.13-1~deb13u1 -t fic-openssh:debian13 .
bash tests/integration/verified_config_service/openssh_native/run-native.sh \
  fic-openssh:debian12 debian-12
bash tests/integration/verified_config_service/openssh_native/run-native.sh \
  fic-openssh:debian13 debian-13
```

This Containerfile is a reproducible recipe, not a claim that it was rebuilt in
the recorded run. That run used the existing images above; their immutable IDs
are in the evidence. A rebuilt/newer image requires a new measured report.

The runner compiles unprivileged with source read-only; runtime containers have
no source/build/host mounts, no network except loopback, no published ports,
and private PID/mount/cgroup contexts. It checks Docker inspect, uses an explicit
random marker, and records caller namespace/root identities. Both Python and C++
refuse a missing marker, caller root/namespace, non-systemd PID1 or non-loopback
network. Running as root alone is not sufficient. No option disables these gates.

Only `/run/fic-openssh-results` is exported, through `docker exec tar` (Docker cp
cannot reliably see systemd's remounted `/run`). Keys, backups, request references
and trust setup stay in a separate work directory and are destroyed with the
container. Existing readable host SSH file hashes/absence are compared before
and after; host SSH is never invoked. EXIT removes the runner's own container.

## Components and evidence

* `harness.py`: safe input preparation/backup/restore, diagnostics, conservative
  test-language Include analyzer, actual loopback identification/KEXINIT, proof
  classification and negative/concurrency tests. It does not parse shell or
  emulate systemd argument expansion. Real systemd + OpenSSH evaluate test opts.
* `Driver.cpp`: links actual production sources; public `activate()` for normal
  tests, existing test-only hooks for faults. Preflight uses actual launch reader,
  SystemdActivation, trust/namespace/topology/tree checks and SshConfigAudit.
  Only guarded fixture provisioning enrolls the container's systemctl.
* `collect-sources.py`: downloads exact .dsc/archive files from Debian, checks
  archive hashes/sizes and applies Debian patches via dpkg-source. It does not
  install packages. The recorded host lacked the signer key; descriptor PGP
  signature verification is **NOT_VERIFIED**, not implied by SHA/HTTPS.
* `collect-evidence.py`: combines sanitized results and source hashes; never
  reads key backups or arbitrary container environment.

```sh
python3 tests/integration/verified_config_service/openssh_native/harness.py --self-test
python3 tests/integration/verified_config_service/openssh_native/collect-sources.py \
  build-openssh-native/sources
python3 tests/integration/verified_config_service/openssh_native/collect-evidence.py \
  build-openssh-native docs/verified-config-openssh-native-evidence.json
```

Root CTest includes the read-only `--self-test`. Privileged real SSH scenarios
run only through the explicit Docker runner. Existing standalone regression
runner remains mandatory on all five distributions; no assertions are weakened.

## Interpretation

Each generic scenario reports A (caller-declared snapshot inputs), B (new verified sshd
readiness), C (full SSH configuration semantics), C_selected (selected fixture
expectations), plus persistent reference bytes/manifests after cleanup. Full C
remains NOT_PROVEN on normal positives and FAILED for demonstrated semantic
counterexamples. C_selected PROVEN is bounded to the fixture's selected behavior
and tested Include language. No authenticated session or full KEX is performed.
`sshd -T` is a separate-process diagnostic, never evidence of running sshd bytes.

The original report/evidence preserves the pre-fix OverlayFS refusal and its
fresh-file/new-directory fixture restriction. The current xattr follow-up runs
30 scenarios and removes that restriction: main and EnvironmentFile are written
in place, all Includes use the stock `/etc/ssh/sshd_config.d`, including an exact
nonempty manifest. Both copied-up file/directory preflights must be SUPPORTED,
followed by public activation of the real stock ssh.service. No production
xattr names are filtered/deleted. See the report's bounded-xattr follow-up.

After `CleanupFailed`/SIGKILL the activator must refuse residuals; a separate
guarded **fixture administrator** cleanup removes only known test mounts.
It never turns the original result into Success. Original FD/glob writes may
leave persistent reference bytes wrong even while A+B and C_selected
were established. See the report for the full matrix and limits.

## SSH adapter v1 gate

The runner additionally executes 30 independent adapter cases on each Debian.
Existing 30 generic cases remain unchanged. Adapter references are built only
from known synthetic fixtures, with all five existing FIC policy expectations
(UsePAM/PubkeyAuthentication yes, root login no, MaxAuthTries 3, port 2222).
Adapter C proves only the explicitly selected policies, not generic full SSH C.
The result JSON stores adapter_cases separately, with A/B/C/P, actual old/new
process identity and socket-to-new-MainPID attestation. Five positives, two
runtime-success/persistent-drift cases and strict preflight/runtime/cleanup
negatives are required by the collector. See docs/ssh-verified-activation-adapter.md.

## Production module path

`module_cases` in exported results call the five actual policy classes and
`Ssh::apply()` with a real isolated MutationJournal and trusted fixture policy
config. They verify fresh writes/ownership, foreign compliant owned enrollment,
new PID/invocation/listener, repeated receipt no-op, stale receipt invalidation,
pre-CAS refusals and post-save uncertainty/provenance. A deterministic test-only
save observation hook injects writer/durability/runtime/journal faults; the
production binary contains no such hook. Real systemd start limits are preserved;
the production bounded restart budget avoids consuming the stock burst.

This is module end-to-end evidence, not complete daemon/package/M1 admission,
PAM login or a cross-kernel/VM proof. Generic/adapter experiments retain their
own independent results. Only sanitized diagnostics/results are exported.

## Ubuntu socket activation

The same driver links the real five policy classes and MutationJournal. The runner
selects `ubuntu_socket.py` for `ubuntu-24.04` / `ubuntu-26.04`; fixture administrative
enablement is separate from production actions. It starts with socket enabled/active,
service disabled/inactive and explicitly probes absent `/run/sshd`. No host SSH.

```sh
bash tests/integration/verified_config_service/openssh_native/run-native.sh fic-ssh-audit:ubuntu2404 ubuntu-24.04
bash tests/integration/verified_config_service/openssh_native/run-native.sh fic-ssh-audit:ubuntu2604 ubuntu-26.04
```

Fixture keys/trust stay inside the container. Exported results contain policy outcomes,
provenance facts, invocation/source fingerprints and bounded diagnostics. Tests check
native effective values, kernel listeners/old inode disappearance, PID1→sshd inherited
FDs, no-op, safe foreign inputs, fail-closed runtime/launch/config states, CAS/durability/
unknown writer/journal failure/Prepared and active-refusal/offline ownership release.
Adapter fault cases use existing deterministic engine checkpoints rather than timing races.
The audit under `ssh-ubuntu-socket-research` remains separate evidence, not policy PASS.


## ALT p11

The same runner selects `alt_service.py` for `alt-p11`. It links the real five
policy classes, journal and adapter; stock vendor `sshd.service` remains unchanged.
Fixture provisioning initializes the stock keys by starting the vendor unit, then
seeds executable trust only inside the guarded disposable container. Production
requires all stock key pairs to exist safely; it does not initialize missing keys.
The optional administrator Include tree is never created by production.

```sh
bash tests/integration/verified_config_service/openssh_native/run-native.sh fic-ssh-audit:alt-p11 alt-p11
```

The default `all` phase is the acceptance gate. Fixture-only
`FIC_ALT_NATIVE_SCENARIO=rollback|activation` permits focused debugging; a partial
phase PASS is not full acceptance. Production has no corresponding bypass.
The runner also builds/runs portable pure adapter contract tests on each platform.
ALT contract, image/package observations, readiness, rollback limitations and
sanitized production evidence: [ALT p11](../../../../docs/alt-p11-ssh-verified-activation.md).

## Verified release and real package/SSH administration

The current lifecycle release gate is separate from the historical adapter/module
experiments above. It runs the production five-policy registry, DisableFlow,
MutationJournal and verified engines. `release` has 30 groups (5 positive,
20 fault/crash/disable-ACK, 5 admission/legacy); `release-plan` exercises preview
without CAS. Group selection is a harness option, never a production bypass.

```sh
FIC_SSH_NATIVE_SCENARIO=release FIC_SSH_NATIVE_RELEASE_GROUP=all \
  bash tests/integration/verified_config_service/openssh_native/run-native.sh \
  fic-ssh-lifecycle-native:debian12 debian-12
bash tests/integration/verified_config_service/openssh_native/run-remote-package.sh \
  fic-ssh-lifecycle-native:debian12 debian-12 /absolute/path/to/deb-artifacts
```

Repeat with debian13/debian-13, ubuntu2404/ubuntu-24.04,
ubuntu2604/ubuntu-26.04, alt-p11/alt-p11. ALT remote uses derivative image
`Containerfile.remote` with test-only openssh-clients and the RPM artifact directory.
The package runner installs real artifacts, uses actual daemon admission and
CLI/IPC, and removes them (DEB also purges). No installed-state forging. A single
previously authenticated loopback SSH ControlMaster performs all commands;
ProxyCommand=false prevents reconnect after Port changes. Its survival is measured,
not inferred from vendor KillMode. Fixture keys are never exported.

Only the isolated test namespace provisions private directory mount boundaries,
trusted keys, daemon config, service startup and test udev readiness. Production
never prepares those boundaries or installs/enables/starts missing SSH providers.
No host SSH files, ports, systemd, PAM or security state are changed. These five
userlands share the Docker/WSL kernel, and loopback connection evidence is not a
promise for arbitrary external networks or custom unit topologies.

Current contract: [adapter](../../../../docs/ssh-verified-activation-adapter.md#verified-configuration-release).
Sanitized results, case composition, actual packages and limitations:
[evidence](evidence/release-lifecycle.json). Raw logs remain in ignored build dirs.

Initially compliant ownership gate (all five native platforms):

```sh
FIC_SSH_NATIVE_SCENARIO=refresh FIC_SSH_NATIVE_REFRESH_GROUP=ownership \
  bash tests/integration/verified_config_service/openssh_native/run-native.sh IMAGE PLATFORM
```

Existing lifecycle runner tests matching foreign
values, native defaults, owned no-op, REFRESH preserving Port fingerprints/IDs,
active release and byte-exact restoration. Ubuntu additionally checks unchanged
socket state for same-endpoint Port publication and kernel/PID1/MainPID FD proof.

Matching active Ports in the permitted Include graph now receive creation-bound
per-file wrappers. The existing `ownership` group checks owned publication,
repeat no-write and exact release for this case. Paths/grammar and scalar policy
semantics are unchanged.
Native defaults are tested only within the existing policy domain; MaxAuthTries6
and UsePAMno remain rejected values.

Multi-file Port gate (same native runner, no host SSH changes):

```sh
FIC_SSH_NATIVE_SCENARIO=refresh FIC_SSH_NATIVE_REFRESH_GROUP=multifile \
  bash tests/integration/verified_config_service/openssh_native/run-native.sh IMAGE PLATFORM
```

`multifile-smoke` selects the first apply/reapply/REFRESH/active-release case.
The full group checks multiple/matching/nested/repeated Includes, Match context,
new Port ownership on same-value refresh, disconnected paths, missing/modified
wrappers, active/offline release with foreign edits and missing final LF, exact
first/second CAS refusal, partial publication/durability/checkpoint failures,
native validation failure after publication, cleanup, crash/restart shared gate,
and trusted-path/glob/mount/alias/orphan refusals. Initial Prepared has explicitly
absent previous ownership. Runtime observations check actual controlled ports;
Ubuntu additionally verifies PID1/MainPID FD ownership. Restored duplicate endpoints
remain unsupported. Test-only cleanup never resolves semantic Prepared state.

The remote package fixture uses two real Include inputs, production CLI/IPC,
refresh, disable, re-enrollment, uninstall rollback and remove/purge over the
same pre-existing authenticated control connection; it checks all wrappers gone.
Historical evidence above is not proof of this new source generation.

Source-bound results: [multi-file lifecycle evidence](evidence/multifile-port-lifecycle.json).
The `ownership` group additionally checks initially matching Include Port and
no-final-LF restoration; run it on each platform alongside `multifile`.
Raw reports stay in ignored build directories; only compact hashes and results
are committed, without compressed report blobs.

## SSH Manager.Environment I1

Production classification remains in the SSH adapter, not in the generic engine.
The supported locale/PATH/XDG grammar and trust boundary are authoritative in
[ssh-verified-activation-adapter.md](../../../../docs/ssh-verified-activation-adapter.md#managerenvironment).
The original full sorted manager environment remains pinned; no equality filtering
or normalization is permitted.

Two additional guarded scenarios reuse the existing driver/hooks and runner:

```bash
FIC_SSH_NATIVE_SCENARIO=environment \
 FIC_SSH_NATIVE_BUILD_DIR="$PWD/build-ssh-i1/ubuntu-26.04" \
 bash tests/integration/verified_config_service/openssh_native/run-native.sh \
 fic-package-native:ubuntu2604 ubuntu-26.04

FIC_SSH_NATIVE_SCENARIO=environment-cli \
 FIC_SSH_INSTALL_ROOT="$PWD/build-pam-i1/ubuntu2604/i1-install" \
 FIC_SSH_NATIVE_BUILD_DIR="$PWD/build-ssh-i1/ubuntu-26.04" \
 bash tests/integration/verified_config_service/openssh_native/run-native.sh \
 fic-package-native:ubuntu2604 ubuntu-26.04
```

`environment` checks three accepted environments, 21 full-contract mutations
(seven changes at admission/publication/post-restart hooks), and an unknown-key
refusal before SSH configuration/journal mutation. Only safe synthetic variables are
injected into the disposable manager; loader negatives are pure unit fixtures.

`environment-cli` uses actual current-build CMake-installed fic, fic-cli,
fic-dick and infrastructure helper/resources. Prepare the staging root using
`DESTDIR=/build/i1-install cmake --install /build --component COMPONENT` for
`fic`, `fic-cli`, `fic-dick` in the same native build image with `/src` mounted.
It runs the real daemon and `fic-cli policy apply NET ssh_use_pam` for the R1
locale/PATH baseline and the reported Flatpak XDG combination; verifies owned
block, durable applied record, process/listener identity, -t/-T, repeat no-op and
RuntimeVerified disable with exact persistent restore. This is **not a DEB
package-manager installation/lifecycle test**. Other policy statuses are disabled
in the fixture administrative configuration; GLOBAL recovery/incident defaults
remain. Production lifecycle admission/proofs are not bypassed. PAM payloads are
installed root:root0644 as in packaging, independent of checkout mode bits.

Runtime containers have systemd PID1 explicitly, private namespaces, no host
binds/ports/network and the existing root/ns/marker guard. CMake payload staging
preserves the runtime image's usr-merge directory symlinks. No operations target
the SSH-only research VM or host policy configuration.

When reusing the general native build images for Debian, add the `ss` diagnostic:

```bash
docker build -f tests/integration/verified_config_service/openssh_native/Containerfile.environment-runtime \
 --build-arg BASE_IMAGE=fic-package-native:debian12 -t fic-ssh-i1-native:debian12 .
# Same recipe with debian13. No host packages are installed.
```

Run the unchanged default platform suites and release/refresh/release-plan
scenarios as applicable. The Ubuntu foreign-Include Port case now expects the
already implemented multi-file wrapper contract, rather than the obsolete
single-file refusal; it verifies the included ownership payload explicitly.
New I1 receipts do not update or reinterpret historical source-bound evidence.

I1 final results (2026-11-09): Debian12/13 each 30 generic +59 adapter +24
module groups PASS; Ubuntu24.04/26.04 each52 groups PASS; ALT p11 65 groups
PASS. Existing multi-file Port apply/repeat/REFRESH/active RuntimeVerified release
smoke additionally PASS on all5. Environment gate25 groups and actual daemon/CLI
2 cases PASS. Raw results: ignored build-ssh-i1/PROFILE/evidence; compact receipts:
[ssh-manager-environment-validation.json](../../../../docs/ssh-manager-environment-validation.json).

Full Ubuntu26 build PASS. Correctly configured full CTest:220 PASS,2 FAIL,4
opt-in native SKIP (226 total). Unrelated failures remain explicit:
incident_state_lifecycle_static_checks (same failure on clean I1 base, old RPM
manifest string check) and identity_policy_hierarchy_tests (unchanged PAM-only
target expects obsolete Recommended rather than Required activation dependencies).
Initial Git trust/DAC-capability test-environment failures were resolved before
this final full run. No unrelated PAM/package code was changed to green the suite.

SSSD retained I3/I4/I5 source-bound checks and I6 historical checks PASS, without
native reexecution. PAM I6 current-source checker rejects retained receipts: the
manifest already differed from those receipts on the I1 base, and differs again
after I1. No historical receipt/hash was replaced or evidence gate weakened.
The Debian fsync fault case now asserts the failed operation and unusable-at-return
state separately from the existing diagnostic tryGet() durable recovery, retaining
the first exact record; it no longer asserts permanent journal poisoning after
the injected fault has been removed. Production journal/recovery is unchanged.
