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
config. They verify fresh writes/ownership, foreign compliant no-enrollment,
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
