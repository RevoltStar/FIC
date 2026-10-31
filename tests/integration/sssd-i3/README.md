# SSSD I3 native gates

These are real stock SSSD/systemd PID1 observations, separate from historical
R1/R2/I1/I2 evidence. The production adapter is standalone: no policy SUCCESS,
ownership, journal, rollback or package lifecycle integration. See the
[authoritative proof contract](../../../docs/sssd-verified-activation-design.md).

The five `reports/<platform>.json` files contain raw commands/observations;
`evidence.json` binds them to source hashes, probe hashes and disposable image
identities. `check-evidence.py` validates retained artifacts only. Ordinary CTest
never starts Docker. `source-review.json` contains versioned distribution-source
anchors; source matches alone are not runtime proof. Full Git history is required
for the unchanged historical-source I1/I2 evidence guards; current I1 reruns are
retained separately in `i1-regressions.json` and `reports/i1-*.json` (43
observations per Debian/Ubuntu, 58 on ALT), not replacements for their old evidence.

## Reproduction

Use the corresponding existing I1 native build images. Docker was explicitly
accepted instead of Podman. For each tag/platform pair:

| tag | platform |
|---|---|
| debian12 | debian-12 |
| debian13 | debian-13 |
| ubuntu2404 | ubuntu-24.04 |
| ubuntu2604 | ubuntu-26.04 |
| alt-p11 | alt-p11 |

```sh
docker build --build-arg BASE_IMAGE=fic-sssd-i1:debian12 \
  -f tests/integration/sssd-i3/Containerfile -t fic-sssd-i3:debian12 \
  tests/integration/sssd-i3
DOCKER_CONFIG=/tmp/fic-package-docker-config \
  tests/integration/sssd-i3/run-native.sh fic-sssd-i3:debian12 debian-12
# Repeat the other four rows, then:
python3 tests/integration/sssd-i3/collect-evidence.py
python3 tests/integration/sssd-i3/check-evidence.py
```

The Containerfile installs test-only local LDAP/TLS and tracing utilities. It
does not modify FIC packaging. Native package inventories identify the actual
SSSD revisions; the adapter refuses other revisions. Build mounts source RO and
build output RW in a separate unprivileged build container. Runtime containers
have network=none/loopback only, private cgroups, `/run` and `/tmp` tmpfs, no host
binds/ports and real systemd PID1. Guards reject an accidental host run.

Fixture preparation creates private `/etc` and `/run` mount boundaries, prepares
native metadata by native fixture restart, quiesces only unrelated console-getty
and supplies synthetic configuration/users/LDAP credentials. It never replaces a
stock SSSD unit for positive gates. Production never performs those preparations
or seeds tool hashes. The probe seeds an isolated `/run/sssd-i3` trust store only.
ALT's stock missing optional EnvironmentFile is separately refused; the supported
positive fixture explicitly provides native DEBUG_LOGGER configuration. This is
not evidence that the missing-input case is supported.

Source manifests are captured **before** building. If any compiled/fixture input
changes during the run, its result is discarded. `completion.json` is written
only after the guarded runner exits zero and the source manifests match. Raw
reports are exported with `docker exec`, since systemd's runtime `/run` mounts
are not reliably visible to Docker's archive/cp view. Intermediate development
runs are not accepted as final evidence.

## Measured results and bounds

All five have positive A/B/source-causal-C/P, independent generation/process/
ConfigDB/UNIX-peer evidence, clean cleanup and no residual mounts. Modern backend
proof additionally records the exact unique central-bus owner, a PID binding and
post-target-initialization IsOnline response. The IsOnline boolean here describes
only the protocol state; it does not turn the availability probe into auth proof.
PAM GET_VERSION is an authenticated-by-kernel-credentials availability observation,
not a password operation. Required lazy-only PAM topology remains Unsupported.

There are 56 observations on Debian12/Ubuntu24 and 58 on Debian13/Ubuntu26/ALT. They include:

* positive full graph, protected RO write rejection, absent main/conf.d, cache
  disabled, two LDAP roots and backend-only selected semantics;
* rejection before dispatch for forged expected values, missing EnvironmentFile,
  lazy-only PAM, provider/relation conflicts, xattrs, stopped service and
  shared/shared-slave publication parents; modern central-bus unsafe-parent and
  foreign-ACL refusals also occur before dispatch;
* deterministic unit changes before/after restart, snippet inode replacement,
  pre-opened writable source FD, mount event, SIGSTOP monitor/PAM/backend,
  stale live ConfigDB test fixture and incomplete cleanup;
* C Proven/P Drifted for hidden-source/inode/negative/env/persistent changes;
  P Proven/B-C NotProven after a consumer is suspended after protected C;
  CleanupFailed with successful primary activation and residual mount, never
  SUCCESS. The intentionally injected residual is confined to its container,
  which is removed by the runner trap.

R2's **unchanged** local LDAP/TLS/native PAM fixture is reused. Every one of its
four SSSD generations also passes I3 before synthetic functional requests:
online/offline password, cached-auth reuse, caching disabled, wrong-password
rejection and aged offline-credential expiration. Cache timestamp manipulation
is fixture-only with SSSD stopped. Production does not execute these requests,
modify caches or claim that a GET_VERSION/IsOnline probe proves authentication.

`diagnostics/ubuntu2604-*` retains a real rejected run and strace: unrelated getty
published/removed `/run/credentials/getty@tty1.service`. The namespace observer
correctly refused SUCCESS. The positive fixture stops only that unrelated unit;
no observer exception was added. Earlier OverlayFS maps-device mismatch was
resolved through kernel `/proc/PID/map_files` object identities.

No bare-metal, enforcing LSM, Podman, other architecture/kernel, AD/IPA/trust,
smartcard/passkey or lazy-only selected-PAM support is established. Root-owned
code/package metadata/native tools are trust prerequisites; this proof does not
protect against a malicious privileged writer forging the trusted program.
Protocol/process/source observations have finite observation windows and cannot
promise future process survival or LDAP availability. Existing generic mount
cleanup identity-check/umount residual race remains documented and unchanged.

The collector and validator do not grant policy coverage or ownership authority.
I4 still needs journal-backed CAS/Apply/REFRESH/recovery; I5 verified release;
I6 policy registration/dependencies and client/end-to-end integration.

## Input Proof A follow-up

Publication alone is a validated local prerequisite. A is promoted only after
complete successful source-causal runtime proof; neither publication nor restart
dispatch is sufficient. The pre-fix saved-evidence RED is retained in
`input-proof-red.txt` (base ad41b954b009989cf9b12bed6fade17c1b7d2e9e).

The five-platform native rerun adds the existing `timeout-published` hook and
asserts A/B/C NotProven before restart, A NotProven with incomplete consumer proof
after dispatch, full A/B/C/P on success, historical A/B/C with P drift or cleanup
failure, and historical A with current B/C invalidation after cleanup. The
retained-evidence guard additionally correlates A with the existing `semantics`
checkpoint, which is reached only after full runtime proof. B/C/P contracts,
generic engine, SSH and runtime proof implementation are unchanged.
