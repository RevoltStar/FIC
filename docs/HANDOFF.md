# Current workspace

## Current base / task
* Branch `main`; base `bcf13593ce883123fea183b580703af12f75e4b4`.
* Cleanup diagnostics complete. Requested single commit:
  `fix(service): expose verified activation cleanup failure details`. No push.

## Accepted architecture / invariants
* Diagnostic-only change. Existing reverse cleanup, namespace/identity/source/type
  checks, ordinary umount2(..., 0), propagation, residual handling, success predicate,
  SSH proof/status and Prepared/release contracts remain.
* No retry, lazy/forced unmount, adoption, journal/schema change, recovery or attempt
  to repair/inspect the working computer's residual mounts. Incident cause unknown.
* cleanupErrors include target/stage/reason and immediately saved errno/strerror
  for syscall failures; logical mismatches have no fabricated errno.
* activationDiagnostic preserves primary result/diagnostic and all cleanup errors.
  SSH activation/snapshot/release forwards it through existing Ssh/ERROR Logger;
  later diagnostic failures cannot overwrite already-known cleanup details.

## Completed / changed areas
* VerifiedConfigServiceActivator h/cpp; mount-support diagnostics; SSH adapter.
* Generic unit/native regressions (EBUSY, foreign identity, multiple faults,
  primary+cleanup error, successful cleanup); existing SSH native suites strengthened.
* Focused `openssh_native/cleanup_diagnostics.py` exercises actual policy→Logger→
  journald, success, verified release and read-only snapshot cleanup failure.
* Authoritative contract/results: `docs/verified-config-service-activator.md`,
  `docs/verified-config-cleanup-validation.md`; native README reproduction.

## Validation
* Local affected production `fic` and unit target build PASS (`build-startup-classification`).
  No PAM stubs; real local libraries. Generic and SSH unit CTest 2/2 PASS with
  read-only netlink access; initial sandbox-address-enumeration failure not a regression.
* Debian12 real systemd generic native suite: 208 PASS / 0 SKIP, including real
  held-descriptor EBUSY, foreign mount preserved, all error targets and primary status.
* Focused SSH native: 4/4 PASS. Exact captured FIC ERROR also exists in journald;
  Prepared retained; successful apply has no cleanup errors; active release and
  read-only snapshot errors fully exposed. OpenSSH 1:9.2p1-2+deb12u10, systemd 252.39.
* Existing release-plan suite plus snapshot-cleanup case: 9/9 PASS, active/offline
  and syntax guards preserved. SSH unit suite also PASS in native build container.
* Runtime isolation inspected: private namespaces/cgroups, network none, no host
  binds/ports/volumes; sysfs/proc-sys RO before PID1. Docker now available via
  `/mnt/wsl/docker-desktop/cli-tools/usr/bin/docker`; no user resources cleaned.
* Python/shell syntax and git diff --check PASS. Logs `/tmp/fic-cleanup-diagnostics/`;
  exact reports in `build-cleanup-native/evidence/`, paths documented in validation.
* Initial fixture-only snapshot failures fixed without relaxing production admission:
  unsupported expectation removed; residual case observes service without re-admission.

## Remaining / limits
* No unfinished implementation. No new full platform/package/PAM matrix or full
  project CTest. No real-machine SSH apply or original incident-mount investigation.
* Underlying shared-cleanup cause remains unknown and is intentionally not fixed.
* Existing mount-ID check→umount residual race and local-only shared cleanup boundary
  remain; no propagation/namespace/topology or global cleanup guarantee added.
