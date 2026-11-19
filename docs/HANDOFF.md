# ALT PAM post-rename compensation and package preflight

* Branch main. Follow-up base 8af70c49. No push.
* 6ac53d63 includes the failing write in faillock compensation and reuses
  history compensation for enable/disable writer errors. Writer failure after
  rename can leave candidate bytes. Restore only matching candidate bytes
  using the existing CAS and trusted metadata checks, leave original bytes
  alone, and report CRITICAL if compensation cannot be proven.
* 31ae61aa requires read-only proof of partial topology at package preflight.
  Only an exact-ID proper subset under Prepared v1 faillock provenance is
  eligible. The check shares strict target, marker and placement checks with
  release, which repeats proof under lock. Complete and legacy paths retain
  their existing journal/physical matching rules.
* Existing ALT control and RPM suites now assert physical marker IDs, including
  across strategy transitions and upgrades. RPM runner accepts the explicit
  private PID namespace reported by Podman, and its test image declares the
  SQLite Python stdlib subpackage required by the hardware check.

## Verification

* Five CTests passed in build-prelogin (journal, platform, activation policy,
  ALT faillock and history). Fsync fixtures observed candidate bytes before
  refusing durability for first/second faillock targets and history
  activation/release. Existing concurrent modification and compensation
  failure cases passed. Partial proof accepts matching ID, preserves bytes,
  and rejects wrong IDs, malformed markers and unreadable targets.
* PackageReleaseResources.cpp compiled. git diff --check, bash -n for the
  RPM runner, and Python syntax checks passed.
* Native ALT p11: production daemon, PAM transaction module and control
  probe built. Expanded I5 checker passed with control modes, matching IDs,
  strategy round trip, legacy release then v1, wrong/malformed markers,
  partial recovery and retained third-party history. Evidence:
  build-pam-p1-alt/followup-control-expanded.json.
* Production RPMs 0.1.0 and 0.1.1 built. Two full native RPM gate attempts
  passed fresh install and reached exact-version reinstall, then reproduced
  sqlite3.DatabaseError: database disk image is malformed in the existing
  hardware_inventory.collected assertion, before PAM activation.
* A separate PAM-focused invocation of the existing RPM driver passed with
  only the unrelated hardware inventory subscenario omitted. It used the
  identical RPMs and actual scriptlets/daemon in an isolated systemd runtime.
  Verified fresh install, both capability activations, 0.1.0 -> 0.1.1
  preserving IDs, release restoring original target bytes, erase, reinstall
  with fresh IDs and direct erase with active v1 topology. Legacy transition
  was proven through native control, not a legacy RPM upgrade. Full gate
  still fails on the inventory check. Host PAM was untouched.

## Reproduction / evidence

* Native images: localhost/fic-p1-followup-runtime:altp11 (build/control)
  and localhost/fic-p1-followup-systemd:altp11 (runtime with pam-config 1.10
  and Python sqlite3). Bounded APT preparation succeeded.
* Use the production builders build-rpm.sh 0.1.0 and build-rpm.sh 0.1.1
  from tests/integration/package-lifecycle inside the ALT builder with
  /src and /build mounted. Put the 0.1.1 artifacts in upgrades/.
* Full gate: run tests/integration/package-lifecycle/run-rpm.sh with
  localhost/fic-p1-followup-systemd:altp11 and
  build-pam-p1-alt/lifecycle-packages. On this machine set DOCKER_HOST to
  the rootless Podman Docker socket. Logs: /tmp/fic-p1-rpm-lifecycle-sqlite.log
  and /tmp/fic-p1-rpm-lifecycle-repeat.log.
* Scoped diagnostic driver and result: /tmp/fic-p1-pam-rpm.QMpIrp
  (copy of the same harness with the unrelated hardware subscenario removed).
  Transcript: /tmp/fic-p1-rpm-pam-focused.log.
* Native control harness: tests/integration/pam-dependencies/alt-control.sh
  build-pam-p1-alt --i5 with the matching test image alias. Transcript:
  /tmp/fic-p1-follow-native-final.log.
