# Current task

* Base 60a5a127. Add fic-gui-system-qt alongside the bundled fic-gui.
* One existing Qt6 ELF per target, two staging roots. Both packages expose
  /bin/fic-gui, conflict with each other and depend on matching fic/fic-dick.
* DEB keeps dpkg-shlibdeps Qt requirements. RPM keeps automatic ELF
  requirements and verifies Widgets before publication. Both query runtime
  package ownership of the XCB and JPEG plugins and fail on missing owners.
* System payload has the ELF and the FIC license. The bundled launcher,
  FIC_QT_ROOT, private Qt closure, provenance and source gate stay on fic-gui.
* APT-RPM was observed installing the replacement before erasing the outgoing
  GUI. Both new RPMs check the installed alternative before removing the
  shared symlink in %preun. Older bundled RPMs lack this check and require
  separate remove and install transactions when switching.
* Release validates seven component names/versions per distro and exactly
  five bundled sidecars. System GUI has no bundled manifest.

# Validation

* Host GUI build and six focused CTest checks passed: release composition,
  GUI compliance/license info, private permissions, DEB dependency analysis
  and prelogin packaging. Bash syntax and git diff --check passed.
* Ubuntu 24.04 and 26.04 each built both real GUI DEBs from a single build.
  SHA-256 of the ELF matched between variants. Fresh install/remove and
  bundled -> system -> bundled passed with APT/dpkg and Xvfb.
* ALT p11 built both real GUI RPMs. The system package has libQt6 ELF
  requirements, libqt6-gui plugin ownership dependency and License SUL-1.0.
  After the symlink fix, fresh install/remove and both APT-RPM switches
  passed with Xvfb, including preservation of the link and core fixtures.
* The isolated GUI tests use real GUI packages and minimal same-version
  fic/fic-dick fixtures. They verify native transaction order, payload, link,
  group access, and loaded Qt libraries and plugins. They do not exercise
  daemon lifecycle or live IPC.
* Debian 12 and 13 builder preparation stalled or retried downloading APT
  package indexes. Both attempts were cancelled after more than ten minutes,
  before GUI compilation.
* Full release build, hosted CI and full FIC package lifecycle were not run.
  Local receipts: /tmp/fic-gui-matrix/*.log.

# PAM follow-up in progress

* Base 13fb1a17. P1 started with the shared Prepared recovery check.
  Recovery from the previous strategy now requires the matching physical ID
  for an ID-bound manager before it restores Applied. The regression test
  supplies a physical ID independent of the ID passed to bind.
* pam_capability_activation_policy_tests built and passed in build-prelogin.
* P1 ALT marker grammar, legacy provenance, partial publication recovery and
  native package gates are pending. P3 audit and P2 report follow P1.
* P1 implementation adds ALT v1 journal domain and target-bound boundary markers.
  Host fixture tests passed (activation, journal and both ALT topology suites).
  Native ALT configure stopped at missing nlohmann_json in the cached image.
  Native control and package lifecycle gates remain outstanding.
* P3 removed the ID-less undoPamCapability overload (only six fixture calls)
  and an unreferenced static slot-writer ownership flag. Production release
  already passes record.id. Legacy inspection and refusal paths remain needed
  for package/recovery checks. The old paired-slot writer still has direct
  tests and was retained. All four Debian/Ubuntu profiles select mutable C2
  for supported password topology. ALT has its own history manager and
  static passwdqc topology. Docs and stale profile comments distinguish these.
* rollback_executor_tests built. Both PAM cases passed, but the complete
  executable failed its mode-and-owner case with "test identity lookup
  failed". platform_profile_tests passed.
* Native ALT p11 retry installed build dependencies in the disposable
  container and compiled both ALT manager suites. The image has no ctest,
  so both binaries were then run directly in a fresh ALT p11 container.
  Both passed, including fixture ID/partial-publication checks. The existing
  --live-alt-enable round trip passed on container PAM, using legacy markers.
  The ID-bound production control-mode and final erase/reinstall gates
  still require native lifecycle validation.
* P2 report: docs/pam-alt-pwhistory-parameter-rollback.md. Recommendation A,
  preserve dedicated config semantics. No P2 production changes.
* P1 follow-up routed ALT final erase domain release through the existing PAM
  rollback backend. The former direct manager disable skipped journal
  provenance and could not release v1. The later uninstall policy phase
  still retires the journal record after proving absence.
* Added a legacy -> release -> v1 fixture and adapted the existing ALT
  production control probe to check physical/journal ID agreement and
  Prepared recovery after one published target. Six focused CTests passed,
  including pam_dependency_contract_tests. PackageReleaseResources.cpp
  compiled separately. The updated native control gate attempt timed out
  at ALT apt-get update (exit 124), before the full build.
* Pending native commands with the test images prepared per the harness:
  FIC_PAM_GATE_STAGE=i5 bash tests/integration/pam-dependencies/run-i1.sh alt-p11 alt-p11 build-pam-p1-alt
  bash tests/integration/pam-dependencies/alt-control.sh build-pam-p1-alt --i5
  bash /src/tests/integration/package-lifecycle/build-rpm.sh 0.1.0
  bash /src/tests/integration/package-lifecycle/build-rpm.sh 0.1.1
  bash tests/integration/package-lifecycle/run-rpm.sh fic-package-native:alt-p11 build-pam-p1-alt/lifecycle-packages
  Arrange 0.1.1 RPMs in upgrades/ before the lifecycle run. The RPM build
  commands run inside the matching builder with /src and /build mounts.

# ALT PAM P1 follow-up

* Compensation now includes the current faillock target when its writer
  returns false, since rename can precede the failed directory fsync.
  History uses the same local compensation path after writer failure on
  activation/release and after a failed activation postcondition. Trusted
  reread, existing CAS, original-byte no-op and CRITICAL on unknown or
  unconfirmed recovery remain in force. Shared PAM snapshot writers already
  compensate every attempted write and were left alone.
* ALT package preflight accepts an incomplete topology only for a Prepared
  v1 faillock record with a nonempty proper subset of exact-ID targets.
  It runs the same read/placement/candidate checks as release, then returns
  before writing. The rollback path repeats those checks under lock.
* Tests use the AtomicFileWriter post-rename fsync hook and assert candidate
  bytes were physically published at injection time. Both targets are
  covered before and after rename, as are history enable and disable.
  Partial proof tests cover correct ID, wrong ID, malformed marker and
  missing target, and check that preview leaves PAM bytes unchanged.
* Five focused CTests passed. PackageReleaseResources.cpp compiled.
* Existing ALT cache has the earlier topology test binaries only. The image
  fic-client-access:altp11 lacks systemd, ctest and build dependencies.
  The initial bounded apt-get update succeeded in 49 s. Full native control
  and RPM lifecycle require the builder/runtime dependencies and current
  artifacts. See the native commands above.
