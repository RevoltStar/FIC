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
