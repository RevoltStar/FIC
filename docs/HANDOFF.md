# FIC handoff

## Current base

* `main`, `cd2ca68`; current packaging fix uncommitted.

## Current task

* Fixed missing graphics on ALT production standalone prelogin build. Native graphical startup awaits next boot; active user desktop preserved.

## Accepted architecture / invariants

* Five-second automatic handoff applies to all distributions; only xgrp frontend group is ALT-specific.
* Countdown requires verified startup success and renderer readiness. No relaxation of PAM provenance or startup failure handling.

## Completed / changed areas

* RPM build_project now passes FIC_TARGET_PLATFORM=alt-p11 to standalone fic-prelogin as well as daemon. Previous root CMake builds masked this missing packaging flag; production binary excluded xgrp and Qt could not open root:xgrp DRM device.
* PackageLifecycleTests.py exercises actual production build dispatch with stub compiler tools and RPM architecture lookup.
* Built optional RPM through production build_project/build_fic_prelogin_package and installed on 172.17.1.107. Broker SHA256 439509578b4ac2d7aef6d00ed27e3db388d2cb8c06a82cc56919e039cc5ac775 matches build.
* Restored previously managed ALT faillock/password-history topology using existing maintenance commands. Startup now applied69/disabled31/failed0, ok=true. No journal deletion or provenance bypass. Cause of topology disappearing after reinstall remains unestablished.

## Validation

* python3 tests/integration/prelogin/PackageLifecycleTests.py . PASS; bash -n packaging/rpm/build-fic-alt-p11-rpm.sh PASS; git diff --check PASS.
* Actual ALT production standalone configure/build/package PASS; generated ALT_XGRP=true. Artifacts/logs build-prelogin-validation/alt-production/.
* Fresh native SSH and sudo PASS; integration verify PASS; fic/sshd/display-manager active; DM PID2227 preserved. One RPM record; installed broker hash matches new build.

## Remaining / limitations

* Qt DRM rendering and countdown during native boot have not been observed after this fix. No reboot or active desktop interruption performed.
* Same-version RPM replacement returned erase failed (exit1), although correct new binary and metadata installed; do not describe RPM transaction as successful exit0.
* Remote recovery backup /root/fic-graphics-recovery-20261010 contains PAM, mutation journal and old broker. Host remains PASSIVE. No commit/push requested.
