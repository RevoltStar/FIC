# Current workspace

## Current base
* Branch `main`, base `50e0d04` (package lifecycle native evidence), production lifecycle `752354c`. Current follow-up is a separate DEB dependency fix; no push.

## Current task
* Fix the confirmed DEB runtime dependency defect in one commit. Readiness performance changes are outside scope.

## Accepted architecture / invariants
* AGENTS17 and docs/package-lifecycle.md remain authoritative: four durable states, daemon-only ownership release, infrastructure-only helper in fic-dick, shared daemon.lock, ownership/CAS and retained provenance. No M1 runtime/finalizer/standalone rollback or migration.
* DEB ELF dependency analysis must fail closed on errors/empty output. GUI's bundled Qt handling remains separate. Never remove durability protections merely to improve readiness timings.

## Completed / changed areas
* packaging/deb/build-fic-debian12-deb.sh: real dpkg-shlibdeps source-package context, absolute ELF paths, retained diagnostics, no libc-only fallback; explicit failure propagation through main/CLI/device/helper/session builders. Prelogin reuses the strict multi-ELF detector.
* New deb_binary_depends_tests registered/labeled in CTest: relative/space-containing paths, multi-ELF/prelogin, failed/empty/missing analysis, cleanup, builder and helper-only failure propagation under conditional command substitution. Old detector fails the regression test.
* Packaging README and package-lifecycle-validation document the build contract and minimal runtime proof.

## Validation
* Ubuntu24 Docker: CMake configure and affected targets fic/fic-dick/fic-cli/fic-package-infrastructure build PASS; 5 related CTest PASS (dependency, prelogin lifecycle, PAM packaging, platform static, build resources). Actual three DEBs rebuilt with Qt/GLib/OpenSSL/systemd/SQLite dependencies as appropriate.
* Separate minimal Ubuntu24 systemd PID1 container: Qt Core, CMake, g++ and Qt devel initially absent; offline-network APT installs corrected DEBs plus cached dependency closure. Qt installed by Depends; all four ELF ldd checks PASS, packages install ok installed, both daemons active, CLI/status and device readiness PASS. No host binds/ports/network; private namespaces and per-mount readonly sysfs.
* Bash syntax, standalone relevant static tests and git diff --check PASS. Host configure lacked PAM headers; complete configure/build/CTest validation used the native Docker build image.
* Raw logs: /tmp/fic-readiness-diag/build-fixed-debs.log, /tmp/fic-deb-depends-native/check.log and depends-results.json (copied from container).

## Remaining boundaries
* Historical five-distro lifecycle gates in 50e0d04 used build/devel-rich images and did not prove complete Depends. This fix's minimal runtime validation is Ubuntu24 only; no new five-distro matrix/full CTest/real PAM authentication/physical-device/graphical/SSH continuity claim.
* Previous diagnostic task left code unchanged: two full Ubuntu24 lifecycle reruns passed. Startup reconciliation performed ~500 sync calls for 33 devices; injected 80ms sync delay reproduced a 30s readiness failure with a live daemon and successful retry after delay removal. Exact cause of the earlier three timeouts remains unproved; strace -f itself can cause udevadm timeout. Diagnostic report: /tmp/fic-readiness-diag/REPORT.md.
* Docker images/caches remain; only disposable validation containers are stopped after evidence collection. Never factory-reset/delete unrelated volumes. Use DOCKER_CONFIG=/tmp/fic-package-docker-config if the Windows credential helper is absent.
