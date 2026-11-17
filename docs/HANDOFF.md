# Current workspace

## Current base / task
* Branch main; base `4ef54fa2ee5d3806e8a4977c783c71471178fa2e`.
* Two Actions failures from run44082428374 fixed in one thematic commit (HEAD).
  No push/Actions dispatch. User will run the next hosted CI.
* User permits static inspection and quick focused test in existing environment;
  prohibits full builds, full CTest/development checks and the five-distro test matrix.

## Accepted contract / completed
* ALT p11 ships /usr/bin/ctest in separate ctest RPM (verified installed p11
  metadata: ctest-3.31.7-alt1.p11.1, source cmake). Add ctest to ALT CI packages
  and command -v ctest immediately after installation, before checkout/build.
* Ubuntu26.04 rootfs has /usr/bin/true and /bin/true ->gnutrue symlinks. Actual
  production resolver rejects them and never calls injected unit runner.
* Udev unit fixture now uses /usr/bin/bash or ALT's /usr/bin/bash5. Both selected
  regular executables verified root:root0755 in existing five distro images.
  ALT /usr/bin/bash itself is a symlink, so bash5 candidate is necessary.
* First ACTIVE assertion now reports runner call count and check.diagnostic().
  All original argv/deadline/environment/output/cache/expiry/fail-closed/mode,
  late-result, recovery and wire serialization assertions retained.
* No real udevadm or fixture executable is launched by unit runner (lambda).
  Production PlatformExecutableResolver/UdevAccessReadiness unchanged, including
  symlink rejection/trusted ownership. Native --native branch unchanged.
* Previous seven CI variants, non-root wrapper/order, filters, default ALT mirrors,
  working distro jobs, warnings and sanitizers preserved. No dev-script changes.

## Changed areas
* .github/workflows/ci.yml.
* tests/fic/incident/UdevAccessReadinessTests.cpp.
* This required AGENTS.md handoff snapshot.

## Validation (actually executed)
* Current source/history and GitHub run jobs/logs inspected. ALT log ends with
  ctest:command not found after full build; Ubuntu26 log shows initial generic
  invariant failure. No workflow started by agent.
* Read-only p11 RPM query confirms ctest package. Metadata-only checks in existing
  fic-client-access:{ubuntu2404,ubuntu2604,debian12,debian13,altp11} images confirm
  symlink layout/fixture ownership/mode; no pulls, packages or environment builds.
* Used existing build-gui-dependencies, fic-gui-dependency-tests:debian12 image:
  cmake --build /build --target udev_access_readiness_tests -j2. RED/GREEN rebuilt
  only changed test translation unit plus link, no full build/configure.
* RED: old true candidates + precise assertion, existing Ubuntu26 client-access
  image, read-only rootfs/build mount, UID65534, no network/caps/core dumps:
  ready test binary failed (exit139), reporting runner calls=0 and both candidate
  paths rejected specifically as symbolic links. This proves cause beyond generic
  invariant text. No new test environment created.
* GREEN: same Debian-built binary after fixture fix, same Ubuntu26 runtime and
  non-root restrictions: exit0, PASS all existing udev unit scenarios.
* GREEN ctest --test-dir /build -R '^udev_access_readiness_tests$'
  --output-on-failure, non-root keep-id: exit0,1 PASS/0 FAIL/0 SKIP,0.06s.
* YAML parsed and compared to base: only ALT ctest dependency and early command
  availability check changed; all other workflow fields identical. PASS.
* Final diff review and git diff --check PASS. Logs:
  build-gui-dependencies/udev-fixture-{red-build,green-build,green-tests}.log.

## Remaining / limits
* No full CI, project rebuild, full CTest, development full checks, sanitizer
  suite, native udev/systemd tests or five-distro test matrix run by user boundary.
* No ALT package installation/new CI dependency step execution; package provider
  verified via existing RPM metadata. Hosted seven-job outcome awaits user's CI.
* Ubuntu26 check uses existing Debian12-profile-built unit binary in Ubuntu26
  runtime, not a new native Ubuntu26 compilation. Relevant resolver fixture path
  is independent of compiled profile; no claim of full platform validation.
