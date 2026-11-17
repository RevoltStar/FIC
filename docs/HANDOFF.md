# Current workspace

## Current base / task
* Branch main; rebased task base `3dad11e0`.
* Fix three ALT p11 test failures without production changes; complete.

## Completed / changed areas
* Both packaging shell tests temporarily define dpkg supporting only
  --print-architecture (amd64), then unset it immediately after sourcing the
  DEB builder. Existing assertions and dpkg-shlibdeps fixture remain unchanged.
* Cleanup traps now precede source, covering source failure too.
* PlatformProfileTests checks exact ALT SDDM path /etc/X11/sddm/sddm.conf;
  other profiles retain /etc/sddm.conf. Production profiles/builders, CI and
  CTest classification unchanged.

## Validation (actually executed)
* bash -n for both shell tests: PASS.
* Both shell tests directly: PASS before and after change (after change also
  with a temporary PATH containing other tools but no dpkg executable).
* cmake --build build-check --target platform_profile_tests -j2: PASS.
* ctest --test-dir build-check -R
  '^(private_client_permissions_tests|deb_binary_depends_tests|platform_profile_tests)$'
  --output-on-failure: 3/3 PASS (Ubuntu 24.04 profile).
* git diff --check: PASS.

## Remaining / limits
* Existing build-a2-alt CTest cannot run locally: stale /src and /build
  container paths; initial attempt failed creating /build/Testing/Temporary.
* Native ALT and five-platform CI matrix left to user GitHub Actions run.
* No full build/full CTest, long container tests or GitHub Actions launched.
* No production behavior changed; one thematic commit. User requested push.
* Rebased onto six origin/main commits; only HANDOFF conflicted. Incoming CI
  fixes remain: ALT ctest dependency and trusted bash/bash5 udev fixtures.
  Their earlier targeted evidence is in commit 3dad11e0; full CI remains unverified.
