# Current workspace

## Current base / task
* Branch main; base `6d4b40375a6db5663f1ce5fde42dea3e9f9f7818`.
* SDDM PAM Ubuntu24.04/26.04 support complete; one fix commit is HEAD, no push.

## Accepted invariants / completed
* Official Ubuntu Docker package extraction, before production edits, confirmed
  identical /etc/pam.d/sddm on Ubuntu24.04 sddm0.20.0-2ubuntu4.2
  (noble-updates/universe) and Ubuntu26.04
  sddm0.21.0+git20250502.4fe234b-2ubuntu3 (resolute/universe), amd64.
  Exact byte match with Debian12 0.19.0-5 and Debian13
  0.21.0+git20250502.4fe234b-2. PAM SHA256/DEB hashes, provenance, line positions,
  Linux-PAM references and semantics: docs/pam-owned-faillock-slots.md.
* Production change ONLY Ubuntu2404Profile.cpp and Ubuntu2604Profile.cpp:
  declare the existing exact SDDM root exclusion contract, required→requisite.
  Existing shared policy/conditional registry registration reused unchanged.
* Policy stays DISABLE by default; no automatic application, dependency or strategy
  changes; CFG remains fail-closed on required/authsucc/even_deny_root.
* Tests use complete package PAM fixture and actual profile factories under
  test-only names. Production registry: Debian12/13, Ubuntu24.04/26.04 registered
  and DISABLE; ALT not registered. No changes to PAM algorithms/ownership/lifecycle.
* Prepared test: actual journal + manager + physical slots + full Structural
  verifier; only pam-auth-update process replaced by existing fixture runner.
  Required rejected, journal unchanged; exclusion apply then same-id Applied
  recovery without native re-run or authsucc rewrite. Config/module paths and
  native-default configTopology metadata relocated to disposable tree.

## Changed areas
* Two Ubuntu profiles; tests/CMakeLists.txt (test factories only); platform,
  SDDM policy, CFG, activation tests; existing PAM dependency integration driver;
  test-only SddmTestProfiles.h and full ubuntu-sddm.pam fixture; PAM docs.

## Validation (actually executed in Docker)
* Research: docker -H unix:///run/user/678421280/podman/podman.sock run --rm
  --network host ubuntu:24.04 / ubuntu:26.04 (also debian:12 / debian:13).
  /etc/os-release, dpkg --print-architecture, sources, apt-get update,
  apt-cache policy sddm, apt-get download sddm, dpkg-deb -f/-c/-x, sha256sum,
  nl -ba, cmp; all four research runs exit0. No package/desktop install required.
  Initial normal container network could not reach archive; host networking worked.
  Evidence: /tmp/fic-sddm-research/<24.04|26.04|debian12|debian13>/research.log.
* Build/test wrapper: Docker CLI same socket, image fic-gui-dependency-tests:debian12;
  --rm --network none --cap-drop ALL --cap-add CHOWN --cap-add FOWNER
  --cap-add SETUID --cap-add SETGID --cap-add KILL --security-opt no-new-privileges;
  repo /src:ro; build-gui-dependencies /build:rw; -w /src.
* RED: cmake --build /build --target platform_profile_tests
  pam_disable_root_sddm_login_policy_tests pam_control_flow_analyzer_tests -j2
  exit0; ctest --test-dir /build -R
  '^(platform_profile_tests|pam_disable_root_sddm_login_policy_tests|pam_control_flow_analyzer_tests)$'
  --output-on-failure: exit8, 0 PASS /3 FAIL /0 SKIP (missing Ubuntu contract).
* Targeted build fic, platform_profile_tests, pam_disable_root_sddm_login_policy_tests,
  pam_control_flow_analyzer_tests, pam_capability_activation_policy_tests,
  pam_auth_update_topology_tests, pam_dependency_contract_tests -j2: exit0.
  Final full cmake --build /build -j2: exit0.
* Focused ctest --test-dir /build -R
  '^(platform_profile_tests|platform_profile_static_checks|pam_policy_defaults_tests|pam_disable_root_sddm_login_policy_tests|pam_control_flow_analyzer_tests|pam_capability_activation_policy_tests|pam_auth_update_topology_tests|pam_dependency_contract_tests|pam_packaging_static_checks|pam_provider_rollback_tests)$'
  --output-on-failure: exit0, **10 PASS /0 FAIL /0 SKIP**, 3.76s.
* Full ctest --test-dir /build --output-on-failure: exit8,
  **225 PASS /2 FAIL /4 SKIP**, 89.56s. The two known unrelated failures persist:
  incident_state_lifecycle_static_checks (RPM manifest security-parent assertion),
  identity_policy_hierarchy_tests (PAM activation recommendation expectation).
* Logs: build-gui-dependencies/sddm-{red,green}-{build,tests}.log,
  sddm-full-{build,tests}.log, sddm-prepared-{build,tests}.log;
  pam-i3-contracts.json has actual sddm_registration results;
  Testing/Temporary/LastTest.log has four-platform Prepared recovery PASS.
* Diff review and git diff --check PASS.

## Remaining / limits
* No host apply, production computers or 192.168.1.50. No native Ubuntu whole-daemon
  startup, real SDDM authentication, graphical E2E, real process crash/reboot or
  native pam-auth-update execution in the Prepared fixture. Tests use real FIC
  algorithms with relocated data and mocked native process invocation.
* Whole-suite green is blocked by the two pre-existing unrelated failures above;
  native/systemd tests skipped in this container. Do not expand this task to fix them.
