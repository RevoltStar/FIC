# Current base

* Branch: main; task base: `53176ae9309933a67c43e64c0c2d384d167c926d`.

# Current task

* Restore automatic CPU/board/memory collection after DEB/RPM installation;
  implementation and fast checks complete, real-package systemd E2E pending.
* One thematic commit requested; no push.

# Accepted architecture / invariants

* Only main FIC post-install enables/starts hardware inventory, after successful
  complete-install and daemon readiness. No early fic-dick writer admission.
* Enable remains mandatory infrastructure; collector start failure warns and
  preserves failed-unit diagnostics without failing an otherwise ready install.
* Use start, not forced restart: active oneshot remains active; existing
  lifecycle writer quiescence may stop it before upgrade/reinstall. Enabled
  multi-user.target activation runs it on subsequent boots.
* Collectors, DB schema, units, udev collector and uninstall scripts unchanged.

# Completed / changed areas

* DEB fic.postinst and RPM fic.post enable fic_get_device_info.service and
  start it with an explicit nonfatal warning on failure.
* Existing native DEB/RPM drivers share hardware_inventory.py assertions:
  automatic invocation/ExecMainStatus/concrete CPU-board-memory DB rows,
  start/restart/stop-start semantics and enabled boot link, INSTALLING refusal
  with DB bytes unchanged, exact-version reinstall, optional upgrade, and
  stopped collector after prepare-uninstall. Runners copy this test module.
* New CTest hardware_inventory_packaging_checks builds tiny archive fixtures
  using production generators, extracts actual DEB/RPM post-install scripts,
  checks ordering and injects admission/collector failures into their startup
  tail with command doubles. These fixtures are never installed and are NOT
  a substitute for native FIC package E2E. Test README updated accordingly.

# Validation (actually executed)

* cmake -S . -B build-prelogin -DFIC_TARGET_PLATFORM=ubuntu-24.04: PASS
  (existing CMake/libcap pkg-config warnings).
* cmake --build build-prelogin --target package_state_store_tests
  package_writer_processes_tests -j2: PASS.
* CTest in build-prelogin: prelogin_package_lifecycle_tests,
  incident_state_lifecycle_static_checks, hardware_inventory_packaging_checks,
  private_client_permissions_tests, deb_binary_depends_tests: 5/5 PASS.
  Archive check built/extracted both DEB and RPM locally.
* Native ALT p11 container archive check: PASS (RPM); uses production
  run_rpmbuild including its explicit root-build policy.
* Four changed/new Python files: ast.parse PASS; both post-install scripts:
  sh -n PASS; both runners: bash -n PASS; git diff --check PASS.
* Two root-only lifecycle CTests skipped on non-root host. Rebuilt tests then
  run in disposable ALT container with build mounted read-only:
  package_state_store_tests PASS; package_writer_processes_tests with its
  required package_unknown_writer_fixture FAILED: `expired budget accepted`.
  Its C++ sources and fixture are unchanged by this task; left out of scope.

# Remaining / limits

* New native DEB/RPM hardware scenarios only syntax-checked, not executed:
  available container images lack systemd, and container cgroups are read-only.
  Need appropriate systemd runtime images and current real FIC packages to run
  existing run-deb.sh/run-rpm.sh gates. No real hardware/DMI discovery or boot
  proof claimed; existing collectors may store unknown placeholders in Docker.
* No full project build, full CTest, five-platform matrix or GitHub Actions run.
* Host /opt/fic, devices.db and FIC configuration were not touched.
