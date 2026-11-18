# Current base

* Branch main; task base `8243a2751add3a36973eb8fdc1eea75fa35cedb8`.

# Current task

* Periodic apply scheduler follow-up: three review findings fixed; complete.
* One thematic commit requested; no push.

# Accepted architecture / completed

* Admitted periodic pass timestamps attempted(steady_clock::now()) immediately
  before run_daemon_apply_all_pass, after existing SSH/incident preflight.
  Refused preflight timestamps attempted(original attempt time), never finished.
  Completion remains after result/readiness handling, including failed passes.
* Formula max(actual start+I, actual finish+P), policy ranges/defaults, startup
  snapshots, CLI override and independent 30s SSH check unchanged.
* Normal startup retains read-only verifyConfigs + settings load. Missing keys
  use 1800/30 without modifying GLOBAL.conf; invalid enabled values still fail.
* Package ensure-config/first-install retains existing trusted additive update,
  CAS/durability and explicit DISABLE/value preservation. ConfigSchemaManager
  implementation unchanged. DEB/RPM scripts already call it before complete-install
  and service start; no packaging integration changes required.
* README unit example corrected; manual --interval examples retained. Authoritative
  docs/periodic-apply.md and upgrade contract updated accordingly.

# Changed areas

* fic/src/main.cpp; fic/README.md.
* tests/fic/daemon/{PeriodicApplyTests.cpp,check-periodic-apply.py}.
* docs/{periodic-apply.md,upgrade-contract.md,HANDOFF.md}.

# Validation (actually executed)

* Existing build-periodic, ubuntu-24.04 profile:
  cmake --build build-periodic --target fic periodic_apply_tests schema_contract_tests
  -j2: PASS. Final additional periodic_apply_tests rebuild: PASS.
* Targeted CTest: 11/11 PASS, 0 FAIL, 0 SKIP: periodic_apply_tests,
  periodic_apply_contract_checks, schema_contract_tests, module_registry_tests,
  file_handler_options_tests, incident_recovery_config_reader_tests,
  prelogin_package_lifecycle_tests, path_layout_static_checks,
  desktop_environment_architecture_static_checks, private_client_permissions_tests,
  deb_binary_depends_tests.
* Model-time tests: 45s successful preflight +1s apply; refused 45s/90s preflight
  with retained previous finish. No real waits.
* Child-process seccomp denies write opens with EACCES, without changing canonical
  fixture metadata: old configs verify/load with 1800/30, bytes unchanged; package
  ensureConfigs reports denied write. Parent verifies package update, idempotence,
  preserved custom values/DISABLE, schema and unsafe-metadata rejection.
* Static guards bind model to both production timestamp branches/read-only startup
  and actual DEB/RPM migration command ordering. README/unit contract also checked.
* git diff --check PASS; diff reviewed. Logs:
  /tmp/fic-periodic-followup-{build,tests-build}.log.

# Remaining / limits

* No full build/full CTest/CI/five-distro matrix, native package E2E or real daemon
  startup/systemd operation performed. Startup config path tested as verify+load
  on isolated fixtures plus production wiring checks; not a whole-startup proof.
* No host FIC configuration, unit or policies modified. Scheduling remains subject
  to delays from synchronous event-loop work.
