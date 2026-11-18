# Current base

* Branch main; task base `c7a4fdf7de985521c1b4060d25772e780503662d`.

# Current task

* Configurable periodic apply interval and minimum pause: complete.
* One thematic commit requested; no push.

# Accepted architecture / completed

* GLOBAL/system_settings/check_interval: integer 60–86400, ENABLE default 1800;
  DISABLE ->1800. Historical explicit --interval parsing/priority retained.
* GLOBAL/system_settings/periodic_apply_min_pause: integer 0–600, ENABLE default
  30; DISABLE or enabled 0 ->0. Both settings are startup-only snapshots.
* Steady-clock schedule requires both start+interval and finish+pause. Completion
  is recorded after result/readiness handling for executed passes, including
  failed passes. Refused preflight postpones primary deadline only. No catch-up,
  added sleeps/threads, dynamic reschedule or change to the independent SSH check.
* Policies only validate config; existing NotEnrolled GLOBAL rollback applies;
  no journal/system resource ownership or service restart.
* Targeted ConfigSchemaManager additive update appends only missing four fields,
  preserving existing fields/bytes and canonical metadata. Trusted read, existing
  AtomicFileWriter CAS/durability; schema remains 1. Called under existing lock
  by ensure-config and ordinary startup before registry construction. Read-only
  verifyConfigs, uninstall and trust-sync routes do not perform this update.
* Unit drops --interval 1800; default config, registry, RU/EN metadata and docs
  updated through existing mechanisms. Generic IntPolicyTypeValue behavior left
  unchanged: strict whole-number validation is local to these two policies.

# Changed areas

* fic/src/main.cpp, daemon/PeriodicApplySchedule.h, daemon/main_function.*.
* GLOBAL/system_settings policies/settings reader; default GLOBAL.conf/lang/unit.
* fic-core ConfigSchemaManager; targeted CMake/CTest and schema tests.
* docs/periodic-apply.md is authoritative; architecture/upgrade docs link it.

# Validation (actually executed)

* Configure build-periodic, ubuntu-24.04 profile: PASS. Host lacked PAM headers;
  downloaded/extracted libpam0g-dev only under /tmp/fic-periodic-deps (no OS
  package install); passed include/library paths explicitly to CMake.
* cmake --build build-periodic --target fic periodic_apply_tests
  schema_contract_tests file_handler_options_tests incident_recovery_config_reader_tests
  -j2: PASS; module_registry_tests also built successfully.
* Targeted CTest: 11/11 PASS, 0 FAIL, 0 SKIP: periodic_apply_tests,
  periodic_apply_contract_checks, schema_contract_tests, module_registry_tests,
  file_handler_options_tests, incident_recovery_config_reader_tests,
  prelogin_package_lifecycle_tests, path_layout_static_checks,
  desktop_environment_architecture_static_checks, private_client_permissions_tests,
  deb_binary_depends_tests. Model time; no real 60–600s waits.
* Generated fic.service ExecStart=/opt/fic/bin/fic confirmed. Final diff reviewed;
  git diff --check PASS. Logs /tmp/fic-periodic-{configure,final-build}.log.

# Remaining / limits

* No full project build/full CTest/CI/five-distro matrix, native package E2E,
  live daemon/GUI/systemd restart or host policy apply performed. Restart behavior
  checked through fresh settings/scheduler instances plus production wiring guards.
* Docker has no ready images; tests ran on host using isolated /tmp fixtures.
* Synchronous event-loop work can delay actual launches beyond the deadlines.
