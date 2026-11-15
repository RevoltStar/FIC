# A2 startup readiness validation — 2026-11-15

Base: `62aa6022a2147dfc6080565584eb388e56a76d47`. Contract:
[startup-readiness.md](startup-readiness.md). Results below apply to the A2
working-tree code built into real packages, not to unmodified base binaries.
Local test package versions are `0.0.0-alpha` → `0.0.1-alpha` (RPM uses `~alpha`).
No production version files were changed. No VM/host policy apply was performed.

## TESTED: native Debian 12 startup

Docker replaces unavailable Podman. Each disposable container has real systemd
PID 1 (252.39), private PID/mount/cgroup/network contexts, network `none`, no host
binds or published ports, and read-only sysfs/proc-sys established before PID 1.
Real DEBs, real FIC/device ELF and installed production units are used. Tests
inspect effective `systemctl show` properties, invocation journals, actual
`prelogin_status` and the production shared PreLogin parser/handoff predicate.
There is no production scheduler or inventory barrier added by the fixture.

| Scenario | Observed result |
| --- | --- |
| Cold pair, all DC block policies disabled | PASS, 2.661 s; real final device reconciliation true |
| Only main requested | PASS, 2.475 s; Wants starts device |
| Only device requested | PASS, 0.229 s to device READY; Requires starts main, whose completed startup is checked separately |
| Device delayed 45 s, USB block `new` enabled | PASS, 47.756 s total; initial apply and final obligation succeed after served status |
| Wrong-version root device responder | PASS negative: about 60 s; status requests only, no device writes; independent policies still apply |
| Missing device socket | PASS negative, about 60 s; no false successful startup |
| Corrupt device DB | PASS negative, about 60 s; device never READY |
| Device policy activation failure | PASS negative, about 60 s; temporary udev rules target made a directory; no device READY |
| Late recovery after failed gate | Startup history stays false; manual recovery cannot authorize automatic startup handoff |
| Missing permanent device | PASS: actual incident ACK true, retry_required false |
| Device restart, subsequent fresh main startup | PASS, bounded responsiveness; not a claim that all runtime mutual-RPC cases are solved |
| Explicit main restart | PASS, 4.019 s, new main PID and successful startup |
| Explicit stop both writers | PASS, inactive/dead, MainPID 0 |
| UNINSTALLING startup | PASS, gate and policy apply bypassed; administrative main remains available while device admission refuses |

Each successful initial pass has one startup audit event, zero failed policy
results, real `device_reconciliation=true`, completed lifecycle and true startup
flags. Negative cases have completed lifecycle but `startup_apply_ok=false`,
`device_reconciliation=false`, a deadline diagnostic and denied automatic handoff.
Enabled DC failures are explicit; disabled DC is not fabricated as Applied.

The 45 s fixture delays the real device process's second SQLite open after socket
creation using the existing test-only preload shim. The test verifies measured
shim duration and readiness after publication. This demonstrates why socket
existence or notify READY alone is insufficient; it does not simulate arbitrary
hardware or make inventory completion a new contract.

### TESTED: ACTIVE early protection and stop

The test persists ISOLATE in PASSIVE, stops main, selects ACTIVE and starts SSH,
then starts main with unavailable device. While main reports `Waiting for device
administrative IPC`, SSH is already inactive, persisted state is still ISOLATE,
and nftables has the real `fic_incident_quarantine` drop chain. Main is activating
and its administrative socket does not exist yet. SIGTERM stops it in 0.114 s,
without startup policy apply. Subsequent PASSIVE recovery succeeds.

This is evidence of actual early SSH containment/crash-state enforcement before
the wait, not a full ACTIVE PAM login/session/authentication test. PreLogin GUI
rendering was not tested; its existing shared status parser and auto-handoff
predicate were exercised on actual daemon replies.

## TESTED: build and CTest

* Full real-PAM/Qt Debian 12 project build: PASS (`build-i2-full`).
* Full production `fic` compile/link with Debian 13, Ubuntu 24.04, Ubuntu 26.04
  profiles: PASS (`build-a2-profiles`). These builds use Debian 12 tooling and are
  **not** native runtime validation of those distributions.
* Actual ALT p11 build of fic/device/CLI/infra/PAM modules: PASS (`build-a2-alt`).
* Production device-wait unit fixtures: PASS on Debian 12 and ALT p11. Includes
  success/delayed bind, wrong product/schema/API, invalid JSON/types/status,
  non-root peer, silent socket, absent socket, bounded timeout and real SIGTERM.
* Planner callback/dependency regression, PreLogin controller and updated path,
  platform, FIREWALL and desktop static contracts: final targeted CTest **7/7 PASS**.
* Full CTest first run: **221 PASS / 4 SKIP / 5 FAIL**, total 230. FIREWALL's
  literal call-shape check was updated for the new callback and then passed.
  Git path check failed due to root container safe.directory and passed after
  correcting only container Git configuration. Three unrelated failures remain:
  incident-state RPM manifest static assertion, identity hierarchy activation
  recommendation assertion (both known on the base), and MutationJournal's
  chmod-fault assertion under root (separate current nonroot run PASS). No green full-suite
  claim. The four skipped native tests require their separate opt-in fixtures.

Python/shell syntax and `git diff --check` are checked separately. No native SSSD,
SSH activation or full PAM matrix rerun is claimed for this startup-only change.

## Receipts and reproduction

Reproducible startup driver:
`tests/integration/package-lifecycle/startup_readiness_native.py`, invoked through
`run-deb.sh` with `FIC_STARTUP_TEST_BINARY` pointing to the built
`device_startup_readiness_tests`. `FIC_STARTUP_TEST_GROUP=all` runs all scenarios;
`remaining` or `restart` permit targeted continuation without repeating the
successful 45 s case. Raw output is in ignored `build-package-lifecycle/`.

Saved receipts for this run:

* `/tmp/fic-a2/first-startup-evidence/startup-results.json`: first four successful
  cases. That initial combined run later hit a **test harness** graph assertion
  against an intentionally masked unit; it is not labelled whole-suite PASS.
* `build-package-lifecycle/native-fic-a2-runtime:debian12-20261115T110314Z-79620/startup-results.json`:
  remaining negatives, permanent incident, ACTIVE/stop and UNINSTALLING, PASS.
* `build-package-lifecycle/native-fic-a2-runtime:debian12-20261115T111140Z-81815/startup-results.json`:
  explicit main restart/stop, PASS.
* `/tmp/fic-a2/full-build-ctest.log`, `final-targeted.log`, `build-debian12.log`,
  `build-alt.log`, profile build logs in `build-a2-profiles/`.

Package-manager results and retained limitations are recorded with the A2
appendix in [package-lifecycle-validation.md](package-lifecycle-validation.md).
Compact observed results and raw receipt hashes are committed in
`tests/integration/package-lifecycle/evidence/startup-readiness-a2.json`.
Raw logs/build trees are local test artifacts, not a new historical-evidence
subsystem or attestation of later HEADs.

## INFERENCE / remaining limits

A valid status is a point-in-time admission proof, not a future availability
lease. Later device failure is still reported by actual apply/final reconcile.
The existing bounded approximately 30 s serial mutual-RPC runtime conflict and
device audit's unsupported `incident` event type remain unchanged/out of scope.
Containers share the Docker/WSL kernel; physical device enforcement, VM boot,
full authenticated ACTIVE access and GUI boot were NOT_TESTED.

## Changed files

* `docs/HANDOFF.md`
* `docs/package-lifecycle-validation.md`
* `docs/package-lifecycle.md`
* `docs/startup-readiness-validation.md`
* `docs/startup-readiness.md`
* `fic-dick/README.md`
* `fic/src/daemon/DeviceStartupReadiness.cpp`
* `fic/src/daemon/DeviceStartupReadiness.h`
* `fic/src/main.cpp`
* `fic/src/policy/execution/PolicyApplication.cpp`
* `fic/src/policy/execution/PolicyApplication.h`
* `fic/src/resources/service/fic-device.service.in`
* `fic/src/resources/service/fic.service.in`
* `tests/CMakeLists.txt`
* `tests/common/static_checks.py`
* `tests/fic/daemon/DeviceStartupReadinessTests.cpp`
* `tests/fic/modules/firewall/static_checks.py`
* `tests/fic/modules/oss/desktop_environment/static_checks.py.in`
* `tests/fic/platform/static_checks.py`
* `tests/fic/policy/PolicyExecutionPlannerTests.cpp`
* `tests/integration/package-lifecycle/README.md`
* `tests/integration/package-lifecycle/evidence/startup-readiness-a2.json`
* `tests/integration/package-lifecycle/rpm_native.py`
* `tests/integration/package-lifecycle/run-deb.sh`
* `tests/integration/package-lifecycle/startup_readiness_native.py`
