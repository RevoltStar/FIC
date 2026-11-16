# Current workspace

## Current base / task
* Branch main; base `eb6a87f60a23faefdefe34a907700fd1068a0278`.
* ACTIVE login udev control responsiveness check complete; one thematic commit,
  no push. Authoritative contract/results: docs/startup-readiness.md.

## Accepted architecture / invariants
* Daemon-only UdevAccessReadiness overlay in currentAccessStatus, shared by
  access_gate_status and prelogin_status. ACTIVE failure projects READY→DEGRADED
  before computedLoginAllowed; never changes underlying DaemonReadiness,
  persistent incident state, severity, containment, sessions or policy configuration.
* Recompute/ScopedApplying READY cannot bypass the per-response overlay. Fresh
  successful ping removes only its own denial; other prerequisites still apply.
* Existing PlatformExecutableResolver Udevadm + VerifiedProcessExecutor, exact
  control --ping --timeout=1, cleared C environment,4KiB output,1250ms child bound.
  No automatic trust enrollment. Cache positive/negative age<2s from probe start;
  expired positive denied, non-ACTIVE status queries invalidate cache. No background thread.
* OFF/PASSIVE and existing autonomous PAM/local-root/fic-group recovery unchanged;
  exemptions happen before daemon RPC. IPC access10/prelogin17 fields unchanged.
* Ping proves only control reply, not workers/rules/queue/device enforcement.
  Socket activation allowed. No trigger/settle/uevents or Device Control changes.

## Completed / changed areas
* fic/src/main.cpp, incident/UdevAccessReadiness.{h,cpp}.
* New focused test target registered in tests/CMakeLists.txt, including existing
  access gate core to verify recovery ordering with a udev-denied response.
* tests/integration/udev-access/run-native.sh: disposable real systemd-udevd
  stopped/healthy/SIGSTOP/SIGCONT/control-socket activation checks.
* docs/startup-readiness.md documents timing/cache/guarantee limits and results.

## Validation (actually executed)
* Docker image fic-udev-access:debian12 based on existing cleanup image, adding
  glib-dev,Qt6 and udev. Explicit QT_DIR selects Qt6 to avoid mixed cached Qt5/6.
* Docker configure: cmake -S /src -B /build -DFIC_TARGET_PLATFORM=debian-12
  -DBUILD_TESTING=ON -DQT_DIR=/usr/lib/x86_64-linux-gnu/cmake/Qt6.
* Targeted build fic, udev_access_readiness_tests, incident_access_gate_core_tests,
  daemon_readiness_tests, incident_access_client_tests, prelogin_controller_tests
  -j2 PASS. Build path build-udev-access.
* CTest regex of five above test targets (excluding fic) **5 PASS/0 FAIL/0 SKIP**;
  tests ran Docker --network none --cap-drop ALL --no-new-privileges, source RO.
* Native runner fic-udev-access:debian12 build-udev-access: **5/5 PASS**.
  Stopped denied24ms; healthy allowed23ms; SIGSTOP denied1090ms;
  SIGCONT allowed23ms; socket activation allowed84ms. This negative control
  excludes success-without-ping chroot behavior on tested image.
* Native runtime privileged but private mount/PID/cgroup/network; no host binds,
  ports/socket, sysfs/proc-sys RO. Container-only service/socket conditions reset
  for RO sysfs. Initial socket fixture missed socket conditions and failed;
  corrected fixture passes without weakening production checks. Container removed.
* Unit covers exit/timeout/start failure/missing executable/overflow/exception,
  cache expiry/1000 polls/recovery/READY reprojection/other denials/OFF/PASSIVE,
  root/fic recovery and wire/prelogin consistency. No host udev actions or VMs.
* Logs /tmp/fic-udev-access/{image,build,tests,native-final}.log.
* bash syntax, diff review and git diff --check PASS.

## Remaining / limits
* No unfinished implementation. No full project build/CTest or cross-distro native
  matrix. No real PAM authentication or full daemon startup E2E. Native uses actual
  production checker/executor plus real udev, each invocation a fresh instance;
  same-instance cache/recovery is unit-tested. Hung workers not tested/promised.
* First status request after cache expiry may incur up to1250ms process budget
  plus normal verification/scheduling; existing2s IPC timeout unchanged.
