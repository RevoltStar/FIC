# Startup main/device readiness (A2)

`fic.service` pulls in `fic-device.service` with `Wants=`. Device retains
`Requires=fic.service`; neither unit orders its startup after the other. Both
remain `Type=notify`, `NotifyAccess=main`, `TimeoutStartSec=600s`. There is no
blocking `ExecStartPre` before the main process's early protection.

```text
systemd
  +-- fic: lock/lifecycle/config → initial registry → ACTIVE SSH preblock
  |        → crash IR reconciliation → bounded device status wait
  |        → one startup apply pass → admin/session sockets
  |        → access readiness → lifecycle complete → READY → IPC loop
  +-- device: DB → policy activation/connected DENY proof → sockets → READY
              → initial inventory/retry → IPC loop
```

The in-process device wait is before **all** initial policy execution: enabled
DC block policies call `DC::reconcile()` during their own apply, earlier than the
mandatory final reconcile. Readiness does not replace that final operation.

## Admission and bounds

`DeviceStartupReadiness` uses the existing `fic::ipc::Client` and framed transport,
not another client or a child `fic-dick` process. It requires a responding `status`
with trusted root `SO_PEERCRED`, supported IPC API, boolean true `ok`, string
message/product version, the exact product version and integer device DB schema
version matching the local build. Malformed/unsuccessful/incompatible responses
never admit startup DC writes. Untrusted response bodies are not copied to audit.

The monotonic budget is **60 seconds**, requests are capped at **1 second** and
remaining budget, and retry pauses at **100 ms** and remaining budget. This admits
the measured 45 s device initialization while leaving most of the existing 600 s
unit envelope for early protection and policy execution. It is not an unlimited
inventory wait. Scheduling can add latency; the overall systemd start limit is
unchanged. SIGTERM/SIGINT are checked between and after requests (at most one
bounded request plus scheduling); shutdown during this wait exits without apply,
socket creation or READY. UNINSTALLING mode bypasses the wait and policy pass.

A status reply is neither an inventory proof nor a lease on future responsiveness.
Device READY still means proven DB, activated policy/enforcement and both sockets;
it intentionally precedes synchronous initial inventory. A socket can therefore
exist, and its unit be active, while it cannot answer yet. Initial inventory may
fail/retry and a compatible status still correctly admits policy synchronization.

## Nonfatal readiness failure

After the budget expires, the existing nonfatal startup model is preserved:
independent policies and FIREWALL reconciliation still run. The existing planner's
own-executor callback returns Failed for enabled device-dependent DC policies,
with `ExecutionInfrastructureFailure` and `ownApplyAttempted=false`, without
calling their IPC writes. Their existing violation severity still applies through
PolicyIncidentReporter. Disabled guards, dependency processing, Required
failures, caching, the real PolicyApplySummary and PolicyIncidentReporter remain
in the same execution engine. The local detector-severity setting is independent
and still applies. No ownership, config statuses or rollback contracts change.

The final mandatory device obligation is explicitly failed/not attempted when
startup device admission failed; it is never falsely marked successful. A late
recovery cannot rescue this initial pass. The audit `policy_apply_pass.result`
adds `startup_device_ipc_ready`, `startup_device_wait_ms` and
`device_reconciliation_attempted`; existing `device_reconciliation=false`, `ok=false`
and `device_error` explain the unresolved obligation. Thus enabled DC can have
Failed results, or all DC block policies can be Disabled, while global startup
still fails. No fabricated Applied summary entries are added.

The daemon then opens its existing sockets, computes access readiness and sends
READY as before. READY proves startup/lifecycle processing finished and sockets
were created, **not** successful policy application. `prelogin_status` keeps its
17-field contract: completed startup is successful only if `startup_apply_ok`
is true; on readiness failure it is false with the deadline diagnostic.
Periodic/admin recovery does not rewrite this per-instance historical outcome.
Existing PreLogin/ACTIVE access checks retain authority; automatic handoff is
not authorized by systemd active/READY alone. No PreLogin or PAM code changed.

## Lifecycle and remaining boundaries

Weak main Wants allows administrative startup in UNINSTALLING even when device
writer admission correctly refuses that lifecycle. Explicit stop still stops the
dependent device via Requires; there is no longer a cross-unit reverse stop order.
Package scripts explicitly stop writers and retain their process/unit/lock/PAM
proofs. No package protocol or persistent state was added.

The existing bounded serial-RPC conflict (device incident callback while main
waits on device during runtime/restart) is not fixed here. Detector ACK/retry and
inventory behavior are unchanged. Startup success does not prove that every
pending permanent incident has already been delivered or that all hardware was
inventoried. Device-local audit's pre-existing unsupported `incident` event type
is outside this change; the DB schema is unchanged.

Validation and receipts: [startup-readiness-validation.md](startup-readiness-validation.md).

## ACTIVE login: udev control responsiveness

`currentAccessStatus()` applies `UdevAccessReadiness` to the outgoing access
status for **both** `access_gate_status` and `prelogin_status`. In ACTIVE only,
the existing `PlatformExecutableResolver` resolves `ExecutableId::Udevadm` and
`VerifiedProcessExecutor` runs exactly `udevadm control --ping --timeout=1` with
a cleared C environment, a4096-byte output bound and an independent1250ms process
deadline. Missing/untrusted executable, launch failure, timeout, nonzero exit or
output overflow all fail closed. Existing platform trust enrollment already
includes udevadm; this check never enrolls or repairs it automatically.

Positive and negative observations are cached on the daemon thread for **less
than2 seconds measured from probe start**. At expiry the next status request
performs a fresh bounded probe; a late success older than2s cannot admit login.
Repeated prelogin polling uses the same cache. No probe runs outside ACTIVE;
a status request outside ACTIVE invalidates the cache. There is no background worker/service.
The1250ms child budget leaves room inside the PAM client's existing2s IPC timeout;
the first request after expiry can incur this latency. Existing synchronous daemon
work/OS scheduling and kernel I/O are not a hard real-time response guarantee.

A failed probe projects outgoing READY to existing DEGRADED before computing
ordinary_login_allowed. It never changes incident severity, persistent state,
containment, configuration or the underlying DaemonReadiness. A later
recomputeAccessReadiness()/ScopedApplying READY cannot bypass this projection.
A fresh successful ping removes only this extra reason; all other readiness,
mode proof, persistent-state and incident restrictions still apply. Failure/recovery
diagnostics are logged on change, not per poll; prelogin includes the cause.
The10-field access schema and17-field prelogin schema are unchanged.

`pam_fic_access.so` and its autonomous trusted mode/recovery configuration readers
are unchanged. OFF/PASSIVE stay neutral. Local root recovery and policy-authorized
fic-group recovery happen before requesting the daemon, so a failed ping cannot
block those existing exceptions. Already-running sessions are unaffected.

The guarantee is **only an answer from udevd's control interface**. It does not
prove rule execution, worker health, queue completion, device authorization or
absence of pre-enforcement access. A hung worker with a responsive manager still
passes. Control socket activation is allowed. No trigger/settle/artificial uevents
are used; no Device Control rule or enforcement changes are involved.

Tests: `udev_access_readiness_tests` covers positive/negative/timeout/launch error,
unavailable executable, cache expiry/intensive polling, recovery, other denials,
READY re-projection, existing PAM recovery ordering and both wire formats. Native
runner: `tests/integration/udev-access/run-native.sh IMAGE BUILD_DIR`, requiring
a Debian12 systemd/udev image and the built test executable. It uses a disposable
private PID/mount/cgroup/network container with no host binds/ports/socket and
read-only sysfs/proc-sys. It checks absent control socket, responding udevd,
SIGSTOP/unresponsive control interface, SIGCONT recovery and socket activation.
A stopped-daemon negative control rejects chroot/no-op ping as integration evidence.

Validation (2026-11-16, base `eb6a87f60a23faefdefe34a907700fd1068a0278`):
Docker Debian12 target build of `fic`, `udev_access_readiness_tests`,
`incident_access_gate_core_tests`, `daemon_readiness_tests`,
`incident_access_client_tests` and `prelogin_controller_tests` passed; focused
CTest5/5 passed. Real udev native5/5 passed: stopped→denied24ms,
responding→allowed23ms, SIGSTOP→denied1090ms, SIGCONT→allowed23ms,
control-socket activation→allowed84ms. The fixture clears vendor
ConditionPathIsReadWrite=/sys for the container-only service/sockets; sysfs stays
read-only. The initial socket-activation fixture lacked socket overrides and
correctly failed; no production check was relaxed. Unit tests verify cache and
recovery on one checker instance; native invocations each create a new instance.
No full daemon startup/PAM authentication, hung-worker experiment, cross-distro
native matrix or full-project CTest was performed. Logs: `/tmp/fic-udev-access/`.
