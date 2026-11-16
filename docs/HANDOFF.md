# Current workspace

## Current base / task
* Branch main; base `d5a2c430d942247d0c8de3163c1e888fe01fe9a0`.
* Udev native-runner privilege follow-up complete; one thematic commit, no push.
* Only runner + docs changed. ACTIVE login production implementation is unchanged.

## Accepted architecture / completed
* tests/integration/udev-access/run-native.sh no longer uses --privileged,
  SYS_ADMIN, cap additions, remount bootstrap or unconfined security profiles.
* docker create→inspect→start: cap-drop ALL, NNP, default seccomp/device controls,
  network none, private cgroup/PID/IPC/mount context, no host binds/ports/devices/
  Docker socket. Only runtime /run,/run/lock,/tmp tmpfs permitted.
* Bootstrap checks /sys,/proc/sys read-only, all capability sets0, NNP1, seccomp2;
  bypasses image-specific /sbin/init wrapper and execs actual systemd binary.
* Without a working restricted systemd manager runner returns SKIP77, prints
  diagnostics and removes its container. No privileged/unsafe fallback flags.
* Five existing native scenarios retained behind that prerequisite. They are
  not claimed PASS here. Full native validation needs a disposable VM or other
  independently isolated/delegated systemd environment; no VM infrastructure added.
* Contract/results and historical privileged-run caveat: docs/startup-readiness.md.

## Validation (actually executed)
* No-cap/NNP Docker probe: systemd252.39 initially failed mounting /run/lock.
  Providing runtime tmpfs /run/lock removed that obstacle; next fatal failure:
  create /init.scope: read-only cgroup2; manager allocation fails, exit255.
  No CAP_SYS_ADMIN/RW host cgroup/host devices were provided to bypass it.
* Final restricted runner: inspected fields and runtime RO/cap/NNP/seccomp guards
  PASS, bootstrap blocked as above, final exit77. Native cases1–5 ALL SKIP.
* Unchanged Docker unit/IPC/prelogin CTest:5 PASS/0 FAIL/0 SKIP in
  fic-udev-access:debian12, cap-drop ALL/NNP/network none, source RO/build RW:
  udev_access_readiness_tests, incident_access_gate_core_tests,
  incident_access_client_tests, daemon_readiness_tests, prelogin_controller_tests.
* bash -n and git diff --check PASS. Production/test C++/CMake unchanged; no rebuild
  required. Probes/runner containers removed. No host udev/USB/device changes.
* Logs /tmp/fic-udev-restricted/{runner-final,unit,cgroup-ro-failure}.log;
  final-probe-inspect.json records restricted configuration.

## Remaining / limits
* Functional production task remains completed at base. This follow-up does not
  re-prove real udev on restricted Docker: all five native cases were unavailable.
* Private cgroup namespace does not grant delegation. No universal claim that all
  possible restricted runtimes cannot run systemd; current Docker cannot bootstrap
  it with accepted permissions. Additional vendor unit requirements not reached.
* Earlier privileged5/5 was functional evidence, not safe-host-isolation evidence.
  Do not restore privileged or equivalent permissions just to make native green.
