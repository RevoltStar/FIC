# Real package lifecycle gates

These gates build production FIC executables and use the production DEB/RPM
staging functions and scriptlets. Versions `0.1.0` and `0.1.1` are local test
versions, not a claim of a released compatibility guarantee. No dummy package
or replacement policy engine is involved.

Use only disposable Docker containers. Runners assert private PID/cgroup/mount
context, no host binds or ports and no network. `/sys` receives a per-mount
read-only flag; its cgroup child remains writable for the container's PID1.
Do not run the Python drivers directly on a host. Never replace the per-mount
remount with a sysfs superblock remount.

Build `Dockerfile.deb` with `BASE=debian:12`, `debian:13`, `ubuntu:24.04` or
`ubuntu:26.04`; `Dockerfile.alt` provides ALT p11. Build packages in a separate
container with the repository mounted `/src:ro` and a distro build cache mounted
`/build:rw`:

```sh
bash /src/tests/integration/package-lifecycle/build-deb.sh debian-12 0.1.0
# Or build-rpm.sh 0.1.0 in ALT.
# Repeat with 0.1.1 and move those archives into lifecycle-packages/upgrades/.
```

The DEB platform names are `debian-12`, `debian-13`, `ubuntu-24.04`,
`ubuntu-26.04`. Production dependency discovery must succeed; do not substitute
hard-coded dependencies to make a fixture install.

```sh
bash tests/integration/package-lifecycle/run-deb.sh IMAGE BUILD/lifecycle-packages
bash tests/integration/package-lifecycle/run-rpm.sh ALT_IMAGE BUILD/lifecycle-packages
bash tests/integration/package-lifecycle/run-restricted.sh IMAGE BUILD/fic/fic
bash tests/integration/package-lifecycle/run-deb.sh IMAGE BUILD/lifecycle-packages purge_failure_native.py
```

Each package run exports unique `build-package-lifecycle/native-*` evidence:
actual commands, exit codes, outputs, IPC requests/reports, configuration/PAM/
journal/witness hashes, container namespace/mount configuration and a result
written only after every assertion passes. A directory without `result.json`
is not a PASS. Keep failed runs when diagnosing; never reuse a previous result.

DEB gates exercise real apt/dpkg install, upgrade, configuring failures and
`dpkg --configure -a`, remove, late purge without the daemon ELF, reinstall,
independent partial rollback, Sudo/shared login.defs and active PAM ownership.
They also cover override failures, best-effort stop with a real failed ExecStop,
broken ELF/journal and refusal to detach foreign PAM references. If an actual
`fic-prelogin` archive is in upgrades, the gate exercises its installation and
the infrastructure helper's deactivation while the optional ELF still exists.

ALT gates exercise real RPM install/upgrade/erase, retained configuration and
helper reinstallation, native faillock/pwhistory and passwdqc provider release.
RPM has no dpkg-style purge. The minimal ALT base image's foreign
`/etc/sudoers.d/99-sudopw` mode is explicitly repaired by the test administrator
before installing FIC and checked with native visudo; FIC does not repair it.
ALT emergency SKIP is tested after actual daemon PAM release: SKIP is never
expected to undo policy topology after breaking the ownership engine.

The restricted daemon gate uses genuinely malformed config/journal, mutating
IPC, periodic intervals, SIGKILL/restart, then a PID1/container restart with
fresh tmpfs `/run` and persistent UNINSTALLING. This is a restart-equivalent
gate, not a physical host reboot. The late-postrm fault gate holds the real
daemon.lock during `dpkg --purge`, verifies retained FIC data/external PAM, then
retries. dpkg can delete its own neutral conffiles before the failed postrm.

These containers do not prove physical device enforcement, real-user PAM
authentication, graphical boot or live SSH session continuity. Existing backend
unit/fault-injection suites cover those release algorithms separately; do not
label those checks package-manager E2E. Runtime images deliberately stop SSH
before the gates, preserving the existing Ubuntu/ALT release boundary.
