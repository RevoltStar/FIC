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
bash tests/integration/package-lifecycle/run-deb.sh IMAGE BUILD/followup-packages detach_retry_native.py
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

The detach-retry gate uses current real DEBs and creates an actual filesystem
obstruction via a test-only fic.service ExecStopPost: an empty directory at
`/var/lib/pam/auth.new`, then `/var/lib/pam/account.new`. Native pam-auth-update
cannot write its saved configuration; the latter fault occurs after updating
common-auth. The helper's physical proof must reject even if the updater exits0.
Both failures occur after ownership rollback and stop, retaining UNINSTALLING,
payload and referenced PAM libraries. Explicit administrator removal of the
obstruction, restricted systemd restart with interval1, idempotent rollback and
ordinary package remove/purge must succeed without changing desired config or
recreating released resources. The drop-in is never installed in production.

## Minimal DEB runtime gates

Build current packages separately on each native build image/cache. An explicit
output directory avoids mixing historical test archives with current packages:

```sh
# Inside the corresponding BUILD image, /src:ro and /build:rw:
DIST_DIR=/build/followup-packages bash /src/tests/integration/package-lifecycle/build-deb.sh debian-12 0.1.1
# On the test controller:
bash tests/integration/package-lifecycle/prepare-runtime-deb.sh debian:12 BUILD/followup-packages fic-followup-runtime:debian12
bash tests/integration/package-lifecycle/run-deb.sh fic-followup-runtime:debian12 BUILD/followup-packages minimal_runtime_native.py
```

Repeat with Debian13/debian:13, Ubuntu24/ubuntu:24.04 and Ubuntu26/ubuntu:26.04,
using the matching platform argument and build cache. `prepare-runtime-deb.sh`
starts from the distro base, installs only boot/harness prerequisites and
downloads (without installing) the actual DEBs' dependency closure. It never
inherits a build image or preinstalls Qt/devel libraries. Actual APT install runs
under systemd PID1 with networking disabled and consumes that cache. Do not use
APT --no-download for local DEBs: it also prevents copying the local archives.

The fixture makes /sys and /proc/sys read-only before PID1, masks coldplug and
clears the native udev units' ConditionPathIsReadWrite only in the disposable
image. This allows real udev control/reload/inventory without writable sysfs;
it is not evidence of hardware enforcement. udev must be available at boot:
installing it only after the readonly remount makes systemd skip it and causes
a harness-induced device-daemon failure. No production unit is changed.

The driver rejects build/devel packages or preinstalled Qt, records all actual
Depends and archive digests, checks every packaged ELF (including PAM/helper),
dpkg status/audit, both daemon services, CLI/readiness, main remove, surviving
helper proof and final purge. The SSH stop is an explicit test-administrator
action preserving existing release restrictions. Success is written only after
the final checks. On failure, diagnostics.json retains native unit/journal facts.


### Optional managed software boundary

Build target `optional_owner_fixture` in the matching native build/cache and
pass its path as the fourth runner argument:

```sh
bash tests/integration/package-lifecycle/run-deb.sh IMAGE BUILD/optional-packages minimal_runtime_native.py BUILD/tests/optional_owner_fixture
```

The runtime image removes preinstalled sudo/openssh-server/procps, and the
driver verifies packages and executables remain absent after real APT install.
It checks all SSH/SUDO/SYSCTL no-owner outcomes are `NOTHING_TO_RELEASE`, then
rejects orphan markers, detached sudo fragments, staging, unsafe parents,
hardlinks and symlinks without adoption or mutation. Ordinary remove/purge
must succeed. A fresh real reinstall then uses the test-only fixture under
daemon.lock to seed valid production-API pending/owned records: SSH Prepared,
SUDO Prepared, and SYSCTL Applied with physical drift. Restricted rollback and
real package removal must refuse and retain provenance/configuration. These
negative rows are synthetic; they are not evidence of successful native
provider apply. The container is destroyed with those rows still active; no
journal reset, retirement or invented recovery is used to get the clean PASS.


### Final physical release proof follow-up

The optional-owner gate also rejects empty/header-only SYSCTL artifacts with
both per-policy failures and a final SYSCTL physical-proof failure. It then
seeds a single SYSCTL Applied A plus unrecorded B using `--mixed-sysctl` on the
test-only fixture. Real `rollback_all` must retire A, leave B, fail the final
proof, and preserve foreign/configuration bytes. Only explicit test-admin
removal of B allows retry and ordinary package removal. A valid foreign
`/etc/sysctl.conf` fixture sets the same value as readonly runtime to permit
strict active rollback without kernel writes; it is verified unchanged and
restored afterwards. This is an isolated test precondition, not production
recovery. SSH/SUDO mixed releases and valid container deletion are additionally
covered by the production rollback/final-inspection unit suites.
