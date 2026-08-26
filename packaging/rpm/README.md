# FIC RPM packaging for ALT p11

Payload бинарников, service-файлов, конфигурации и данных берется из
именованных CMake install-компонентов. ALT-профиль передает CMake свои каталоги
systemd и tmpfiles; скрипт упаковки отвечает за RPM metadata, lifecycle и Qt
runtime bundle, а не за генерацию integration-файлов.

This packaging flow builds five RPM packages for ALT Linux p11:

- `fic-dick`
- `fic`
- `fic-session-agent`
- `fic-cli`
- `fic-gui`

The packaging script always configures the daemon with
`FIC_TARGET_PLATFORM=alt-p11`; it does not derive the profile from the build
container. The resulting daemon validates `ID=altlinux` and
`ALT_BRANCH_ID=p11` before starting.

ALT packages do not install `/usr/share/pam-configs/fic-*`, do not depend on
the Debian package `libpam-runtime` and do not invoke `pam-auth-update`. The
`fic` RPM installs the native ALT control facility
`/etc/control.d/facilities/fic-pam-faillock`. Installation does not activate
it; PAM topology remains an explicit administrator choice.

## ALT PAM topology integration

The supported package-level integration is limited to `pam_faillock`:

```bash
sudo control fic-pam-faillock status
sudo control fic-pam-faillock enabled
sudo control fic-pam-faillock disabled
```

The facility is `disabled` after a clean install. It is a thin dispatcher to
the offline FIC PAM manager and never generates or edits PAM content in shell.
Enable acquires an inter-process lock, rejects symlink or untrusted targets,
uses the shared PAM parser to find the unique local `pam_tcb` auth/account
anchors, and atomically installs FIC-owned marked blocks. The native ALT
`pam_tcb` auth rule is retained byte-for-byte in marker metadata while its
active control is `sufficient`, as required by the ALT faillock topology.
Enable therefore requires `pam_tcb` to be the final executable auth rule in
the local stack; comments and blank lines may follow it, but another PAM rule
would be bypassed by `sufficient` success and is rejected before any write.
The only added provider calls are:

```text
auth requisite pam_faillock.so preauth
auth [default=die] pam_faillock.so authfail
account required pam_faillock.so
```

Policy values such as `deny`, `fail_interval`, `unlock_time` and
`even_deny_root` remain in `/etc/security/faillock.conf`. After enable, the
same `PamCapabilityVerifier` used by daemon policies must prove the resulting
AuthenticationLockout capability Effective for `system-auth-local-only`.
This explicit local scope also applies in the native ALT `sss` routing mode;
the global `required_pam_enforcement` policy keeps its broader semantics.
Before mutation the manager inspects the effective include/substack graph of
configured authentication services and rejects external `pam_faillock` rules.
Failed postconditions restore the exact original bytes atomically; a failed
rollback is reported as a critical inconsistent-state error.

FIC never adopts or removes administrator-owned `pam_faillock` rules. Partial,
duplicated or modified FIC markers fail closed. Disable removes only valid
FIC-owned blocks and restores the original `pam_tcb` rule; unrelated content
is preserved. Moved managed blocks make disable fail without mutation. Atomic
replacement also refuses a target whose `dev+ino` changed since the secure
snapshot. The facility never changes `control system-auth` or its symlinks.

RPM upgrade uses ALT `control-dump` / `control-restore` to preserve the selected
enabled/disabled state. Final erase invokes the same safe disable operation
before removing the helper and facility; malformed managed state makes erase
fail instead of triggering blind cleanup.

The `fic` RPM depends on `control`, `pam >= 1.7.1` (the ALT p11 owner of
`pam_faillock.so`) and `pam-config >= 1.10.0` (the owner of
`system-auth-local-only`). Native `pam_passwdqc` topology remains unchanged and
has no FIC activation facility. ALT activation of `pam_pwhistory` is currently
unsupported pending a separately proven safe password-history storage design.

## Package contents

`fic-dick` installs:

- `/opt/fic/bin/fic-dick`
- `/usr/lib/systemd/system/fic-device.service`
- `/usr/lib/systemd/system/fic_get_device_info.service`
- `/etc/udev/rules.d/99-fic-devices.rules` (bootstrap, затем active generated policy)

`fic` installs:

- `/opt/fic/bin/fic`
- `/opt/fic/bin/fic-udevadm-trigger`
- immutable defaults under `/opt/fic/share/default-config/*.conf`
- the empty working directory `/opt/fic/config` (working files are created by FIC)
- `/opt/fic/db`
- `/opt/fic/image`
- `/opt/fic/lang`
- `/opt/fic/log`
- `/opt/fic/notify`
- `/usr/lib/systemd/system/*` from `fic/src/resources/service`
- `/bin/fic` symlink to `/opt/fic/bin/fic`
- `/etc/control.d/facilities/fic-pam-faillock` (disabled by default)

During installation, `fic.service`, `fic-device.service` and `fic-notify.service`
are enabled and started automatically. `fic-device.service` performs initial
device reconciliation itself from current udev/sysfs inventory. The
`fic_get_device_udev_info.service` helper no longer runs a mass
`udevadm trigger`; it waits for the device daemon and then runs the
permanent-device check.

`fic-session-agent` installs:

- `/opt/fic/bin/fic-session-agent`
- `/etc/xdg/autostart/fic-session-agent.desktop`

`fic-cli` installs:

- `/opt/fic/bin/fic-cli`
- `/bin/fic-cli` symlink to `/opt/fic/bin/fic-cli`
- `/usr/share/bash-completion/completions/fic-cli`

`fic-gui` installs:

- `/opt/fic/bin/fic-gui`
- `/opt/fic/bin/fic-gui.real`
- bundled Qt runtime under `/opt/fic/qt`
- `/bin/fic-gui` symlink to `/opt/fic/bin/fic-gui`

Each project is packaged as a single binary file placed into `/opt/fic/bin`.

## Dependency chain

- `fic` requires `fic-dick`
- `fic-session-agent` is optional and must be installed separately when
  graphical-session policies are needed; ALT p11 RPM does not support the
  `Recommends` spec tag
- `fic-gui` requires both `fic` and `fic-dick`

## Ownership and permissions

During installation each package:

- creates the system group `fic` if it does not already exist;
- owns immutable `/opt/fic/share/default-config/*.conf` as ordinary package files;
- bootstraps missing FIC-owned `/opt/fic/config/*.conf` atomically without
  replacing existing files;
- initializes a missing `/opt/fic/db/devices.db` directly at the current schema
  through the offline maintenance command;
- creates `/opt/fic/lockstatus` and `/opt/fic/db/commandhash.txt` only when they do not yet exist;
- applies `root:fic` recursively to `/opt/fic`;
- applies `2750` to directories under `/opt/fic` so the group is inherited and
  the tree remains readable and traversable without group write access;
- applies `0640` to regular files under `/opt/fic`;
- applies `0750` to files in `/opt/fic/bin`.

Members of `fic` mutate configuration and device state through the two
administrative sockets. Direct access to configuration, database and binary
files is read-only.

## Installation lifecycle

Package versions must be Semantic Versions and are embedded through
`FIC_PRODUCT_VERSION`. The `fic-dick` and `fic` `%pre` actions stop active
daemons before either package replaces its executable payload. The `fic`
`%post` action creates only missing working configs, initializes an absent or
empty device database directly as schema 1, strictly checks config and DB schema
1, refreshes trusted command hashes, then starts and health-checks both
administrative daemons. Schema, trust, start, and health-check failures are
fatal; optional tmpfiles/udev refreshes remain best-effort.

Existing working configs and a non-empty database are never overwritten or
converted. Incompatible state makes installation fail with an explicit error.
Normal removal deletes package-owned defaults naturally, but never explicitly
deletes FIC-owned working configs, the working database or logs. Working configs
are absent from the RPM payload and are not declared with `%config`.
The complete state contract is in
[`docs/upgrade-contract.md`](../../docs/upgrade-contract.md).

The `fic` package runs `fic --trust-sync-platform` before enabling services and
installs the ALT-native `/usr/lib/rpm/fic-trust-sync.filetrigger`. ALT invokes
executable `*.filetrigger` helpers after a successful transaction and passes
the affected file list on standard input. The helper forwards that complete
list to `fic --trust-sync-platform-affected`; FIC matches it against
`profile.executables.entries` and does no package query or hash write when
there is no match. A matching transaction verifies and atomically refreshes
only the affected logical executables. Any mismatch fails the trigger and
leaves the existing hash store unchanged.

## Bundled Qt runtime for fic-gui

`fic-gui` bundles the Qt runtime inside the package to reduce dependency on the
Qt version installed on the target host.

The package:

- installs the real GUI binary as `/opt/fic/bin/fic-gui.real`;
- installs a launcher script as `/opt/fic/bin/fic-gui`;
- installs `/opt/fic/bin/qt.conf` to point Qt to the bundled runtime;
- copies the required Qt libraries into `/opt/fic/qt/lib`;
- copies the required Qt plugins into `/opt/fic/qt/plugins`;
- copies the shared-library dependency closure required by the bundled GUI runtime,
  excluding the base glibc loader/runtime components.

## Docker build for ALT p11

Build the packages inside the provided Docker image based on `alt:p11`:

```bash
chmod +x packaging/rpm/build-fic-alt-p11-rpm-docker.sh
./packaging/rpm/build-fic-alt-p11-rpm-docker.sh 0.0.0-alpha
```

The product version is mandatory and must be SemVer without build metadata.
There is no default. Prerelease product versions remain unchanged in the
binaries but use native package ordering: `0.1.0-rc.1` produces RPM version
`0.1.0~rc.1`.

This wrapper:

- builds `packaging/rpm/Dockerfile`;
- starts a container from `alt:p11`;
- installs build dependencies for `fic`, `fic-session-agent`, `fic-cli`, `fic-dick`, and `fic-gui`;
- runs `build-fic-alt-p11-rpm.sh` inside that container;
- uses a separate temporary `BUILD_ROOT` inside the container so it does not
  conflict with host-side CMake caches.

The resulting `.rpm` files are written into `dist/` in the repository.

## Build resource policy

Both the native and container entry points use
`packaging/lib/build-resources.sh`. By default the builder reserves 2 GiB of
currently available memory and one or two CPUs for the host, allows one C++
compile job per 2 GiB of the remaining memory, and caps automatic parallelism
at eight jobs. The build runs with nice level 10 and best-effort I/O priority
7.

The container wrapper applies the calculated CPU and memory limits to both
image build and package build. Its memory and memory-plus-swap limits are equal
by default, preventing the RPM/Qt compression stages from swapping out the
desktop session. `.containerignore` and `.dockerignore` exclude Git metadata,
`dist/`, and local build directories from the image build context.

Selected values are printed before the build. Explicit overrides are available
for larger build hosts and CI:

```bash
BUILD_JOBS=4 \
CONTAINER_CPUS=4 \
CONTAINER_MEMORY_MB=8192 \
CONTAINER_MEMORY_SWAP_MB=8192 \
./packaging/rpm/build-fic-alt-p11-rpm-docker.sh 0.0.0-alpha
```

Supported tuning variables are `BUILD_JOBS`, `FIC_BUILD_MAX_JOBS`,
`FIC_BUILD_MEMORY_PER_JOB_MB`, `FIC_HOST_MEMORY_RESERVE_MB`,
`CONTAINER_CPUS`, `CONTAINER_MEMORY_MB`, `CONTAINER_MEMORY_SWAP_MB`,
`FIC_BUILD_NICE`, and `FIC_BUILD_IONICE_PRIORITY`.
