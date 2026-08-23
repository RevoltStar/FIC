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
the Debian package `libpam-runtime` and do not invoke `pam-auth-update`. PAM
topology activation remains an administrator responsibility until a separate
ALT-specific integration is designed around the native `pam-config` /
`pam-config-control` mechanism; that integration is outside the current
package contract.

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
- `/usr/lib/systemd/system/*` from `fic/src/scripts/service`
- `/bin/fic` symlink to `/opt/fic/bin/fic`

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
