# FIC Debian and Ubuntu packaging

Payload бинарников, service-файлов, конфигурации и данных берется из
именованных CMake install-компонентов. Скрипты упаковки отвечают за metadata,
maintainer scripts и Qt runtime bundle, но не поддерживают отдельную копию
production-путей в исходных systemd/tmpfiles/udev-файлах.

This packaging flow builds five distribution-specific Debian-format packages:

- `fic-dick`
- `fic`
- `fic-session-agent`
- `fic-cli`
- `fic-gui`

## Package contents

`fic-dick` installs:

- `/opt/fic/bin/fic-dick`
- `/lib/systemd/system/fic-device.service`
- `/lib/systemd/system/fic_get_device_info.service`

`fic` installs:

- `/opt/fic/bin/fic`
- `/opt/fic/bin/fic-udevadm-trigger`
- `/opt/fic/config`
- `/opt/fic/db`
- `/opt/fic/image`
- `/opt/fic/lang`
- `/opt/fic/log`
- `/opt/fic/notify`
- `/opt/fic/state`
- `/lib/systemd/system/*` from `fic/src/scripts/service`
- `/etc/udev/rules.d/*` from `fic/src/scripts/udev`
- `/bin/fic` symlink to `/opt/fic/bin/fic`

During installation, `fic.service`, `fic-device.service` and `fic-notify.service`
are enabled and started automatically. The coldplug device scan service
`fic_get_device_udev_info.service` is enabled and runs through systemd when
requested by the target.

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

- `fic` depends on `fic-dick`
- `fic` recommends `fic-session-agent`
- `fic-gui` depends on both `fic` and `fic-dick`

As a result:

- `fic` cannot be installed without `fic-dick`
- `fic` can be installed without `fic-session-agent`, but desktop-session policies
  require the agent package to be installed and running in graphical sessions
- `fic-gui` cannot be installed without `fic` and `fic-dick`

## Ownership and permissions

During installation each package:

- creates the system group `fic` if it does not already exist;
- preserves `/opt/fic/config/*.conf` as package-managed configuration files;
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

## Upgrade lifecycle

Package versions must be Semantic Versions and are embedded through
`FIC_PRODUCT_VERSION`. The `fic-dick` and `fic` pre-install actions stop active
daemons before either package replaces its executable payload. The `fic`
post-install action then resumes or creates `/opt/fic/state/upgrade.journal`, backs up and migrates all
policy configs, performs the SQLite migration through `fic-dick`, commits the
journal, refreshes trusted command hashes, then starts and health-checks both
administrative daemons. Migration, trust, start, and health-check failures are
fatal; optional tmpfiles/udev refreshes remain best-effort.

Downgrade is intentionally rejected. Normal removal disables services, leaves
configs to Debian conffile semantics, and never explicitly deletes the working
database, journal, logs, or backups.
The complete recovery and rollback policy is in
[`docs/upgrade-contract.md`](../../docs/upgrade-contract.md).

The `fic` package runs `fic --trust-sync-platform` before enabling services and
generates exact `dpkg` `interest-noawait` file triggers from the compiled
platform profile's executable candidates. On a triggered maintainer-script
run, the activated paths are passed to `fic --trust-sync-platform-affected`.
FIC ignores unrelated paths and verifies only the affected logical executables
against package checksums before atomically refreshing their SHA-256 references.
A failed package integrity check leaves all existing references unchanged and
fails the maintainer-script action.

## Bundled Qt runtime for fic-gui

`fic-gui` bundles the Qt runtime inside the package to reduce dependency on the
Qt version installed on the target host.

The package now:

- installs the real GUI binary as `/opt/fic/bin/fic-gui.real`;
- installs a launcher script as `/opt/fic/bin/fic-gui`;
- installs `/opt/fic/bin/qt.conf` to point Qt to the bundled runtime;
- copies the required Qt libraries into `/opt/fic/qt/lib`;
- copies the required Qt plugins into `/opt/fic/qt/plugins`;
- copies the shared-library dependency closure required by the bundled GUI runtime,
  excluding the base glibc loader/runtime components.

The launcher sets `LD_LIBRARY_PATH`, `QT_PLUGIN_PATH`, and
`QT_QPA_PLATFORM_PLUGIN_PATH` before starting `fic-gui.real`.

## Build

Debian 12, Debian 13, and Ubuntu 24.04 use separate entry points. Each entry
point fixes the daemon compile-time platform profile and output distribution
tag:

```bash
./packaging/deb/build-fic-debian12-deb.sh 2.0.0-dev
./packaging/deb/build-fic-debian13-deb.sh 2.0.0-dev
./packaging/deb/build-fic-ubuntu2404-deb.sh 2.0.0-dev
```

The product version is mandatory and must be SemVer without build metadata.
There is no default. Prerelease product versions remain unchanged in the
binaries but use native package ordering: `2.0.0-rc.1` produces DEB version
`2.0.0~rc.1`.

The resulting packages are created under `dist/`. Output filenames include the
target distribution tag, for example
`fic-cli_2.0.0~dev_debian13_amd64.deb`.

## Docker build

To avoid bundling Qt libraries that were compiled against a too-new `glibc`,
build each package set inside its matching distribution image.

Build Debian 12, Debian 13, or Ubuntu 24.04 through its matching container:

```bash
./packaging/deb/build-fic-debian12-deb-docker.sh 2.0.0-dev
./packaging/deb/build-fic-debian13-deb-docker.sh 2.0.0-dev
./packaging/deb/build-fic-ubuntu2404-deb-docker.sh 2.0.0-dev
```

Each builder passes its fixed `FIC_TARGET_PLATFORM` (`debian-12`, `debian-13`,
or `ubuntu-24.04`) and never derives the target from the build host. The
wrappers use separate temporary `BUILD_ROOT` directories, and the resulting
`.deb` files are written into `dist/`.

The payload compressor can be overridden explicitly:

```bash
DEB_COMPRESSOR=gzip ./packaging/deb/build-fic-debian12-deb.sh 2.0.0-dev
```

## Build resource policy

All native and container entry points use
`packaging/lib/build-resources.sh`. By default a builder:

- reserves 2 GiB of currently available memory for the host;
- reserves two CPUs on hosts with at least four CPUs, or one CPU on smaller
  multi-core hosts;
- allows one parallel C++ job per 2 GiB of the remaining memory;
- caps automatic parallelism at eight jobs;
- runs with process nice level 10 and best-effort I/O priority 7.

Container wrappers apply the calculated CPU and memory limits to both image
build and package build. The container memory and memory-plus-swap limits are
equal by default, so a package build cannot make the host unresponsive by
swapping out the desktop session. `.containerignore` and `.dockerignore`
exclude Git metadata, `dist/`, and local build directories from the image build
context.

The detected values and selected limits are printed before the build. They can
be overridden when additional throughput or a stricter CI limit is required:

```bash
BUILD_JOBS=4 \
CONTAINER_CPUS=4 \
CONTAINER_MEMORY_MB=8192 \
CONTAINER_MEMORY_SWAP_MB=8192 \
./packaging/deb/build-fic-debian13-deb-docker.sh 2.0.0-dev
```

The tuning inputs are:

- `BUILD_JOBS`: explicit CMake parallelism;
- `FIC_BUILD_MAX_JOBS`: automatic parallelism cap, default `8`;
- `FIC_BUILD_MEMORY_PER_JOB_MB`: memory allowance per job, default `2048`;
- `FIC_HOST_MEMORY_RESERVE_MB`: memory kept outside the container, default
  `2048`;
- `CONTAINER_CPUS`, `CONTAINER_MEMORY_MB`, and
  `CONTAINER_MEMORY_SWAP_MB`: explicit container limits;
- `FIC_BUILD_NICE` and `FIC_BUILD_IONICE_PRIORITY`: scheduling priorities,
  default `10` and `7`.
