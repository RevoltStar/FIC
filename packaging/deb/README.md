# FIC Debian packaging

This packaging flow builds four Debian packages:

- `fic-dick`
- `fic`
- `fic-cli`
- `fic-gui`

## Package contents

`fic-dick` installs:

- `/opt/fic/bin/fic-dick`

`fic` installs:

- `/opt/fic/bin/fic`
- `/opt/fic/bin/fic-udevadm-trigger`
- `/opt/fic/config`
- `/opt/fic/db`
- `/opt/fic/share/devices.seed.db`
- `/opt/fic/image`
- `/opt/fic/lang`
- `/opt/fic/log`
- `/opt/fic/notify`
- `/lib/systemd/system/*` from `fic/src/scripts/service`
- `/etc/udev/rules.d/*` from `fic/src/scripts/udev`
- `/bin/fic` symlink to `/opt/fic/bin/fic`

During installation, the bundled systemd services are enabled with
`systemctl enable`, and `fic.service` is started automatically.

`fic-cli` installs:

- `/opt/fic/bin/fic-cli`
- `/bin/fic-cli` symlink to `/opt/fic/bin/fic-cli`

`fic-gui` installs:

- `/opt/fic/bin/fic-gui`
- `/opt/fic/bin/fic-gui.real`
- bundled Qt runtime under `/opt/fic/qt`
- `/bin/fic-gui` symlink to `/opt/fic/bin/fic-gui`

Each project is packaged as a single binary file placed into `/opt/fic/bin`.

## Dependency chain

- `fic` depends on `fic-dick`
- `fic-gui` depends on both `fic` and `fic-dick`

As a result:

- `fic` cannot be installed without `fic-dick`
- `fic-gui` cannot be installed without `fic` and `fic-dick`

## Ownership and permissions

During installation each package:

- creates the system group `fic` if it does not already exist;
- preserves `/opt/fic/config/*.conf` as package-managed configuration files;
- installs the seed database as `/opt/fic/share/devices.seed.db`;
- creates `/opt/fic/db/devices.db` from the seed only when the working database does not yet exist;
- creates `/opt/fic/lockstatus` and `/opt/fic/config/commandhash.conf` only when they do not yet exist;
- applies `root:fic` recursively to `/opt/fic`;
- applies `2770` to directories under `/opt/fic` so the group is inherited and the directories remain traversable;
- applies `0660` to regular files under `/opt/fic`;
- applies `0770` to files in `/opt/fic/bin`.

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

Run on a Debian/Ubuntu-like system or inside WSL with Debian tooling installed:

```bash
chmod +x packaging/deb/build-fic-debian12-deb.sh
./packaging/deb/build-fic-debian12-deb.sh 0.1.0
```

The resulting packages are created under `dist/`. Output filenames include the
target distribution tag, for example `fic-cli_0.1.0_debian12_amd64.deb`.

## Docker build for broader compatibility

To avoid bundling Qt libraries that were compiled against a too-new `glibc`,
build the packages inside the provided Docker image based on Debian 12.

Why Debian 12:

- it provides Qt6 packages out of the box;
- its `glibc` is older than on newer build hosts;
- packages built there are more likely to run on newer Debian systems.

Build through Docker:

```bash
chmod +x packaging/deb/build-fic-debian12-deb-docker.sh
./packaging/deb/build-fic-debian12-deb-docker.sh 0.1.0
```

This wrapper:

- builds `packaging/deb/Dockerfile`;
- starts a container from `debian:12`;
- installs build dependencies for `fic`, `fic-cli`, `fic-dick`, and `fic-gui`;
- runs `build-fic-debian12-deb.sh` inside that container;
- uses a separate temporary `BUILD_ROOT` inside the container so it does not
  conflict with host-side `build-linux/` CMake caches.

The resulting `.deb` files are still written into `dist/` in the repository.
The distribution tag can be overridden with `PACKAGE_DISTRO_TAG` if needed.

## Debian 9 compatibility

The build script forces `gzip` compression for the Debian package payloads so that
older systems such as Debian 9 can install the resulting `.deb` files.

If needed, the compressor can be overridden explicitly:

```bash
DEB_COMPRESSOR=gzip ./packaging/deb/build-fic-debian12-deb.sh 0.1.0
```
