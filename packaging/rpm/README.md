# FIC RPM packaging for ALT p11

This packaging flow builds three RPM packages for ALT Linux p11:

- `fic-dick`
- `fic`
- `fic-cli`
- `fic-gui`

## Package contents

`fic-dick` installs:

- `/opt/fic/bin/fic-dick`

`fic` installs:

- `/opt/fic/bin/fic`
- `/opt/fic/bin/fic-session-agent`
- `/opt/fic/bin/fic-udevadm-trigger`
- `/opt/fic/config`
- `/opt/fic/db`
- `/opt/fic/share/devices.seed.db`
- `/opt/fic/image`
- `/opt/fic/lang`
- `/opt/fic/log`
- `/opt/fic/notify`
- `/usr/lib/systemd/system/*` from `fic/src/scripts/service`
- `/etc/udev/rules.d/*` from `fic/src/scripts/udev`
- `/etc/xdg/autostart/fic-session-agent.desktop`
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

- `fic` requires `fic-dick`
- `fic-gui` requires both `fic` and `fic-dick`

## Ownership and permissions

During installation each package:

- creates the system group `fic` if it does not already exist;
- preserves `/opt/fic/config/*.conf` as `%config(noreplace)` files;
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
./packaging/rpm/build-fic-alt-p11-rpm-docker.sh 0.1.0
```

This wrapper:

- builds `packaging/rpm/Dockerfile`;
- starts a container from `alt:p11`;
- installs build dependencies for `fic`, `fic-cli`, `fic-dick`, and `fic-gui`;
- runs `build-fic-alt-p11-rpm.sh` inside that container;
- uses a separate temporary `BUILD_ROOT` inside the container so it does not
  conflict with host-side CMake caches.

The resulting `.rpm` files are written into `dist/` in the repository.
