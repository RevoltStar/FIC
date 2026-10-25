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
- `/etc/udev/rules.d/99-fic-devices.rules` (bootstrap, затем active generated policy)

`fic` installs:

- `/opt/fic/bin/fic`
- `/opt/fic/bin/fic-udevadm-trigger`
- immutable defaults under `/opt/fic/share/default-config/*.conf`
- working `/opt/fic/config` is created by the first-install maintenance command,
  not carried in the package payload
- `/opt/fic/db`
- `/opt/fic/image`
- `/opt/fic/lang`
- `/opt/fic/log`
- `/opt/fic/notify`
- `/lib/systemd/system/*` from `fic/src/resources/service`
- inactive package profiles `/usr/share/pam-configs/fic-faillock-notify`,
  `/usr/share/pam-configs/fic-faillock-authfail`,
  `/usr/share/pam-configs/fic-faillock-preauth-required`,
  `/usr/share/pam-configs/fic-faillock-authsucc`,
  `/usr/share/pam-configs/fic-pwquality` and
  `/usr/share/pam-configs/fic-pwhistory`
- `/bin/fic` symlink to `/opt/fic/bin/fic`

During installation, `fic.service`, `fic-device.service` and `fic-notify.service`
are enabled and started automatically. `fic-device.service` performs initial
device reconciliation itself from current udev/sysfs inventory. The
`fic_get_device_udev_info.service` helper no longer runs a mass
`udevadm trigger`; it waits for the device daemon and then runs the
permanent-device check.

`fic-session-agent` installs:

- `/usr/libexec/fic/fic-session-agent` (`root:root`, mode `0755`)
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
- `fic` directly depends on `libpam-runtime`, `libpam-modules` and
  `libpam-pwquality`: the first provides `pam-auth-update`, the second owns the
  core PAM modules referenced by the FIC profiles, and the third provides
  `pam_pwquality.so`; FIC ships its own inactive `fic-pwquality` activation
  profile and never takes ownership of the distro `pwquality` profile.
  AuthenticationLockout additionally installs four permanent pam-auth-update
  hook profiles plus four `/etc/pam.d/fic-faillock-*` conffile slots. The
  hooks are infrastructure; only journal-bound slot markers are policy-owned.
- `fic` directly depends on `libnotify-bin` for `notify-send` and on
  `util-linux` for the notification dispatcher's `setpriv`
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
- owns immutable `/opt/fic/share/default-config/*.conf` as ordinary package files;
- bootstraps the working config tree only on first install when its directory
  is absent; upgrades preserve existing files and reject missing `GLOBAL.conf`;
- initializes a missing `/opt/fic/db/devices.db` directly at the current schema
  through the offline maintenance command;
- creates `/opt/fic/lockstatus` and `/opt/fic/db/commandhash.txt` only when they do not yet exist;
- normalizes ordinary package state while excluding `/opt/fic`,
  `/opt/fic/config`, `GLOBAL.conf` and their aliases from generic metadata
  repair;
- applies `0750` to files in `/opt/fic/bin`.

Members of `fic` mutate configuration and device state through the two
administrative sockets. Direct access to configuration, database and binary
files is read-only.

## Installation lifecycle

Package versions are embedded through `FIC_PRODUCT_VERSION`. The existing
`fic-dick` dependency carries the infrastructure-only helper. Compatible install
and upgrade establish INSTALLING before payload replacement, prove configuration,
MutationJournal, PAM/incident infrastructure and the current device DB schema,
then explicitly publish INSTALLED before starting and health-checking services.
Failed proofs leave startup fenced; upgrade never performs ownership rollback or
restores old executables. See [package lifecycle](../../docs/package-lifecycle.md)
for the authoritative state, override, remove/purge and failure contract.

Existing working configs and a non-empty database are never overwritten or
converted. Incompatible state makes installation fail with an explicit error.
The canonical config authority is a real `root:fic` directory with mode `2750`
and single-link regular `root:fic` files with mode `0640`. Unsafe existing
metadata is neither repaired nor accepted by package configuration or daemon
startup. The first-install-only `ensure-config-first-install` command proves
the metadata of the tree it creates; upgrades use `ensure-config`.
Normal removal deletes package-owned defaults naturally, but never explicitly
deletes FIC-owned working configs, the working database or logs. No
`DEBIAN/conffiles` entry is created for `/opt/fic/config/*.conf`.
The complete state contract is in
[`docs/upgrade-contract.md`](../../docs/upgrade-contract.md).

The `fic` package runs `fic --trust-sync-platform` before enabling services and
generates exact `dpkg` `interest-noawait` file triggers from the compiled
platform profile's executable candidates. On a triggered maintainer-script
run, the activated paths are passed to `fic --trust-sync-platform-affected`.
FIC ignores unrelated paths and verifies only the affected logical executables
against package checksums before atomically refreshing their SHA-256 references.
A failed package integrity check leaves all existing references unchanged and
fails the maintainer-script action.

## PAM integration

The Debian and Ubuntu `fic` package ships ten declarations under
`/usr/share/pam-configs/`: four legacy faillock profiles, `fic-pwquality`,
`fic-pwhistory`, and four permanent `fic-faillock-hook-*` integration
profiles. The declarations are ordinary package data, not conffiles. The
package also owns four `/etc/pam.d/fic-faillock-*` conffile slots.

`pam-auth-update` remains the owner of generated `common-*`. On configure the
maintainer script first runs the read-only pre-attach validation

```sh
/opt/fic/bin/fic --maintenance validate-pam-slots-before-attach
```

and aborts package configuration (before the daemon is started) when the
preserved `/etc/pam.d/fic-faillock-*` slots are not proven canonical-neutral
or journal-bound FIC-owned state. Only after a passing validation does it run
`pam-auth-update --package` and explicitly enable the four permanent hook
profiles. It never uses `--force`. Runtime policy enable/disable does not own
those hook selections: AuthenticationLockout owns only strict marker blocks
inside the four slot files.

On remove, the running daemon first enters durable UNINSTALLING and releases
ownership through `policy rollback all` without changing configured ENABLE/values.
The infrastructure helper then takes daemon.lock, proves stopped unit/cgroup and
process state, detaches permanent hooks and independently proves the absence of
PAM references. Overrides cannot waive those final proofs. There is no autonomous
rollback or automatic reattachment/restart on `abort-remove`; failed release
retains its provenance and UNINSTALLING until a successful retry.

Remove preserves working configuration and the journal/witness pair. A late
purge without the daemon ELF uses the previous REMOVED proof under daemon.lock
and deletes that retained data. dpkg may delete its own neutral PAM conffiles
before postrm; failed postrm does not authorize deletion of FIC data. Retry is
idempotent. The restrictive REMOVED marker remains after purge.

The hook topology is:

```text
fic-faillock-hook-preauth  -> /etc/pam.d/fic-faillock-preauth
fic-faillock-hook-authfail -> /etc/pam.d/fic-faillock-authfail
fic-faillock-hook-authsucc -> /etc/pam.d/fic-faillock-authsucc
fic-faillock-hook-account  -> /etc/pam.d/fic-faillock-account
```

An active slot carries the exact journal mutation id and strategy. A neutral
slot contains one `optional pam_deny.so`: this preserves the one-element slot
shape used when `pam-auth-update` calculates numeric jumps, while a degenerate
stack containing only the hook fails closed. A strategy transition rewrites
only the FIC-owned slots; `common-*` is never directly edited by the daemon.

Legacy selector declarations in package data are not permission to adopt old
ownership or to migrate arbitrary development installations. Compatible upgrade
validates current provenance; no guarantee is made that a new script can prevent
an old package manager scriptlet from running. Password quality/history use the
current C2 owned-slot and joint package preflight/release contract. Pre-attach
validation must accept its active-owned/neutral-sibling shape, and must not use
the obsolete legacy pair validator.

The ownership/diagnostic details are in
[`docs/pam-owned-faillock-slots.md`](../../docs/pam-owned-faillock-slots.md).
