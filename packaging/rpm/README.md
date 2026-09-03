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
`fic` RPM installs native ALT control facilities
`/etc/control.d/facilities/fic-pam-faillock` and
`/etc/control.d/facilities/fic-pam-pwhistory`. Installation does not activate
them; PAM topology remains an explicit administrator choice.

## ALT PAM topology integration

The package provides independent explicit activation for `pam_faillock` and
`pam_pwhistory`:

```bash
sudo control fic-pam-faillock status
sudo control fic-pam-faillock enabled
sudo control fic-pam-faillock disabled
sudo control fic-pam-pwhistory status
sudo control fic-pam-pwhistory enabled
sudo control fic-pam-pwhistory disabled
```

The facility is `disabled` after a clean install. It is a thin dispatcher to
the offline FIC PAM manager and never generates or edits PAM content in shell.
Enable acquires an inter-process lock, rejects symlink or untrusted targets,
uses the shared PAM parser to find the unique local `pam_tcb` auth/account
anchors in typed platform targets, and atomically installs FIC-owned marked
blocks. `system-auth-local-only` carries authentication+account blocks, while
`system-auth-use_first_pass-local-only` carries the authentication blocks used
by the stock SSH path. The native ALT `pam_tcb` auth rule in each target is
retained byte-for-byte in marker metadata, including `use_first_pass`, while
its active control is `sufficient`, as required by the ALT faillock topology.
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
AuthenticationLockout capability Effective for `system-auth-local-only` and
for configured services whose authentication graph uses the additional typed
target, including stock `sshd`. This explicit target scope does not reinterpret
unrelated native ALT `sss` routing; the global `required_pam_enforcement`
policy keeps its broader semantics.
An operational failure of `pam_faillock preauth` that itself terminates the
stack fail-closed is not reported as an `authfail` accounting bypass. A
credential failure terminating before `pam_faillock` is reached remains a
rejected bypass.
The stock `gdm-password` rule `auth sufficient pam_succeed_if.so user ingroup
nopasswdlogin` is accepted only as the exact platform-declared
`ExplicitPasswordlessLogin` bypass, including service, source, simple control,
and ordered arguments. The separate `disable_nopasswdlogin` policy accepts
only the typed ALT NSS contract (`files` with optional `systemd`, and trailing
`role` for group/initgroups), clears supplementary local membership with
hash-verified `gpasswd`, and verifies effective NSS membership using the same
primary-GID, group-record, and initgroups semantics as `pam_succeed_if`.
Primary-GID, residual role-derived membership, and unknown or remote NSS
services fail closed. Lockout/authentication policies recommend this policy, while
password quality and history policies do not depend on it.
Before mutation the manager inspects the effective include/substack graph of
configured authentication services and rejects external `pam_faillock` rules.
Failed postconditions restore the exact original bytes of every written target;
a failed rollback is reported as a critical inconsistent-state error.

FIC never adopts or removes administrator-owned `pam_faillock` rules. Partial,
duplicated or modified FIC markers fail closed. Disable removes only valid
FIC-owned blocks and restores the original `pam_tcb` rule; unrelated content
is preserved. Moved managed blocks make disable fail without mutation. Atomic
replacement also refuses a target whose `dev+ino` changed since the secure
snapshot. The facility never changes `control system-auth` or its symlinks.

The password-history facility manages only the password path in
`system-auth-local-only`. It requires the unique native `pam_tcb.so
write_to=tcb` rule and rejects an existing external `pam_pwhistory` or
`pam_fic_pwtxn` rule. Enable keeps that `pam_tcb` line byte-for-byte and wraps
it in the following owned block:

```text
password requisite pam_fic_pwtxn.so begin timeout=15
password requisite pam_pwhistory.so use_authtok conf=/etc/security/fic-pwhistory.conf
<original pam_tcb password rule>
password required pam_fic_pwtxn.so end
```

`pam_fic_pwtxn.so` serializes the complete history/backend update using
`/var/lib/fic-pwhistory/.lock`; PAM cleanup releases the lock even when the
requisite history check terminates dispatch before the explicit `end` call.
The history database is `/var/lib/fic-pwhistory/opasswd`. The directory is
`root:shadow 2730`, while both `opasswd` and `.lock` are one-link regular
`root:shadow 0660` files. The module has a fixed lock path and rejects unsafe
metadata. The manager likewise verifies trusted module/config files and
requires exactly `file=/var/lib/fic-pwhistory/opasswd`.

The RPM prepares this storage but ships `remember=0`, so installation and
topology activation do not themselves enforce password history. Administrator
order is: install/update `fic`, run `control fic-pam-pwhistory enabled`, verify
`status`, then apply the FIC history-depth/root policy. Disable restores the
exact pre-enable PAM bytes but deliberately retains the history database.

RPM upgrade uses ALT `control-dump` / `control-restore` to preserve the selected
enabled/disabled state. Final erase invokes the same safe disable operation
before removing the helper and facility; malformed managed state makes erase
fail instead of triggering blind cleanup.

The `fic` RPM depends on `control`, `pam >= 1.7.1` (the ALT p11 owner of
`pam_faillock.so` and `pam_pwhistory.so`) and `pam-config >= 1.10.0` (the owner of
`system-auth-local-only`). Native `pam_passwdqc` topology remains unchanged and
has no FIC activation facility. The ALT platform composition uses the strict
native `/etc/passwdqc.conf` backend (`option=value`, PAM argument `config=`)
for passwdqc thresholds, passphrase, match, similar, retry and root-enforcement
settings. It does not expose pwquality-only policies.

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
- `/etc/control.d/facilities/fic-pam-pwhistory` (disabled by default)
- `/lib64/security/pam_fic_pwtxn.so`
- `/etc/security/fic-pwhistory.conf`
- persistent `/var/lib/fic-pwhistory/{opasswd,.lock}` storage

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

`fic-gui` dynamically links to a minimal Qt runtime bundled inside the package.
FIC remains under SUL-1.0; bundled Qt files retain their RPM-declared
third-party licenses. The generated `fic-gui` spec uses
`SUL-1.0 AND LGPL-3.0-only`: this describes the separately licensed payload and
does not relicense FIC under LGPL.

The package:

- installs the real GUI binary as `/opt/fic/bin/fic-gui.real`;
- installs a launcher script as `/opt/fic/bin/fic-gui`;
- installs `/opt/fic/bin/qt.conf` to point Qt to the bundled runtime;
- starts the closure from `fic-gui.real`, `platforms/libqxcb.so`, and
  `imageformats/libqjpeg.so`;
- recursively copies only required `libQt6*.so*` files from the `qt6-base`
  source RPM;
- leaves package-owned non-Qt libraries as system dependencies and rejects an
  unexpected unowned dependency;
- generates `/usr/share/doc/fic-gui/third-party-components.json`, source-RPM
  provenance, RPM license notices, SUL-1.0, LGPLv3/GPLv3 texts, and
  `SOURCE_OFFER.md` from the actual payload.

Set `FIC_QT_ROOT=/path/to/custom/qt` to make the launcher use that compatible
`lib/` and `plugins/` tree instead of `/opt/fic/qt`. `fic-gui.real` can also be
run directly with caller-supplied loader/plugin paths.

Packaging fails if Qt is not dynamically linked, required notices are missing,
the manifest and `/opt/fic/qt` differ, or a Qt file does not originate from
`qt6-base`. Official releases must also satisfy the Corresponding Source gate
documented in
[`docs/third-party-licensing.md`](../../docs/third-party-licensing.md).

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
