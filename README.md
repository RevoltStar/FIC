FIC - daemon-centered Free Integrity Control

Development status:

- This repository contains the FIC implementation. The old
  FIC 1.x prototype was never released and has no compatibility or migration
  contract.
- The current development version is `0.0.0-alpha`. The first planned stable
  release is `0.1.0`; prereleases use tags such as `v0.1.0-rc.1`.

Components:
- fic: daemon, owns policy application and /opt/fic/config mutations through /run/fic/fic.sock
- fic-session-agent: per-graphical-session context provider; it does not apply policies
- fic-cli: terminal client; sends set/enable/disable/apply commands to fic
- fic-gui: graphical client; sends config mutation commands to fic
- fic-dick: device database collector

The daemon exposes module descriptors through `module_list`. Each descriptor
has a `name` and a `view` (`standard`, `device`, or `audit`); `policy_list`
contains the editor metadata for policies without duplicating the module view.
The Qt GUI selects a page from this contract. A future web client must use the
same daemon APIs and must not read policy configs, device SQLite data, or logs
directly.

`AUDIT/log_level` controls regular FIC records emitted through `Logger`.
Administrative IPC requests are written to a separate always-on security audit
trail; it is not filtered by `AUDIT/log_level`, including when the value is
`NoLog`.

Shared libraries:
- fic-common/fic-version: compiled product, IPC, configuration, and database schema versions
- fic-common/fic-ipc: shared IPC client/protocol helpers used by fic, fic-cli, fic-gui, and fic-session-agent
- fic-common/fic-core: shared low-level utilities used by fic, fic-dick, and fic-device-db
- fic-common/fic-device-db: shared SQLite device database access layer used by fic and fic-dick
- fic-common/fic-policy: shared policy base classes, apply-result model, and policy value types

Access model:
- Access to the daemon API is intentionally controlled by Unix socket permissions.
- Members of the `fic` OS group are treated as full FIC administrators and currently have full access to all daemon API commands, including configuration changes, policy application, device database changes, lock/unlock actions, hash recalculation, and daemon shutdown.
- Members of `fic` can read and execute installed FIC files as appropriate, but
  cannot modify `/opt/fic` directly. Policy configuration and device state
  mutations must go through the daemon sockets.
- Ordinary users must not be added to the `fic` group.

Target platforms:
- The privileged daemon is built for exactly one target platform.
- Supported profiles are `debian-12`, `debian-13`, `ubuntu-24.04`, `ubuntu-26.04` and
  `alt-p11`.
- CMake configuration must select one explicitly, for example:

```bash
cmake -S . -B build-check -DFIC_TARGET_PLATFORM=alt-p11
```

- Distribution packaging scripts select their own fixed profile. At runtime the
  daemon checks `/etc/os-release` and refuses to start on an incompatible host.
- The profile owns distribution integration data used by policies: system tool
  paths, SSH and sudo layouts, PAM service/config/module locations,
  display-manager configuration paths, and the DAC system-file/command rule
  sets. Desktop-environment and kernel/FHS capability detection remains
  independent of the distribution profile.
- Executable candidates are stored once in the profile under the typed
  `executables` registry (`Sshd`, `Systemctl`, `Loginctl`, `Visudo`, `Lscpu`,
  `Dmidecode`, `Udevadm`, `UpdateGrub`, `Nft`). Policies request a logical executable ID from the
  shared resolver instead of maintaining their own path lists.
- Initial package installation runs `fic --trust-sync-platform`. Subsequent
  package triggers pass affected paths to
  `fic --trust-sync-platform-affected`; only paths listed in the compiled
  profile's `executables` registry are verified against the `dpkg` or RPM
  database and atomically refreshed. Normal daemon runtime never accepts a new
  hash.

Version and schema contract:
- Product versions are Semantic Versions. Official release versions come only
  from exact annotated `vMAJOR.MINOR.PATCH[-prerelease]` Git tags; package
  builders require an explicit version and have no fallback default.
- `--version` reports the product version. `--build-info` additionally reports
  build kind, the full source commit, release tag, and independent API/schema
  versions without mixing the commit into SemVer.
- Administrative IPC, policy configuration, and the device SQLite database
  have independent schema/API versions.
- Fresh schema-1 bootstrap, strict state validation and package lifecycle are
  documented in
  [`docs/upgrade-contract.md`](docs/upgrade-contract.md).
- The release gate and native package version mapping are documented in
  [`docs/release-process.md`](docs/release-process.md).

License:
- FIC is source-available under the Sustainable Use License Version 1.0
  (`SUL-1.0`); see [`LICENSE`](LICENSE).
- The license permits personal and non-commercial use and a company's own
  internal business use. Distribution is permitted only free of charge for
  non-commercial purposes.
- `SUL-1.0` is not an OSI-approved open-source license. Third-party components
  retain their own license terms.
- Binary `fic-gui` packages dynamically link to and bundle a minimal Qt runtime.
  Qt and every other bundled third-party component remain under their own
  licenses; their inclusion does not relicense FIC. Runtime notices, provenance,
  replacement instructions, and the release source-artifact contract are
  documented in [`docs/third-party-licensing.md`](docs/third-party-licensing.md).
