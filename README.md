FIC 2.0 - daemon-centered Free Integrity Control prototype

Components:
- fic: daemon, owns policy application and /opt/fic/config mutations through /run/fic/fic.sock
- fic-session-agent: per-graphical-session context provider; it does not apply policies
- fic-cli: terminal client; sends set/enable/disable/apply commands to fic
- fic-gui: graphical client; sends config mutation commands to fic
- fic-dick: device database collector

Shared libraries:
- fic-common/fic-ipc: shared IPC client/protocol helpers used by fic, fic-cli, fic-gui, and fic-session-agent
- fic-common/fic-core: shared low-level utilities used by fic, fic-dick, and fic-device-db
- fic-common/fic-device-db: shared SQLite device database access layer used by fic and fic-dick
- fic-common/fic-policy: shared policy base classes, apply-result model, and policy value types

Access model:
- Access to the daemon API is intentionally controlled by Unix socket permissions.
- Members of the `fic` OS group are treated as full FIC administrators and currently have full access to all daemon API commands, including configuration changes, policy application, device database changes, lock/unlock actions, hash recalculation, and daemon shutdown.
- Ordinary users must not be added to the `fic` group.

Target platforms:
- The privileged daemon is built for exactly one target platform.
- Supported profiles are `debian-12`, `debian-13`, `ubuntu-24.04`, and
  `alt-p11`.
- CMake configuration must select one explicitly, for example:

```bash
cmake -S . -B build-check -DFIC_TARGET_PLATFORM=alt-p11
```

- Distribution packaging scripts select their own fixed profile. At runtime the
  daemon checks `/etc/os-release` and refuses to start on an incompatible host.
- The profile owns distribution integration data used by policies: system tool
  paths, SSH and sudo layouts, display-manager configuration paths, and the DAC
  system-file/command rule sets. Desktop-environment and kernel/FHS capability
  detection remains independent of the distribution profile.
- Executable candidates are stored once in the profile under the typed
  `executables` registry (`Sshd`, `Systemctl`, `Loginctl`, `Visudo`, `Lscpu`,
  `Dmidecode`, `Udevadm`). Policies request a logical executable ID from the
  shared resolver instead of maintaining their own path lists.
- Initial package installation runs `fic --trust-sync-platform`. Subsequent
  package triggers pass affected paths to
  `fic --trust-sync-platform-affected`; only paths listed in the compiled
  profile's `executables` registry are verified against the `dpkg` or RPM
  database and atomically refreshed. Normal daemon runtime never accepts a new
  hash.
