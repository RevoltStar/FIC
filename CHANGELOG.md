# Changelog

All notable changes to FIC releases are documented in this file.

The project has not published a stable release yet. FIC 1.x was an unreleased
prototype and is not part of the compatibility or migration contract. The
first planned stable release is 2.0.0.

## [Unreleased]

- Initial release engineering and compatibility contract for FIC 2.0.
- Device Control now compiles desired policy from `devices.db` into atomically
  activated udev rules, with direct/children policy, identity matching and
  SQLite-free hotplug enforcement.
- Added FIREWALL v1 with validated IPv4/IPv6 nftables rules, status-only RDP
  and FTP blocking policies, atomic startup/periodic reconciliation, and a
  deliberately limited exclusive host INPUT/OUTPUT filtering mode.
