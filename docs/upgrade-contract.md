# FIC product upgrade contract

This document defines the versioned upgrade boundary for the second-generation
FIC implementation. FIC 1.x was never released and has no supported state,
configuration, database, IPC, or package migration path. The current
`2.0.0-dev` line is development software; the first planned stable release is
`2.0.0`.

## Independent versions

| Contract | Current version | Owner | Compatibility rule |
|---|---:|---|---|
| Product | `2.0.0-dev` | annotated Git release tag and `fic-common/fic-version` | Must be SemVer without build metadata. Official releases require an exact matching tag, full commit and clean tree. |
| Administrative IPC | `2` | `fic-common/fic-ipc` | Every request and response contains `api_version`. A mismatch is rejected before routing. Version 2 changes `module_list` from strings to `{name, view}` descriptors. |
| Policy configuration | `2` | `fic-core/UpgradeManager` | Every installed module config contains exactly one `_schema_version`. Schema 2 adds `AUDIT.conf` and moves `log_level` out of `GLOBAL.conf`. Normal startup accepts only the exact current schema. |
| Device SQLite database | `2` | `fic-device-db` | `PRAGMA application_id=0x46494344` and `PRAGMA user_version=2` identify the database and schema. Normal startup never mutates an old schema. |

The versions are deliberately independent. Changing the product version does
not imply an IPC or storage-schema change. A breaking change increments only
the affected contract and adds an explicit offline migration where applicable.

The Git tag is the sole release-version authority. CMake defaults to the
identifiable development version `2.0.0-dev`; package builders require the
product version as an explicit argument. For native ordering, a prerelease such
as `2.0.0-rc.1` remains the embedded product version but maps to package version
`2.0.0~rc.1`. Stable `2.0.0` maps unchanged.

Every executable provides `--build-info`. The output keeps the full 40-character
source commit and release tag in separate fields rather than appending them to
SemVer. A release build is rejected during CMake configuration unless
`FIC_RELEASE_BUILD=ON`, `FIC_RELEASE_TAG=v<FIC_PRODUCT_VERSION>`, and a full
lowercase commit SHA are supplied. Development builds use `release_tag=none`.

## Package upgrade sequence

The DEB/RPM lifecycle performs the following fail-closed sequence:

1. stop active `fic`, `fic-device`, and `fic-notify` services from both daemon
   package pre-install actions, before either executable payload is replaced;
2. create any missing working policy configs atomically from the package-owned
   immutable defaults in `/opt/fic/share/default-config`, without replacing any
   existing working config;
3. create/resume `/opt/fic/state/upgrade.journal` for the target product version;
4. back up all policy configs and migrate them offline;
5. create a consistent SQLite backup with the SQLite Backup API, run the
   supported schema migration in one transaction, and run `quick_check` plus
   `foreign_key_check`; the durable backup path is recorded in the journal
   before the database transaction starts;
6. mark the journal committed only after configuration and database migration;
7. normalize ownership/modes, refresh trusted command hashes, reload systemd,
   start services, and require the two administrative daemons to be active.

The journal is written atomically and can resume the same target version after
an interrupted package action. Daemons refuse normal work while the journal is
in `prepared`, `config_migrated`, or `database_migrated`, or when its committed
product version differs from the running binary. Maintenance commands remain
available so the package action can finish recovery.

Configuration backups are stored below
`/opt/fic/state/upgrades/<version>-<time>-<pid>/config`. Database backups are
stored below `/opt/fic/state/db-backups`. They are regular `0640` files under a
`root:fic` tree; group members can inspect them but cannot modify them.
Every transaction directory retains its final `manifest`, including the exact
database backup path, so a later reinstall does not erase rollback provenance.

The pre-contract configuration format (`0`) is initialized directly as current
schema `2`. Because no stable release exists, there is intentionally no
configuration migration or compatibility fallback from development schema `1`:
defaults and all active producers/consumers were replaced together. Device DB
migration remains the separately versioned `0 -> 1 -> 2` path, and new
databases are initialized directly at schema `2`.
There is no runtime `CREATE TABLE IF NOT EXISTS` repair of an existing database.
The repository's legacy migration fixture also contains unused `domain_policies`,
`lock_history`, `system_settings`, and `temporary_allowances` tables. The
`0 -> 1` migration preserves the authoritative device tables and removes these
deprecated tables only after the complete legacy database has been backed up;
no current producer or consumer owns their contents.

## Operator commands

These commands are intended for package scripts or a root administrator while
the services are stopped:

```text
fic --version
fic --build-info
fic --maintenance ensure-config
fic --maintenance begin-upgrade
fic --maintenance migrate-config
fic --maintenance check-config
fic-dick --maintenance migrate-db
fic-dick --maintenance check-db
fic --maintenance commit-upgrade
```

`status` responses from both administrative sockets expose the product and
owned schema version. `--version` exposes concise version information;
`--build-info` exposes provenance and all compiled contract versions. The main
daemon also reports its compile-time platform profile.

## Downgrade, rollback, and removal policy

Automatic downgrade is forbidden. `begin-upgrade` compares SemVer with the
last committed product version, while config and DB checks independently reject
schemas newer than the running binary. Installing an older package over newer
state is therefore expected to fail closed.

Rollback means restoring a complete backup set made by the failed/undesired
upgrade and reinstalling the exact previous package set. It is an explicit
operator recovery, not an automatic package-script action: automatically
restoring old data while leaving new binaries installed would create a more
dangerous mixed-version system. Before restoration, services must be stopped;
the config directory and SQLite database must be restored from the same upgrade
transaction, followed by installation of the matching older packages.

Normal package removal disables services and removes package-owned binaries and
integration files, including immutable configuration defaults under
`/opt/fic/share/default-config`. The package manager does not own
`/opt/fic/config/*.conf`: FIC creates and owns these working files, and
maintainer scripts never explicitly delete them. The working database, journal,
logs, and backups are likewise preserved. Purging all persistent state is a
separate administrator operation; scripts do not recursively delete `/opt/fic`.

## Test boundary

`upgrade_contract_tests` covers secure configuration bootstrap, initial
migration, interruption/resume,
idempotent reinstall, reconstruction of a rollback set, downgrade refusal,
newer-schema refusal, fresh database
initialization, and migration of the repository's real pre-contract database.
New packages do not ship that legacy database as a seed: fresh installations
create schema `1` plus the canonical virtual device roots directly. Packaging
scripts are syntax/static checked in CI. A disposable VM is still required for
the full package-manager sequence and service health checks; unit tests do not
pretend to validate systemd or mutate the development host.

This journal covers product configuration and database upgrades. It does not
make multi-file operating-system policy application crash-atomic; that requires
the separate runtime policy transaction journal described in the policy
architecture.

The source/tag gate, explicit package version input, prerelease mapping and
compiled provenance are covered separately by `version_contract_tests`,
`release_contract_tests`, and `build_info_tests`.
