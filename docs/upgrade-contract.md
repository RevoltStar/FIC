# FIC product upgrade contract

This document defines the first versioned upgrade boundary. It does not declare
`0.x` builds stable; it makes the mechanics required for a future stable release
explicit and testable.

## Independent versions

| Contract | Current version | Owner | Compatibility rule |
|---|---:|---|---|
| Product | CMake `FIC_PRODUCT_VERSION` | `fic-common/fic-version` | Must be SemVer. Package builders embed the package version in every binary. |
| Administrative IPC | `1` | `fic-common/fic-ipc` | Every request and response contains `api_version`. A mismatch is rejected before routing. |
| Policy configuration | `1` | `fic-core/UpgradeManager` | Every installed module config contains exactly one `_schema_version`. Normal startup accepts only the exact current schema. |
| Device SQLite database | `1` | `fic-device-db` | `PRAGMA application_id=0x46494344` and `PRAGMA user_version=1` identify the database and schema. Normal startup never mutates an old schema. |

The versions are deliberately independent. Changing the product version does
not imply an IPC or storage-schema change. A breaking change increments only
the affected contract and adds an explicit offline migration where applicable.

## Package upgrade sequence

The DEB/RPM lifecycle performs the following fail-closed sequence:

1. stop active `fic`, `fic-device`, and `fic-notify` services from both daemon
   package pre-install actions, before either executable payload is replaced;
2. create/resume `/opt/fic/state/upgrade.journal` for the target product version;
3. back up all policy configs and migrate them offline;
4. create a consistent SQLite backup with the SQLite Backup API, run the
   supported schema migration in one transaction, and run `quick_check` plus
   `foreign_key_check`; the durable backup path is recorded in the journal
   before the database transaction starts;
5. mark the journal committed only after configuration and database migration;
6. normalize ownership/modes, refresh trusted command hashes, reload systemd,
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

The first supported migrations are the pre-contract configuration/DB format
(`0`) to schema `1`. New databases are initialized directly at schema `1`.
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
fic --maintenance begin-upgrade
fic --maintenance migrate-config
fic --maintenance check-config
fic-dick --maintenance migrate-db
fic-dick --maintenance check-db
fic --maintenance commit-upgrade
```

`status` responses from both administrative sockets expose the product and
owned schema version. `--version` additionally exposes the IPC version, and the
main daemon reports its compile-time platform profile.

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
integration files. Config files follow the native `conffile`/`%config` package
manager rules; the working database, journal, logs, and backups are never
explicitly deleted by maintainer scripts. Purging all persistent state is a
separate administrator operation; scripts do not recursively delete `/opt/fic`.

## Test boundary

`upgrade_contract_tests` covers initial migration, interruption/resume,
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
