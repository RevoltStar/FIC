# FIC version and schema contract

FIC has no published stable release yet. The embedded development version is
`0.0.0-alpha`; the first planned stable release is `0.1.0`.

Product, IPC, policy configuration and device database versions are independent:

| Contract | Current version | Source |
| --- | ---: | --- |
| Product | `0.0.0-alpha` | `fic-common/fic-version` |
| Administrative IPC | `1` | `fic-common/fic-version` |
| Policy configuration | `1` | `ConfigSchemaManager` |
| Device SQLite database | `1` | `fic-device-db` |

Product releases continue to use SemVer and the release validation documented
in [`release-process.md`](release-process.md). Schema numbers change only when
their own contracts change.

## First-public-release state policy

Schema 1 is the first and only supported policy configuration and device DB
schema. There are no supported earlier schemas and no automatic import or
conversion of development state.

This also applies to the development-only OSS policy key renamed from
`disable_videodisplay_when_locked` to
`disable_kde_lock_screen_media_controls`: an existing development `OSS.conf`
must be archived/removed and recreated from the packaged defaults. The rename
does not change `CONFIG_SCHEMA_VERSION` and does not introduce a migration for
pre-release state.

A fresh package installation:

1. copies an immutable default only when the corresponding working config is
   absent;
2. creates an absent or empty device database directly with the complete schema
   1 layout, `application_id`, `user_version`, indexes, triggers and baseline
   rows;
3. strictly validates every config and the device database;
4. synchronizes trusted command hashes and starts the daemons only after those
   checks succeed.

The maintenance commands used by this bootstrap are:

```bash
fic --maintenance ensure-config
fic-dick --maintenance initialize-db
fic --maintenance check-config
fic-dick --maintenance check-db
```

`ensure-config` never overwrites an existing working configuration. Existing
configuration files must contain exactly one `_schema_version=1`. A missing,
invalid, lower or future schema version is rejected.

`initialize-db` creates schema 1 only when the database is absent or empty. A
non-empty database is accepted only when its `application_id`, `user_version=1`,
table layout, indexes, triggers, baseline rows and SQLite integrity checks all
match the current contract. An unversioned database, another application ID,
another schema version or an incompatible layout is rejected without mutation.

Package lifecycle scripts do not delete incompatible state and do not remove
`/opt/fic`. An administrator must explicitly archive or remove development state
before installing the first public version if strict validation rejects it.

## Runtime startup

Normal `fic` and `fic-dick` startup verifies configuration schema 1 before doing
work. `fic-dick` also initializes an absent database through the same schema 1
bootstrap used by installation and rejects any incompatible non-empty database.

There is no product upgrade journal, transaction manifest, migration backup
directory or downgrade state machine in the first-public-release contract.
Runtime policy edits retain their own atomic/transactional behavior; that is a
separate correctness mechanism and not old-state compatibility.
