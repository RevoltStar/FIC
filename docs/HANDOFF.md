# FIC handoff

## Current base

* Branch `main`; parent commit `90712a50c20fc6a0ac62e8515605130ccd355746`.

## Current task

* Close two P1 package lifecycle flaws in recovery configuration provenance and Debian incident gate removal.

## Accepted architecture / invariants

* `/opt/fic/config` and `/opt/fic/config/GLOBAL.conf` are recovery authority. Generic package hooks do not repair their ownership or mode, including through symlink or hardlink aliases. Other ordinary config files keep the existing normalization behavior, except multiply linked files are conservatively skipped.
* `ensure-config-first-install` creates a missing config directory and default `GLOBAL.conf` only when the main package sees a virgin first install with both config directory and incident state absent. Normal `ensure-config` never creates missing recovery authority or repairs existing metadata. Missing recovery authority on upgrade fails package configuration; unsafe existing metadata remains fail-closed for fic-group recovery.
* Debian removal proves FIC writers stopped, releases provider and C2 password domains, removes other PAM profiles, then proves the incident gate effective and detaches `fic-incident-access` as the last fail-closed security boundary. Failed or partial detach triggers narrow gate compensation and effective-topology proof; unproven restoration is CRITICAL and removal fails. No semantic release follows proven gate detach.
* Trusted local-root pre-IPC recovery uses only the console `login` PAM service with local context. Graphical root recovery is out of scope. PAM denial remains a generic message; differentiated UX is deferred.
* Production registry fail-closed behavior, daemon readiness, fixed production PAM IPC socket, two-second timeout and lockstatus state machine remain unchanged.

## Completed

* Excluded recovery authority from Debian and RPM generic normalization, auxiliary hook directory creation, and package directory ownership; split first-install config bootstrap from normal ensure-config.
* Reordered Debian prerm and extended package/script and schema regression tests, including unsafe metadata, alias paths and gate failure fixtures.

## Changed areas

* `fic-common/fic-core` config schema manager, `fic` maintenance dispatch and install rule, Debian/RPM package builders, schema and packaging tests, related CI static checks.

## Validation

* RED-before: baseline package chmod changed fixture `/opt/fic/config` 0777 to 2750 and `GLOBAL.conf` 0666 to 0640 in both Debian and RPM builders.
* Fresh Debian 12 builder: full configure/build passed; `ctest -N` listed 132 tests; root CTest excluding `mutation_journal_tests` passed 131/131; that test passed separately under UID 1000.
* Root-only owner/group fixture and Debian/ALT packaging checks passed. Staged CMake install component `fic` contains no `/opt/fic/config` directory. Shell syntax and `git diff --check` passed.

## Remaining

* Real DEB/RPM package install, upgrade and erase were not run. Host PAM topology and runtime policy state were not modified. After commit, run `git show --check` and confirm a clean working tree.
