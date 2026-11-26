# Debian 13 D13-3D SSH MFA package lifecycle

## Current base

`main`, based on `9184d203855c5c4b06829d71d4fdaffc150ab2c6`.

## Current task

Integrate active SSH MFA into compatible DEB upgrade, standard remove, and
reinstall. The [package lifecycle](package-lifecycle.md#debian-13-ssh-mfa)
specifies the operator contract. The [validation instructions](package-lifecycle-validation.md#debian-13-ssh-mfa-package-lifecycle)
identify the native cases.

## Accepted invariants

- The daemon checks the durable UNINSTALLING fence and journal/witness before
  rollback-all. Ordinary and periodic apply remain unavailable under that fence.
- MFA release preserves the ordinary SSH blocks and requires a verified active
  listener, drained authentication/session children and safe PAM detachment.
  Uninstall commits the typed release with all saved selections intact.
  Administrative disable still requires durable DISABLE and registry reload.
- MFA precedes other SSH releases, grouped PAM, and the SSSD releases when
  the journaled MFA contract consumes SSSD. Port is last among SSH owners.
  Ordinary SSH release rechecks the fence, trusted NET.conf generation, and
  journal plus physical MFA absence. Normal Recommended dependencies are intact.
- The package helper's existing writer and PAM reference proofs apply to every
  removal mode. TOTP registrations belong to the administrator.

## Changed areas

Daemon admission, rollback-all resource graph, the existing SSH MFA coordinator,
typed journal finalization, unrecorded-resource inspection, lifecycle docs and
targeted unit/native fixtures.

## Validation

- Debian 13 DEB `0.1.3` built and tested with the real D13-3C `0.1.2` packages.
- `d13-3d-native-local.log` and `d13-3d-native-sssd.log` under
  `build-d13-3b` cover upgrade, blocked removals, standard remove, reinstall
  and purge. The LDAP/SSSD driver records the successful steps in the native
  evidence directory's `commands.log`.
- `d13-3d-native-minimal.log` covers install/remove without SSH and mandatory
  PAM reference refusal in both emergency modes.
- Eleven targeted CTests and the standalone SSH adapter CTest passed.
  `d13-3d-ctest-final.log` and `d13-3d-adapter.log` contain the results.
- `d13-3d-pam-required.log` and `d13-3d-pam-requisite.log` cover both
  faillock strategies for UNIX and LDAP/SSSD. `d13-3d-ssh-regression-final.log`
  covers both MFA routes, Port and scalar ownership, periodic apply, restart
  and administrative disable. `d13-3d-incident-regression.log` covers the
  incident gate on both routes and refusal after a failed SSH reload.

## Remaining limits

An active MFA owner requires a supported running `ssh.service` with drained
sessions. A retained `ssh_released` phase can retry terminal persistence after
a fresh runtime and physical proof. Unknown publication and partly detached PAM
can require manual recovery. The scope is Debian 13 SSH only. Faults at the
terminal journal persistence boundary were exercised in unit tests. The native
package gate did not interrupt dpkg during upgrade or force a failure after SSH
publication. The multi-distribution matrix was outside this gate.

## CMake test profile regression

`ssh_mfa_dependency_tests` links the existing Debian 12/13
`sddm_test_profile_*` libraries and uses their shared factory declarations.
Each test library owns its factory rename. The source-wide definitions added
in `9184d203` had also reached the SDDM consumers, causing duplicate macro
definitions and undefined factory references in CI run `45771531034`.
The test still exercises the real SSH classes and both production profiles.

`platform_profile_tests` now checks the exact Debian 13 incident PAM service
list including `fic-sshd-mfa`. A clean Debian 13 configuration built `fic` and
all six profile-library consumers in one directory. All six CTests passed.
The compile database and `nm -C` confirmed isolated test factory names and
the original production factory. Logs are under `build-profile-link-fix/`.

## Hardware inventory packaging check

The isolated DEB generator receives `FIC_PACKAGING_TARGET_PLATFORM` explicitly
for Debian 12 and Debian 13. Both fixtures build a DEB, verify the selected
postinst branch and run the existing startup assertions. Both DEB cases and
the RPM case passed with the variable unset and with an unrelated external
value. The focused CTest passed in `build-d13-empty-password`.

## ALT p11 supplementary groups

Implemented on `main` from base `d5039bf9`. ALT p11 enables
`user_default_supplementary_groups` via `ShadowUseraddDefaults` and wires
`alt_ldap_users_default_groups` and `alt_role_groups` into normal daemon apply
and rollback. The two new policies default to DISABLE. The accepted role
layout replaces `.role` with `.fic` and publishes a relative link at the
original path. Ownership of an exchanged pair uses journaled inode identities.

`shadow-utils 4.17.4-alt4` passed 119 checks in Docker with active role NSS.
`libnss-role 0.5.6-alt4` passed nested inheritance, the exact NAME_MAX case,
empty rules, new files, conflicts, crash recovery, rollback and reinstall of
`alterator-roles-common 0.55-alt1`. The stock `alterator-ldap-users 0.8.6-alt3`
passed local account creation for nonempty/empty lists, absent RPM, restart
recovery and rollback. Logs are in `build-user-creation-native/alt-p11/`.
The native USER_CREATION regressions passed on Debian 12/13 and Ubuntu
24.04/26.04 with cached drivers. The ALT daemon and three focused unit targets
built. The unit binaries passed as an unprivileged user in the ALT container.
Real FIC RPM `0.1.1` passed CLI configuration, daemon periodic discovery of
a new role file, independent release during a link-ownership conflict, and
RPM erase retry with all resources restored and selected values retained.
Evidence: `build-package-lifecycle/native-fic-alt-groups-lifecycle:p11-20261126T113823Z-779361/`.

**External Alterator defect.** Separate Docker runs used a real loopback
`openldap-servers 2.6.13-alt1`, `alterator-ldap-users 0.8.6-alt3`,
`ldap-user-tools 0.9.5-alt1` and `grep 3.11.0.20.dd8f-alt1`.

- Stock LDAP: `rpm -V` verified the Alterator package before apply. The
  account was created, but the backend treated the `egrep` warning captured
  from `ldap-useradd` as an error and skipped default groups. This reproduced
  with the stock assignment and with both nonempty and empty assignments
  applied by FIC.
  Evidence: `alt-groups-ldap-probe-final.log`.
- Diagnostic LDAP: only the username validation call in
  `/usr/sbin/ldap-useradd` was switched from `egrep` to `grep -E` inside
  the disposable container. Both requested groups gained the first LDAP
  user. With `default_groups=""`, the second LDAP user was created without
  those memberships. Rollback restored the exact original Alterator backend.
  Evidence: `alt-groups-ldap-diagnostic-final.log`.
- The stock local route passed for nonempty and empty lists. Kerberos and AD
  were not tested. FIC manages the assignment without detecting or restricting
  the Alterator mode. The diagnostic change is outside FIC production code.

### P1/P2 follow-up

Base `30d3b692`. Exclusive apply for `/etc/role` repairs trusted drift under
CAS and retains the original snapshot. A drifted pre-publication snapshot
has `before_owned=false`, so Prepared recovery cannot use it as rollback
authority. Older records retain their previous interpretation. Rollback
still checks the last owned state. The staging window for `.role` links
remains unchanged.

P2 was reproduced on the base revision with a real RPM reinstall of
`alterator-ldap-users 0.8.6-alt3`: the inode changed, stock defaults returned,
and both apply and rollback then refused. Only on ownership conflict, FIC
now resolves the trusted package query executable, checks exact file ownership
and the RPM database digest against the captured bytes, and rechecks the
snapshot. A proven stock file allows no-write release or a new journal cycle
with the stock assignment as its baseline. A failed proof retains the conflict.

Docker native checks passed with `shadow-utils 4.17.4-alt4`,
`libnss-role 0.5.6-alt4`, `alterator-roles-common 0.55-alt1` and
`alterator-ldap-users 0.8.6-alt3`. They cover NSS drift repair, strict rollback,
missing original files, RPM reinstallation, missing or mismatched RPM proof,
and process interruption between journal cycles and around publication.
The old journal cycle in the reinstall test starts from a different assignment
to prove that rollback uses the new package baseline. No second official p11
RPM was available from the checked archive paths, so a version-to-version
upgrade was not tested. Evidence: `p2-baseline.log`, `p1-p2-native.log` and
`p1-p2-useradd.log` (119 checks) under `build-user-creation-native/alt-p11/`.
The ALT build and the profile, journal and rollback unit binaries passed.
The real FIC RPM `0.1.1` lifecycle gate passed periodic drift repair,
independent rollback during a role-link conflict, and erase retry.
Evidence: `build-package-lifecycle/native-fic-alt-groups-lifecycle:p11-20261126T121902Z-878060/`.
