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
