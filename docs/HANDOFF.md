# Debian 13 empty-password login policy

* Branch main. D13-1 base `0e4d014a`. The policy is Debian 13 only and
  defaults to DISABLE with a fixed value ENABLE.
* Debian packaging attaches `fic-empty-password-hook` as an Additional
  substack. The daemon changes only the journal-bound
  `/etc/pam.d/fic-empty-password` slot using the existing PAM transaction
  primitives. The strict `pam_unix use_first_pass` check is scoped to
  local accounts; the official non-local SSSD route skips it.
* Apply verifies the effective graph, selected hook, trusted modules and
  the physical witness. An already strict foreign graph can be observed
  without writing. Policy release does not require a usable provider or
  attachment. Package detach first requires the canonical neutral slot
  and then verifies that no live references remain.
* Contract: `docs/rollback.md`. Targeted gate:
  `tests/integration/pam-empty-password/README.md`.

## Validation

* Debian 13 native PAM preflight with libpam 1.7.0-5 and libpam-sss
  2.10.1-2+b1. Verified stock nullok, selected sss, nullresetok and
  preservation of local modifications by pam-auth-update.
* Rebuilt production DEBs and passed fresh install, apply and repeated
  apply, profile regeneration, missing attachment rejection, explicit
  disable and repeated disable, observation-only, faillock composition,
  same-version reinstall with stable ID, bulk release and dpkg remove.
  Actual PAM returned 0 for valid nonempty and 7 for blank, wrong and
  locked. Real loopback LDAP/SSSD returned 0/7 for correct/wrong passwords
  of a user absent from local shadow.
* The native ownership fixture passed before/after Prepared recovery,
  post-rename compensation in both directions, CAS conflict, missing
  and wrong-ID witness, orphan refusal and release with provider removed.
* Ten selected CTests passed inside Debian 13. The separate
  `mutation_journal_tests` passed inside the same Debian 13 image as an
  unprivileged user. Permission-denial fixtures fail as container root
  because root can write the directories those tests chmod.
* Final logs: `/tmp/fic-d13-1.fDnpFvhL/native-checked-build.log`,
  `/tmp/fic-d13-1.fDnpFvhL/native-package-checked.log`, and the native
  evidence directory printed on the first line of the latter.
* No host PAM, real desktop/SSH login, AD/IPA, other distribution or
  full CI run. Unsupported manual graphs and colliding local/domain
  identities remain outside the declared scope.
