# Debian 13 D13-3B SSH MFA faillock follow-up

Branch `main`. The follow-up starts from `edab51dffc83ab6a38c58028fb2cafdfd1fea275`.

The explicit Debian 13 backend projects the managed block before CAS,
checks the exact two SSH authentication chains and the dedicated PAM
service, and binds PAM and SSH reference digests to the verified
systemd invocation and main PID. It verifies the actual incident PAM
module controls `fic-sshd-mfa`. MFA activation repeats the verified
runtime operation when checking a reference again. The existing FIC
faillock slots compose with `preauth_required` and
`preauth_requisite`. Both SSH stages must now pass a strict preauth
check. The OTP stage terminates within its substack and has a fail-closed
barrier before the password branch. Password failures use the owned
authfail slot and the existing account phase keeps tally reset after
completed authentication. `authsucc` remains unsupported.

The Debian 13 DEBs and six focused CTests passed in
`faillock-guard-build.log`. The standalone SSH adapter CTest passed
in `faillock-guard-ssh.log`. The follow-up native gates use OpenSSH
`1:10.0p1-7+deb13u4`. The `faillock-guard-preauth-*.log` cases exercise
UNIX and LDAP/SSSD for both strategies, all tally assertions, the
preauth I/O error, invalid selector evidence and the incident account
denial. The `faillock-guard-verified-*.log` cases exercise cutover and
rollback with the verified listener. The D13-2/D13-3A PAM and SSH
regression matrix is in `faillock-guard-regression.log`.

Evidence is under `build-d13-3b/` and the reported directories under
`build-package-lifecycle/`. See the [MFA contract](pam-mfa-d13.md),
[SSH adapter](ssh-verified-activation-adapter.md), and
[native gate](../tests/integration/pam-mfa-d13/README.md).

The independent regular and periodic apply, rollback and release
callers still need a single authorized source of the mandatory
contract. A process-local activation receipt and the current disk
configuration cannot supply that authority after a daemon restart or
drift. Production policy registration, PAM artifact publication,
MutationJournal ownership, recovery and package lifecycle remain
outside this backend.
