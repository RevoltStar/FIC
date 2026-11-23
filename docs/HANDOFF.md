# Debian 13 D13-3B SSH MFA backend

Branch `main`. D13-3B starts from `d639bffb0c92461d1afc73219fd13893b2e81d25`.

The explicit Debian 13 backend projects the managed block before CAS,
checks the exact two SSH authentication chains and the dedicated PAM
service, and binds PAM and SSH reference digests to the verified
systemd invocation and main PID. It verifies the actual incident PAM
module controls `fic-sshd-mfa`. MFA activation repeats the verified
runtime operation when checking a reference again. The existing FIC
faillock slots compose with `preauth_required` and
`preauth_requisite`; `authsucc` is refused.

The Debian 13 DEBs and eight focused CTests passed
(`build-d13-3b/package-closed.log`). The standalone SSH adapter test
passed with Debian 13 and Debian 12 build profiles. The D13-1 native
lifecycle, D13-2/D13-3A native PAM and SSH regressions, and both native
preauth strategy cases passed. The rootful UNIX and LDAP/SSSD gates on
OpenSSH `1:10.0p1-7+deb13u4` verified cutover, preserved an open
SSH session, exercised both MFA pairs and the incident account gate,
rejected unauthorized input drift, retained MFA after a failed reload
and verified rollback. The final gate logs are `final-local.log` and
`final-sssd.log`.

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
