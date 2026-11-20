# Debian 13 D13-2 MFA follow-up

Branch `main`. Base `9f10cc4c40ae795fbb556aa9be73e7d48d41744f`.

The D13-2 renderer and canonical `fic-mfa` slot are ready for later
policy wiring. The read-only verifier admits the mixed password route
with `passwd: files sss`, `shadow: files`, and the locked SSSD NSS
password field. Both modules can remain in `group`.

On clean Debian 13, installing libnss-systemd followed by SSSD produced
`files systemd sss` in passwd, shadow and group. The verifier rejects
both passwd orders that combine systemd and sss. UserDB can resolve
qualified names itself and can supply shadow hashes. Lookup order
alone cannot prove that a qualified identity comes from LDAP/SSSD.

The native gate exercises local and LDAP/SSSD logins with the accepted
NSS route. Both unsupported passwd orders are also tested as native
samples, with separate structural rejection. Missing and corrupt TOTP
registrations fail with the same six-digit code that worked before the
change. The gate also checks conversation failure, D13-1 and faillock
composition, and the existing PAM control-flow regressions.

Debian 13 package build, the native gate and six targeted CTests passed. Evidence in
`/tmp/fic-d13-mfa-nss/` includes `stock-nss.log`, `build-ctest.log`
and `native-final.log`. The native log points to exported evidence under
`build-package-lifecycle/`. See the [D13-2 contract](pam-mfa-d13.md)
and [native gate](../tests/integration/pam-mfa-d13/README.md).

D13-3 still owns policy wiring, journal-bound publication, provenance,
recovery and rollback. Native client workflows and UserDB, DynamicUser
and homed authentication were outside the gate.
