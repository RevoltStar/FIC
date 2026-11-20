# Debian 13 D13-2 MFA topology

Branch `main`. Starting commit `1973dd406183bab4ac8b3c928c6e2e7cdafe2ba1`.

`PamMfaTopology` renders a disabled `pam-auth-update` Additional profile
and the neutral and mandatory `fic-mfa` slot forms. The read-only
StructuralEffective verifier checks a selected service's effective PAM
graph, the strict password routes, trusted provider and credential
format. It proves that every modeled success includes the appropriate
primary followed by Google TOTP and that a blank local password cannot
succeed. It makes no PAM or credential writes.

The Debian 13 native gate invokes the production verifier and real
`pam_authenticate()` for `login` with local Unix and online TLS LDAP/SSSD.
It covers both factor failures, empty passwords, credential and provider
failures, control transitions, token preservation and the D13-1 guard.
With the tested faillock hooks, bad primary passwords increment the
tally. Wrong OTPs after good passwords are denied without incrementing it.

The Debian 13 DEBs and probe were built natively. The six focused PAM,
packaging and platform CTests passed. The D13-1 policy, ownership and
package-lifecycle regression gate also passed. Logs are under
`/tmp/fic-d13-mfa.O0UrDLT5/` in `debian-verified-build.log`,
`ctest-final.log`, `native-final-gate.log` and `native-d13-1-final.log`.
The native logs point to the exported `build-package-lifecycle/native-*`
evidence. Reproduction is in
[the native gate README](../tests/integration/pam-mfa-d13/README.md).

[The D13-2 contract](pam-mfa-d13.md) records structural, native and
unsupported scopes. Production packages contain no active MFA topology.
D13-3 still owns policy wiring, journal-bound publication, provenance,
recovery and rollback. SSH and graphical client conversations were
outside the native gate.
