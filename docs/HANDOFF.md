# Debian 13 D13-3A MFA core

Branch `main`. D13-3A starts from `4df4f4cdedf36d49f08d40da04809021729ade4c`.

The three canonical PAM forms are `InteractiveTwoPrompt` (existing
`fic-mfa` hook), `SingleInputForwardPass` (dedicated `xrdp-sesman`
auth substack), and `SshStagedAuthentication` (dedicated
`fic-sshd-mfa` auth substack). The Debian 13 build produces
`fic/pam_fic_ssh_stage.so`. The module consumes evidence from the PAM
handle and accepts only an explicitly empty value, one verified password
record, or one Ed25519 record. The SSH verifier proves individual PAM
stages conditional on those inputs. Runtime/chain proof is D13-3B.

The shared D13-2 identity name guard now ignores `PAM_IGNORE`
during setcred. Google TOTP still fails on any non-success result.
The verifier reuses the D13-2 TOTP registration, trusted PAM source
and NSS/SSSD proofs. The supported mixed route remains
`passwd: files sss` with `shadow: files`; both modules can remain in
`group`. Additional authentication routes require separate proof.

Debian 13 DEB build, eight targeted CTests, the D13-1 native lifecycle,
the D13-2 PAM/NSS regression and a real TTY login passed. Native
forward-pass exercises the full PAM lifecycle with UNIX and LDAP/SSSD.
OpenSSH `1:10.0p1-7+deb13u4` opens and closes real UNIX and LDAP/SSSD
sessions for both chains, including retries and fail-closed injection
for evidence publication, removal and setcred. See the
[MFA contract](pam-mfa-d13.md) and
[native gate](../tests/integration/pam-mfa-d13/README.md).
Logs are in `/tmp/fic-d13-3a/`: `ctest-final.log`, `d13-1.log`,
`tty.log` and `native-final.log`. The latter points to exported
`result.json`, `commands.log`, `pam.log` and `ssh-pam.log`.

D13-3B requires exact effective SSH routing and verified activation
receipts, guards in regular and periodic apply and rollback, and native
switch, reload-failure and drift coverage. Production PAM attachment,
policy registration, MutationJournal ownership, recovery, release and
package lifecycle remain D13-3C/D. The selector is copied into the
native test container only. A new LightDM GTK or xrdp client gate was
outside this run.
