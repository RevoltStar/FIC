# Debian 13 D13-3C SSH MFA

Branch `main`. The production integration follows the first-publication
preflight in `0043d6e3c78b5a22faecf6ad9f1c36726c94f1b7`.

`NET/SshEdit/ssh_mfa_required` is registered on Debian 13 and ships disabled.
`SshMfaPolicy` proves the desired status in the trusted `NET.conf` generation.
Ordinary and periodic apply, Port and verified release share that requirement
and the `release_ssh_mfa` ownership record. The daemon re-proves the persistent
journal and witness against its live records. Adapter receipts supply
runtime evidence only. The selector ships in the Debian 13 DEB.

First activation preflights the projected PAM and SSH configuration, prepares
the journal, publishes the dedicated auth slot and service, then commits the
SSH image and verifies listener activation. Disable proves an explicit
release against the same configuration generation. It verifies SSH with the
ordinary policy blocks preserved, checks for SSH children and foreign PAM
references and removes only the exact owned PAM files. Final acknowledgement
requires durable DISABLE. A clean initial no-effect failure may discard
its intent. Ambiguous effect retains ownership and requires recovery.

Active or unresolved SSH MFA ownership refuses prepare-uninstall before the
irreversible lifecycle fence. D13-3D covers full package-manager integration
for MFA ownership. Prerequisites and current operator behavior are in
[pam-mfa-d13.md](pam-mfa-d13.md). The SSH adapter and rollback contracts
describe the proof boundaries.

Debian 13 build and unit/static evidence is under
`build-d13-3b/d13-3c-complete-{build,adapter}.log`. Native production
results for local UNIX and LDAP/SSSD are in `d13-3c-port-{local,sssd}.log`.
The fixtures exercised an actual port change to 2222 and independent
release in both directions. The local run also verified periodic apply.
PAM observer and faillock evidence is in `d13-3c-pam-preauth-*.log` and the
native directories named there. Package lifecycle end-to-end and the
distro matrix are outside this gate.
