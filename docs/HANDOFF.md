# Debian 13 D13-3C SSH MFA

Branch `main`. Base `f858cf843cdf6f53dc0ecda6a2124e1dc811c92c`.
D13-3C is in progress.

The SSH adapter can validate a first-activation plan before either PAM file
exists. It projects the canonical `fic-sshd-mfa` and `fic-mfa-ssh-auth` bytes
into the authorized input graph, including the protected preflight snapshot.
Existing targets are a conflict. Reference capture and Port planning accept an
explicit `SshMfaReference` and check its authorized PAM inputs alongside the
SSH sources. The Debian 13 FIC package stages `pam_fic_ssh_stage.so`.

The production entry points are `Ssh::apply()` for ordinary and periodic
apply, `SshPortTransaction` for the multi-file Port graph, and the verified
release path through `RollbackExecutor` and `SshRollback`. The latter is
also used by the disable flow before the DISABLE setting is saved.

The next change needs to register `NET/SshEdit/ssh_mfa_required` and bind
those entry points to one trusted `NET.conf` generation and durable
MutationJournal ownership. The adapter snapshot and activation receipt
supply input and runtime evidence only. They cannot supply desired policy
intent or prove ownership. Persistent publication needs staged PAM creation
ahead of SSH CAS and activation. Explicit MFA release must verify SSH
activation without the dedicated service, then prove PAM detach safe before
removing the exact owned files. Ambiguous effect or ownership must retain
journal evidence and report recovery required.

Debian 13 DEBs, the topology, stage selector, incident PAM gate and verified
SSH adapter CTest targets passed. The SSH and periodic apply static checks
passed. The native adapter cutover and rollback passed with both local UNIX
and LDAP/SSSD accounts. Both fixtures covered pre-publication proof, a
modified candidate, a byte-identical foreign slot, and reference capture
and Port planning with a pinned MFA contract. Evidence is under
`build-d13-3b/d13-3c-reviewed-*.log` and the native directories named there.
See the [MFA contract](pam-mfa-d13.md) and
[SSH adapter](ssh-verified-activation-adapter.md). Policy lifecycle native
coverage, fault injection across publication stages and uninstall admission
for MFA ownership remain open.
