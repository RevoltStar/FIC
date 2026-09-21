# PAM faillock ownership: permanent hooks and journal-bound slots

This document records the staged PAM ownership model introduced after
`b11a23308c58aa0650870f2cb137bbe45179b0b1`.

## Problem

`pam-auth-update` profile identifiers are selection state, not causal
provenance.  A durable `Prepared` journal record can exist before the native
writer runs.  If an administrator selects a known `fic-*` profile during that
window, rollback must not infer that FIC created that state and delete it.

Therefore:

- `Prepared` is intent, not ownership;
- a reserved profile name is not ownership;
- semantic equality with the requested PAM graph is not ownership;
- rollback may mutate only a concrete artifact carrying an exact FIC ownership
  witness for the journal record.

## Debian/Ubuntu AuthenticationLockout

`pam-auth-update` owns the generated `common-*` files. FIC installs four
permanent integration profiles:

- `fic-faillock-hook-preauth`
- `fic-faillock-hook-authfail`
- `fic-faillock-hook-authsucc`
- `fic-faillock-hook-account`

They include four package conffiles under `/etc/pam.d`:

- `fic-faillock-preauth`
- `fic-faillock-authfail`
- `fic-faillock-authsucc`
- `fic-faillock-account`

The hook selection is infrastructure and is never policy ownership.  Policy
enable/disable mutates only the four slots. Active slots contain a strict
versioned marker with the durable journal mutation id, slot name and faillock
strategy. Neutral slots contain the canonical neutral marker and one
`optional pam_deny.so` rule. Keeping one rule preserves the numeric-jump shape
validated by the Docker probe, while a degenerate stack containing only a FIC
hook fails closed instead of authenticating through `pam_permit`.

Rollback binds the journal record id to the manager. It can neutralize a
crash-partial subset only when every existing active marker has that exact id.
A malformed marker or a different id is a conflict. An unmarked external
`pam_faillock` graph is never removed.

PasswordQuality and PasswordHistory still use the legacy pam-auth-update
inspection backend, but **new profile-selection mutation and destructive
rollback are disabled**. The Docker probe validated faillock hook placement,
not a permanent password-stack ownership contract; Password-Initial /
`use_authtok` composition requires its own proof before those activation
policies can safely mutate topology. An already-effective foreign topology may
still be verified.

Legacy exact, partial and mixed pam-auth-update selections are never treated as
causal ownership merely from their profile names. Debian/Ubuntu package upgrade
is blocked before unpacking the new PAM ownership model when an old FIC
faillock/pwquality/pwhistory profile remains selected **or** an active legacy
PAM journal record still refers to that identifier domain. The administrator
must reconcile it with the installed version first. The guard is repeated
after stopping the old daemon; if that race check refuses the upgrade, services
that were active before preinst are restarted.

## ALT p11

ALT stays on `AltTcbManaged`. A hook-only translation is not semantically
equivalent because native `pam_tcb.so required` success continues into a
following `authfail` hook. The existing controlled transformation of the
native TCB rule is therefore necessary. `authsucc` is also unsafe in the tested
service paths because `pam_nologin.so` can fail after an early tally reset.

## Diagnostic evidence (2026-09-20)

The v2 Docker diagnostic was run on Debian 12, Debian 13, Ubuntu 24.04,
Ubuntu 26.04 and ALT p11.

Debian/Ubuntu results:

- `preauth_requisite`, `preauth_required` and `authsucc`: PASS on all four
  images;
- native numeric-jump semantics: PASS; the generated pam_unix success jump
  changed from `1` to `2` but still landed on `pam_permit.so`;
- the generated `pam_unix` Auth-Initial/Auth transition added
  `try_first_pass` and was classified as a benign generator-owned variant;
- the four hooks survived `pam-auth-update --package`;
- the four hooks survived same-version `libpam-runtime` reinstall;
- the four hooks survived install and remove of the real
  `libpam-pwquality` package.

ALT p11 results:

- package repositories were restricted to `mirror.yandex.ru`;
- both local-only targets are owned by `pam-config` with RPM flags `cn`
  (`%config(noreplace)`);
- direct diagnostic hooks survived `control system-auth local` and same-version
  `pam-config` reinstall;
- hook-only `preauth_requisite` and `preauth_required`: FAIL because successful
  `pam_tcb` does not bypass `authfail`;
- hook-only `authsucc`: FAIL and additionally reaches tally reset before a later
  `pam_nologin` gate;
- a real two-version `pam-config` upgrade test was attempted but remained
  inconclusive because the mirror exposed only one installable version through
  the tested APT-RPM interface.

These are pre-patch architecture diagnostics, not a claim that repository CI
for this patch was run by the diagnostic harness.
