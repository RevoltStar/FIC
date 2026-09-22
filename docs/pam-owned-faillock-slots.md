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

## Package lifecycle invariants (removal and reinstallation)

> Package removal first stops all FIC PAM writers and only then detaches
> permanent hooks; package installation/reinstallation never attaches
> permanent hooks until existing FIC slot state is proven canonical-neutral or
> journal-bound owned state.
>
> Hook detach requires positive proof that every FIC PAM writer is inactive;
> timeout is a package-removal failure, not permission to continue.
>
> After a PAM hook detach begins, no FIC writer may be restarted until the
> permanent hook infrastructure is either proven untouched or restored and
> proven attached. The prerm performs that recovery itself while the writers
> are still stopped; `postinst abort-remove` re-proves the state with a
> read-only check before it restarts any writer.
>
> If `prerm remove` fails before PAM hook detach because a FIC PAM writer
> remains active, dpkg's `postinst abort-remove` path restores
> package-managed service enablement/runtime state without touching PAM
> hooks, PAM managed slots, mutation journal, or journal witness.
>
> `abort-remove` is not a configure path.
>
> Active slot provenance is accepted only from a read-only witness-aware
> persistent journal state that the normal daemon lifecycle would also
> accept.
>
> Journal ownership proof includes exact mutation id, active status, backend,
> capability, topology, activation domain, policy identity, resource identity
> and physical target strategy.

### Removal (`prerm remove`)

> Hook detach requires positive proof that every FIC PAM writer is inactive;
> timeout is a package-removal failure, not permission to continue.

`prerm` stops `fic.service`, `fic-device.service` and `fic-notify.service`
(`systemctl disable --now`, best-effort) and waits (bounded, 10 × 1 s per
unit) until they are inactive **before** it runs
`pam-auth-update --package --remove ...`. After the bounded wait the prerm
performs a final `systemctl is-active` proof per unit with no `|| true`:
if any of the three units is **still active**, the prerm prints a diagnostic
naming the unit and exits non-zero. In that case no
`pam-auth-update --remove` is executed and the permanent hooks stay attached;
the package removal fails. A live daemon could otherwise perform PAM
mutations or re-activate the hook infrastructure concurrently with the
profile detach. Upgrade semantics are unchanged: this ordering applies only
to the `remove` action.

### Detach failure recovery (Phase B, `prerm remove`)

`pam-auth-update --package --remove ...` is a failure-guarded command. If it
exits non-zero, the prerm must contain the damage right there: this is the
only window in which every FIC PAM writer is proven stopped, and dpkg gives
`postinst abort-remove` no information about why the removal failed.

The prerm recovery:

1. re-enables **only** the four permanent hook profiles
   (`pam-auth-update --enable fic-faillock-hook-preauth
   fic-faillock-hook-authfail fic-faillock-hook-authsucc
   fic-faillock-hook-account`). The legacy policy-owned selector profiles
   are deliberately **not** re-enabled — policy state lives in the managed
   `/etc/pam.d/fic-faillock-*` slots and the installed package guarantees
   only the permanent hooks. A single `--enable` is sufficient: it
   re-selects the profiles and regenerates the `common-*` stacks;
2. proves the restoration through the read-only standard-state proof
   (`fic_prove_permanent_hooks_attached`, see below) and prints an explicit
   diagnostic;
3. always exits non-zero — the removal failed.

If the recovery `--enable` fails but the proof still passes, the prerm
reports that the hooks are proven still attached (the detach failed before
any state change). If the recovery enable fails **and** the proof fails
(for example after a partial detach), the prerm reports explicitly that the
permanent hook state is **not proven restored**; the partial state is left
untouched for manual administrator recovery. The prerm never touches managed
slots, the mutation journal or its witness, and never runs any FIC command.

### The standard-state permanent hook proof

`fic_prove_permanent_hooks_attached()` is shared by the generated `prerm`
(recovery proof) and `postinst` (abort-remove guard) and is strictly
read-only:

- selected profile identity is proven by an exact full-line
  `Module: <profile>` entry in the correct pam-auth-update facility state
  file (`/var/lib/pam/auth` for `fic-faillock-hook-preauth`,
  `fic-faillock-hook-authfail` and `fic-faillock-hook-authsucc`;
  `/var/lib/pam/account` for `fic-faillock-hook-account`). Entries in
  another facility file, entries embedded in other lines and profile-name
  prefix/suffix collisions do not prove selection;
- physical attachment is proven by an active, correctly facilitated, exact
  include rule in the generated `common-*` stack (`auth include <target>`
  anchored to the full rule in `common-auth` for the
  `fic-faillock-preauth`, `fic-faillock-authfail` and
  `fic-faillock-authsucc` hook targets; `account include
  fic-faillock-account` in `common-account`). Commented lines, wrong
  facility, non-include control words, target prefix/suffix names and
  unrelated text mentions do not prove attachment.

It never invokes `pam-auth-update` and never mutates PAM state, managed
slots, the journal or the witness.

### Failed removal recovery (`postinst abort-remove`)

When `prerm remove` aborts (Phase A: a FIC PAM writer refused to stop before
any PAM operation; Phase B: the PAM detach failed and the prerm recovered as
described above), dpkg invokes `postinst abort-remove` — the same way in
both phases, with no failure reason in the argument. This is a dedicated
early recovery path, handled before any configure-specific logic:

- **Guard**: before any action, the read-only
  `fic_prove_permanent_hooks_attached` check must pass. Normally it only
  re-confirms what the prerm already proved (Phase A: hooks untouched;
  Phase B recovery success: hooks restored). If the proof fails — the only
  case is a Phase B recovery that could not be proven — abort-remove
  **refuses to restart any FIC writer**, prints a diagnostic naming the
  unproven PAM state and exits non-zero, leaving the package in the dpkg
  error state (Half-Configured) for manual administrator recovery. This is
  the honest outcome: restarting writers over a partially detached PAM
  graph is exactly what the lifecycle invariant forbids. No marker file is
  needed: the proof is stateless and covers even a crash between the prerm
  and abort-remove.
- **Does** (only after the guard passes): `systemctl daemon-reload`, then
  restores package-owned enablement (`systemctl enable` for `fic.service`,
  `fic-device.service`, `fic-notify.service` and the optional
  `fic_get_device_udev_info.service` helper) and runtime availability
  (`systemctl start` for `fic.service`, `fic-device.service`,
  `fic-notify.service`). `systemctl start` on an already-active unit is
  idempotent, so the live writer that caused the removal failure is simply
  left running.
- **Critical units**: `fic.service`, `fic-device.service` and
  `fic-notify.service`. Normal `postinst configure` treats
  `fic-notify.service` as mandatory (`systemctl enable --now` under
  `set -e`), so the abort-remove recovery uses the same strict model:
  strict `enable`, strict `start` and a final `systemctl is-active` proof
  per unit; a failure names the unit and exits non-zero. The udev helper
  keeps its non-blocking, best-effort semantics.
- **Never does**: run any `pam-auth-update` call, neutralize/rewrite/
  repair/recreate managed slots, rollback/discard/mark or migrate the
  mutation journal or its witness, run `ensure-config`, `check-config`,
  trust sync or `validate-pam-slots-before-attach` as a form of recovery,
  and never `systemctl stop`/`restart` a FIC writer.

The exit status of the failed removal itself stays non-zero. After a
successful abort-remove recovery dpkg reports the package in the
**Installed** state (checked semantically as the third status field, e.g.
`dpkg-query -W -f='${db:Status-Status}\n'`; the first-field wording —
`install`/`deinstall` — varies between dpkg versions after an aborted
removal), with the services, permanent hooks, slots and journal provenance
exactly as they were before the removal attempt. After a guard refusal the
package is left Half-Configured: that is the explicit, visible signal that
the PAM recovery failed and manual action is required.

### Installation / reinstallation (`postinst configure`)

`postinst configure` validates the existing `/etc/pam.d/fic-faillock-*`
slots through the read-only maintenance command

```sh
/opt/fic/bin/fic --maintenance validate-pam-slots-before-attach
```

**before** the first action that could make a FIC slot effective in the live
PAM graph (`pam-auth-update --package`, then
`pam-auth-update --enable fic-faillock-hook-*`). The validator reuses the
daemon managed-slot classification and answers strictly read-only: it never
rewrites slots, never creates or mutates the mutation journal, never runs
`pam-auth-update`, never rolls back or neutralizes state.

Attach is allowed only in two cases:

1. **Canonical neutral state** — all four slots carry the exact canonical
   neutral content. The journal is not consulted at all (neutral slots do
   not need journal provenance), so a virgin system without any journal
   state passes here.
2. **Active FIC-owned state** — the slots form a complete consistent strategy
   topology with matching strict markers, and the mutation journal carries an
   active record (`Prepared`, `Applied` or `RollbackFailed`; `RolledBack`
   fails) that:
   - matches the slot mutation id exactly;
   - carries the exact policy identity `IDENTITY_ACCESS` / `PAM` /
     `enable_authentication_lockout` and the resource
     `capability/enable_authentication_lockout`;
   - belongs to the PAM backend with an `enable_authentication_lockout`
     ownership payload;
   - proves the exact managed-slot activation domain of the current platform
     profile (no semantic equality, no profile-name inference);
   - records a `target_strategy` equal to the exact physical strategy the
     active slots carry (`status.activeStrategy` from the daemon slot
     inspection; e.g. physical `preauth_required` with journal
     `target_strategy=authsucc` is rejected).

### Journal provenance state table (read-only, witness-aware)

> Active slot provenance is accepted only from a read-only witness-aware
> persistent journal state that the normal daemon lifecycle would also
> accept.

The pre-attach validator never loads the journal through the raw legacy
primitive. `MutationJournal::validatePersistentStateReadOnly()` evaluates the
same persistent (journal, witness) state table as the daemon's
`initializeOrLoad()`, with the identical security checks, but performs **no**
filesystem mutation: no bootstrap, no witness creation, no migration, no
repair. The exact table:

| journal `mutation-journal.json` | witness `.initialized`        | verdict for active slots                                                                                     |
| ------------------------------- | ----------------------------- | ------------------------------------------------------------------------------------------------------------ |
| missing                         | missing (virgin system)       | **FAIL** — read-only validation cannot bootstrap a journal                                                     |
| missing                         | valid                         | **FAIL CLOSED** — provenance loss (same as the daemon runtime)                                                 |
| missing                         | invalid/malformed             | **FAIL CLOSED** — persistent-state anomaly                                                                     |
| valid                           | missing                       | **FAIL CLOSED** — pending migration; the runtime accepts this state only by durably *creating* a witness, which the validator must never do. Complete the migration through the normal daemon lifecycle (start `fic` once, letting `initializeOrLoad()` finish the migration) and re-run configuration |
| valid                           | invalid/malformed             | **FAIL CLOSED** — persistent-state anomaly; no witness repair                                                  |
| valid                           | valid                         | journal is strictly loaded and may be used as the ownership proof (record lookup and identity checks above)    |

After a PASS or a FAIL the validator leaves the journal, the witness and all
slot files byte-for-byte unchanged; missing files stay missing (regression
tested).

Everything else fails closed **before** any `pam-auth-update` invocation and
before the daemon is started: active slots with a missing journal, a wrong or
mixed mutation id, a non-active record, a foreign policy/resource identity,
a foreign capability/domain/backend payload, a mismatched physical strategy,
malformed markers, modified marker bodies, partial strategies or
missing slots. The package never repairs, neutralizes or deletes such state;
the administrator must resolve it manually.

### Reinstall with preserved conffiles

The four `/etc/pam.d/fic-faillock-*` files are conffiles and survive
`apt remove fic` followed by `apt install fic`. On reinstall:

- neutral slots (fresh install or post-rollback state) pass validation and
  the hooks are attached as usual;
- active slots left behind by a working `remove`-before-reinstall cycle are
  proven against the preserved journal in `/opt/fic` and attach only when the
  journal record matches exactly;
- any preserved slot state that cannot be proven (missing journal record,
  drifted or malformed markers, partial topology) aborts package
  configuration with a diagnostic instead of silently attaching unproven PAM
  content. This is intentional fail-closed behavior: the daemon never gets a
  chance to run, and the live PAM graph is never extended with the
  permanent hooks.


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
