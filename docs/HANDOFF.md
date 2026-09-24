# FIC: передача контекста

## Current base

- Ветка `main`. Baseline: `6cf4fb71c76efa60081c879f8b07a5a434a2fbbd`
  ("Приступаем к шагу Step5B") + `ea3e2145614c9be6d60b14d2a4e338e22f6c9e85`
  ("Follow-up к Step5B").

## Current task

- Step 5B (PAM PasswordQuality/PasswordHistory package/bootstrap
  infrastructure) — ЗАВЕРШЁН (uncommitted working tree).
- Step 5C — следующий этап: actual `pam-auth-update` attach lifecycle,
  resulting-state proof, partial-failure compensation, remove/reinstall
  handling.

## Ownership boundary (accepted, core Step 5B invariant)

```text
package owns infrastructure/existence  (hook profiles + slot conffiles)
runtime policy + journal own managed state
pam-auth-update owns generated common-* files
```

Bootstrap/package НЕ является владельцем текущего Active/Neutral policy
state и никогда его не перезаписывает.

## Step 5B architecture / invariants

- Package payload:
  - `/usr/share/pam-configs/fic-password-quality-hook` — Priority 1024,
    `Password-Type: Primary`, Password и Password-Initial включают
    `fic-password-quality`.
  - `/usr/share/pam-configs/fic-password-history-hook` — Priority 1023,
    `Password-Type: Primary`, Password включает `fic-password-history`,
    Password-Initial включает `fic-password-history-initial`.
  - Оба профиля `Default: no`; profile IDs/priorities/includes — immutable
    package infrastructure; daemon/runtime их никогда не редактирует.
  - Три slot paths (`/etc/pam.d/fic-password-quality`,
    `fic-password-history`, `fic-password-history-initial`) staged как
    canonical Neutral bytes (`# FIC managed password slot: state=neutral\n`)
    и защищены dpkg conffiles (upgrade/reinstall не перезаписывает
    admin/runtime-modified Active slot).
- Bootstrap primitive `PamManagedPasswordSlotBootstrap`
  (`fic/src/modules/identity_access/pam/PamManagedPasswordSlotBootstrap.{h,cpp}`):
  - existence-only контракт; использует существующий
    `fic-core` `AtomicFileWriter::writeWithResult` (exclusive create,
    rejectSymlink, file fsync + parent dir fsync, freshness post-write
    verification) — НЕ создаёт параллельную transaction framework;
  - физический parent chain check (lstat, no symlink traversal);
  - O_EXCL-эквивалентный publish, никогда truncate/replacement;
  - typed result: per-slot `Created/AlreadyPresent/failed/error` +
    монотонный `changedSystemState` (honest partial-mutation accounting);
  - НЕ создаёт journal record, witness, Prepared/Applied; не вызывает
    rollback; НЕ repair existing files.
- Bootstrap state matrix:

```text
Absent            -> Created (canonical Neutral, durable, verified)
Neutral           -> AlreadyPresent, byte/metadata-identical no-op
Active (+J/W)     -> AlreadyPresent, bytes/journal/witness untouched
Broken regular    -> AlreadyPresent (no repair); PreAttach validator -> UNSAFE
Symlink           -> FAIL closed (target untouched)
Dangling symlink  -> FAIL closed
Directory         -> FAIL closed
FIFO/special      -> FAIL closed
```

- Maintenance CLI (production, root-only, в `fic/src/main.cpp`):
  - `fic --maintenance bootstrap-pam-password-slots` — требует
    pam-auth-update password topology (PasswordQuality capability с
    `PamTopologyStrategyKind::PamAuthUpdate`; ALT -> отказ), default
    production identity root:root 0644; exit 0 только при полном
    fail-free bootstrap, иначе nonzero + per-slot diagnostics.
  - `fic --maintenance validate-pam-slots-before-attach` — теперь включает
    password PreAttach verdict в общий package-side gate (password-часть
    раньше была отключена под Step 5; faillock-часть не изменена).
  - Production sequence: bootstrap -> validate -> STOP. Attach — только
    Step 5C.
- Packaging (`packaging/deb/build-fic-debian12-deb.sh`; все platform
  scripts debian13/ubuntu2404/ubuntu2604 делегируют в него):
  - postinst configure: bootstrap (fail-closed exit 1) ->
    validate-pam-slots-before-attach -> faillock attach (Step 5A,
    неизменён) -> STOP для password hooks; НЕТ
    `pam-auth-update --enable fic-password-*-hook`; НЕТ common-password
    mutations.
  - prerm remove list включает оба password hook profiles (existing
    framework removes all packaged profiles); recovery re-enable
    по-прежнему только faillock hooks.

## Completed

- Phase model PreAttach/Attached + empty-services P2 (ранее).
- Bootstrap primitive + unit tests (`pam_managed_password_slot_bootstrap_tests`,
  `tests/fic/modules/identity_access/pam/PamManagedPasswordSlotBootstrapTests.cpp`):
  all-absent, existing-neutral, existing-Active+J/W, corrupt-regular ->
  validator UNSAFE, symlink, dangling symlink, directory, FIFO,
  partial-existing-state, repeated-invocation fingerprint no-op,
  durability-failure (AtomicFileWriter test seam) fail-closed + idempotent
  retry, fault-injection fail-fast + changedSystemState honesty,
  bootstrap->validator SAFE read-only separation proof.
- Maintenance CLI wiring (bootstrap + validator password gate).
- Packaging payload (2 profiles + 3 slots + conffiles) + postinst/prerm wiring.
- Packaging contract tests (`tests/integration/packaging/PamPackagingChecks.py`):
  profile fields/priorities/includes/Password-Type, canonical Neutral slot
  payload, conffiles contract, bootstrap-before-validate ordering,
  behavioral postinst (success + validator-failure + bootstrap-failure
  paths), запрет password-hook enable и common-password edits.
- Package build Debian 12 (docker) — успешна; contents `fic_*.deb`
  проверены `dpkg-deb`: оба профиля, три slots, conffiles, postinst/prerm
  без password-hook enable и без common-password.

## Changed areas

- `fic/src/modules/identity_access/pam/PamManagedPasswordSlotBootstrap.{h,cpp}` (новые).
- `fic/src/main.cpp` (bootstrap command + password PreAttach gate в validate).
- `packaging/deb/build-fic-debian12-deb.sh`;
  `packaging/deb/pam-configs/fic-password-{quality,history}-hook` (новые);
  `packaging/deb/pam-slots/fic-password-quality`,
  `packaging/deb/pam-slots/fic-password-history`,
  `packaging/deb/pam-slots/fic-password-history-initial` (новые).
- `tests/CMakeLists.txt`; `tests/fic/modules/identity_access/pam/PamManagedPasswordSlotBootstrapTests.cpp` (новый);
  `tests/integration/packaging/PamPackagingChecks.py`.
- НЕ изменены: `common-password` access, journal schema, rollback,
  lockout semantics, `PamPolicySupport::ReadOnly`, runtime activation,
  ALT implementation, platform profiles.

## Validation

- Ubuntu 24.04: `cmake -S . -B build-step5b-u2404 -DFIC_TARGET_PLATFORM=ubuntu-24.04 -DBUILD_TESTING=ON`
  + `cmake --build build-step5b-u2404 -j4` — PASS.
- Targeted CTest (`pam_password|pam_slot_attach|pam_control_flow|pam_managed_password|pam_configuration|journal|rollback|packaging`):
  15/15 PASS на обоих build-trees.
- Full CTest: Ubuntu 24.04 — 101/102 PASS, 1 skipped
  (`command_hash_batch_tests`, root-only); Debian 12 — 101/102 PASS,
  1 skipped. Единственный failure на обоих — известный baseline
  `passwdqc_config_file_tests` (`pwquality policy did not retain its
  topology-dependent state`), симптом идентичен задокументированному.
- Debian 12: `cmake -S . -B build-step5b-deb12 -DFIC_TARGET_PLATFORM=debian-12 -DBUILD_TESTING=ON`
  + build — PASS.
- Package: `packaging/deb/build-fic-debian12-deb-docker.sh 0.1.0-rc.1` —
  PASS; contents проверены (см. Completed).
- `git diff --check` — PASS.

## Remaining

- Step 5C (next): actual `pam-auth-update` attach lifecycle для
  `fic-password-quality-hook` / `fic-password-history-hook`,
  resulting-state attachment proof, partial-failure compensation,
  remove/reinstall handling. Bootstrap + validate уже wired и НЕ должны
  смешиваться с attach в один opaque helper.
- Step 6: Debian 12 ModuleArguments option writer. Step 7: runtime
  activation (`enable_password_quality`/`enable_password_history`),
  lifting `PamPolicySupport::ReadOnly`.
- Baseline failure `passwdqc_config_file_tests` — вне scope, не чинить без
  отдельной задачи.
- Не запускать параллельно `/tmp`-конфликтующие test-наборы
  (известный конфликт: `grub_rollback_journal_tests`).
