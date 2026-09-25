# FIC: передача контекста

## Current base

- Ветка `main`. Baseline: `f8892b45a6d0bd0d2d9460b80e3d2eb3b3e4976c`
  ("Завершаем реализацию Step5B"; включает более ранние Step 5B коммиты).

## Current task

- Step 5B follow-up: selection-preserving remove lifecycle для двух
  password hook profiles в Debian/Ubuntu prerm — РЕАЛИЗОВАН (uncommitted
  working tree, коммиты по инструкции не создаются).
- Step 5C — следующий этап: install-time attach lifecycle
  (`pam-auth-update --enable` в postinst с resulting-state proof и
  partial-failure compensation) — НЕ реализован и не начинался.

## Ownership boundary (accepted, core Step 5B invariant)

```text
package owns infrastructure/existence  (hook profiles + slot conffiles)
runtime policy + journal own managed state
pam-auth-update owns generated common-* files
```

Bootstrap/package НЕ является владельцем текущего Active/Neutral policy
state и никогда его не перезаписывает.

## Remove lifecycle (prerm, selection-preserving, Step 5B follow-up)

Контракт `write_system_integration_symlink_prerm` (Debian/Ubuntu, prerm
remove): snapshot → remove → восстановление → proof → fail closed.

1. ДО первого `pam-auth-update`: read-only snapshot выбора двух password
   hook profiles — точный full-line `grep -q "^Module: <profile>$"`
   грамматикой из `/var/lib/pam/password`
   (`fic_password_{quality,history}_hook_selected`).
2. `pam-auth-update --package --remove` всех 8 профилей (4 faillock hooks +
   4 legacy); при rc=0 — обычное завершение (selected hooks честно сняты).
3. При rc!=0: обязательное восстановление ВСЕХ 4 faillock hook profiles
   (инвариант infrastructure-always-restore не изменился) + strict proof
   `fic_prove_permanent_hooks_attached`.
4. Затем selection-preserving восстановление password hooks:
   `--enable` ТОЛЬКО hooks из snapshot-derived `fic_password_hook_restore_list`
   (unselected hooks восстановление не включает никогда), после чего
   read-only proof `fic_prove_password_hook_state_restored <q> <h>`:
   selected → точный `Module:` record + активные include(s) в
   `common-password` (history — dual-stack: `fic-password-history` и
   `fic-password-history-initial`); unselected → отсутствие record и
   includes. rc=0 от `--enable` не трастится никогда.
5. Любая ошибка recovery/proof → диагностические сообщения
   ("password hook recovery failed" / "NOT proven restored") + `exit 1`
   (rc=0 от remove не трастится).

Read-only инварианты: proof-функции никогда не вызывают pam-auth-update и
не мутируют PAM state; prerm не редактирует `common-password` напрямую —
writer только pam-auth-update.

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
- Step 5B follow-up (uncommitted): prerm remove lifecycle стал
  selection-preserving для password hooks — snapshot до remove,
  snapshot-derived restore list, `fic_prove_password_hook_state_restored`
  (read-only, exact Module:/include grammar, dual-stack history includes),
  fail-closed диагностика. Фейк `pam-auth-update` расширен: password
  facility, dual-stack history regen, partial mutation в password,
  инъекции `FAKE_PAU_PASSWORD_ENABLE_FAILS` / `FAKE_PAU_PASSWORD_MALFORMED`.
- Package build Debian 12 (docker) — успешна; contents `fic_*.deb`
  проверены `dpkg-deb`: оба профиля, три slots, conffiles, postinst/prerm
  без password-hook enable и без common-password.
  ВНИМАНИЕ: на текущем хосте docker-сборка образа сломана окружением
  (apt не находит qt6-* пакеты, см. Remaining); вместо полной сборки
  выполнена artifact-проверка сгенерированного `DEBIAN/prerm`
  (`write_system_integration_symlink_prerm` → `sh -n` + ручная инспекция).

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

- `python3 tests/integration/packaging/PamPackagingChecks.py .` — PASS
  (включая новые static-проверки password snapshot/proof/read-only и
  behavioral matrix P-A..P-S: none-selected / only-quality / both-selected
  восстановление, порядок restore, password-enable failure fail-closed,
  rc=0 + malformed include fail-closed, успешный remove без dangling
  includes/records).
- `ctest --test-dir build-check -R pam_packaging` — PASS.
- `bash -n packaging/deb/build-fic-debian12-deb.sh` — PASS;
  сгенерированный `DEBIAN/prerm`: `sh -n` PASS, snapshot до первого
  `pam-auth-update`, условный recovery, read-only proof, отсутствуют
  прямые правки `common-password`.
- `git diff --check` — PASS.
- Docker-сборка Debian 12 пакета НЕ выполнена: `docker build` падает на
  `apt-get install` (qt6-base-dev-tools, qt6-qpa-plugins, xauth, xvfb —
  "Unable to locate package"), это проблема окружения/зеркала, не связана
  с изменениями.

## Remaining

- Рабочее дерево содержит незакоммиченные изменения Step 5B follow-up
  (`packaging/deb/build-fic-debian12-deb.sh`,
  `tests/integration/packaging/PamPackagingChecks.py`) — закоммитить
  отдельной задачей (по текущей инструкции коммиты не создаются).
- Docker-сборка Debian 12 образа сломана окружением: `apt-get install` в
  `packaging/deb/Dockerfile` не находит qt6-base-dev-tools,
  qt6-qpa-plugins, xauth, xvfb; полная package-build validation после
  починки окружения.
- Step 5C (next): install-time attach lifecycle для
  `fic-password-quality-hook` / `fic-password-history-hook`
  (postinst-side `pam-auth-update` attach с resulting-state proof и
  partial-failure compensation; remove-side уже закрыт этим follow-up).
  Bootstrap + validate уже wired и НЕ должны смешиваться с attach в один
  opaque helper.
- Step 6: Debian 12 ModuleArguments option writer. Step 7: runtime
  activation (`enable_password_quality`/`enable_password_history`),
  lifting `PamPolicySupport::ReadOnly`.
- Baseline failure `passwdqc_config_file_tests` — вне scope, не чинить без
  отдельной задачи.
- Не запускать параллельно `/tmp`-конфликтующие test-наборы
  (известный конфликт: `grub_rollback_journal_tests`).
