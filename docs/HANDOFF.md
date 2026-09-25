# FIC: передача контекста

## Current base

- Ветка `main`. Baseline: `23f3df433035ac39ce647b46923c50ec66bc8759`
  ("Follow-up к последнему коммиту №2"; включает remove/recovery fix для
  password hook profiles — per-profile enable, proof после каждой
  native mutation, resulting-state proof (0, 0) после успешного remove).

## Current task

- Fail-fast follow-up: password-hook recovery в prerm теперь строго
  fail-fast — после первой failed/unproven password mutation
  (enable rc!=0 ИЛИ immediate proof fail) НИКАКОЙ последующий
  `pam-auth-update` password вызов не выполняется, финальный full-state
  proof запускается только если все запрошенные мутации выполнены и
  proven — РЕАЛИЗОВАНО в working tree (коммит отдельной задачей, по
  текущей инструкции не создаётся).
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

## Remove lifecycle (prerm, selection-preserving, per-profile enable)

Контракт `write_system_integration_symlink_prerm` (Debian/Ubuntu, prerm
remove): snapshot → remove → resulting-state proof → восстановление →
proof → fail closed.

1. ДО первого `pam-auth-update`: read-only snapshot выбора двух password
   hook profiles — точный full-line `grep -q "^Module: <profile>$"`
   грамматикой из `/var/lib/pam/password`
   (`fic_password_{quality,history}_hook_selected`).
2. `pam-auth-update --package --remove` всех 8 профилей (4 faillock hooks +
   4 legacy). rc=0 НЕ трастится: сразу после успешного remove выполняется
   read-only proof `fic_prove_password_hook_state_restored 0 0`
   (отсутствие обоих Module records И всех generated includes). Если proof
   (0, 0) fail — remove считается failed/ambiguous и входит в ТОТ ЖЕ
   recovery path, что и native rc!=0 (общий флаг
   `fic_pam_remove_failed`); просто `exit 1` без восстановления
   недопустимо, т.к. native remove уже мог изменить PAM state.
3. При failed/ambiguous remove: обязательное восстановление ВСЕХ 4
   faillock hook profiles (инвариант infrastructure-always-restore не
   изменился) + strict proof `fic_prove_permanent_hooks_attached`.
4. Затем selection-preserving восстановление password hooks — строго
   ПО ОДНОМУ profile на `pam-auth-update --enable` invocation
   (combined `--enable quality history` запрещён; fake проваливает
   combined password enable детерминированно) и СТРОГО FAIL-FAST:
   - quality selected → `--enable fic-password-quality-hook` →
     немедленно `fic_prove_password_hook_state_restored 1 d`;
   - history selected → `--enable fic-password-history-hook` →
     немедленно `fic_prove_password_hook_state_restored d 1`
     (don't-care "d" только в промежуточных per-hook proofs;
     post-failure state второго hook неизвестен до финального proof);
   - history enable guarded состоянием recovery: выполняется ТОЛЬКО при
     `fic_password_hook_recovery_failed = 0` — после failed enable или
     failed immediate proof quality НИКАКОЙ последующий password
     `pam-auth-update` вызов не делается (поверх непроверенной топологии
     мутации запрещены);
   - финальный full-state proof
     `fic_prove_password_hook_state_restored <q> <h>` запускается только
     если ВСЕ запрошенные мутации выполнены и proven, и сверяет оба hook
     с pre-remove snapshot.
5. Semantics proof: selected → точный `Module:` record + активные
   include(s) в `common-password` (history — dual-stack:
   `fic-password-history` и `fic-password-history-initial`); unselected →
   НЕТ record И НЕТ exact generated include любого из его targets
   (stale include без record проваливает proof). rc=0 от любого
   `--enable` не трастится никогда. Любая ошибка recovery/proof →
   диагностические сообщения + `exit 1`.

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

- `python3 tests/integration/packaging/PamPackagingChecks.py .` — PASS:
  unit-проверки password proof (canonical / T2 stale quality include / T3
  stale history includes / commented, wrong-facility, wrong-control,
  collision / unknown flags fail closed / read-only digest), static-
  проверки (per-profile enable в snapshot-conditioned ветках, fail-fast
  guard history enable по `fic_password_hook_recovery_failed`, guard
  финального full-state proof, отсутствие combined restore list, proof
  (0, 0) после успешного remove, negative include checks для всех трёх
  targets, snapshot до первого pam-auth-update) и behavioral matrix
  P-A..P-E, P-S, T1..T5, T8 + F1 (quality enable rc!=0 → history enable
  не вызывается) / F2 (rc=0 quality enable с failed immediate proof →
  history enable не вызывается).
- `ctest --test-dir build-check -R pam_packaging --output-on-failure` —
  PASS.
- `bash -n packaging/deb/build-fic-debian12-deb.sh` — PASS;
  сгенерированный `DEBIAN/prerm`: `sh -n` PASS, snapshot до первого
  `pam-auth-update`, fail-fast per-profile enable + промежуточные proofs,
  read-only proof, отсутствуют прямые правки `common-password`.
- `git diff --check` — PASS.
- Docker-сборка Debian 12 пакета НЕ выполнена: `docker build` падает на
  `apt-get install` (qt6-base-dev-tools, qt6-qpa-plugins, xauth, xvfb —
  "Unable to locate package"), это проблема окружения/зеркала, не связана
  с изменениями.

## Remaining

- Рабочее дерево содержит незакоммиченный fail-fast follow-up
  (`packaging/deb/build-fic-debian12-deb.sh`,
  `tests/integration/packaging/PamPackagingChecks.py`,
  `docs/HANDOFF.md`) — закоммитить отдельной задачей (по текущей
  инструкции коммиты не создаются).
- Docker-сборка Debian 12 образа сломана окружением: `apt-get install` в
  `packaging/deb/Dockerfile` не находит qt6-base-dev-tools,
  qt6-qpa-plugins, xauth, xvfb; полная package-build validation после
  починки окружения.
- Step 5C (next): install-time attach lifecycle для
  `fic-password-quality-hook` / `fic-password-history-hook`
  (postinst-side `pam-auth-update` attach с resulting-state proof и
  partial-failure compensation; remove-side закрыт). Bootstrap + validate
  уже wired и НЕ должны смешиваться с attach в один opaque helper.
- Step 6: Debian 12 ModuleArguments option writer. Step 7: runtime
  activation (`enable_password_quality`/`enable_password_history`),
  lifting `PamPolicySupport::ReadOnly`.
- Baseline failure `passwdqc_config_file_tests` — вне scope, не чинить без
  отдельной задачи.
- Не запускать параллельно `/tmp`-конфликтующие test-наборы
  (известный конфликт: `grub_rollback_journal_tests`).
