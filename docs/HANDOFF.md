# FIC: передача контекста

## Current base

- Ветка `main`, HEAD `41be075`.
- Рабочее дерево содержит незакоммиченную реализацию GRUB
  ownership-release rollback (см. Current task).

## Current task

- **GRUB journal-backed rollback** поверх `d518cb0` + follow-up, незакоммичено.
  Модель владения: Debian/Ubuntu — FIC-owned drop-in
  `/etc/default/grub.d/zzzz-fic.cfg` (canonical format, пустой файл
  удаляется); ALT — FIC managed block в EOF `/etc/sysconfig/grub2`
  (`GrubManagedBlock.{h,cpp}`, строгий fail-closed парсинг, byte-exact
  сохранение чужих байт, relocation в EOF).
  Journal payload `UndoRemoveGrubManagedSetting{key, appliedValue}`
  (`MutationBackend::Grub`): только key + appliedValue; топология — из
  текущего platform profile, в journal не пишется; без migration/backward
  compatibility (schema_version journal НЕ менялся — tagged payload
  расширяет вариант естественным образом).
  Rollback: `GrubRollback.{h,cpp}` (`undoGrubManagedSetting`), dispatch в
  `RollbackExecutor` (`grubOptions` deps, whitelist
  grub_timeout/grub_cmdline_linux/grub_disable_recovery → Supported,
  неизвестные OSS/Grub → Unsupported). Семантика: missing key/артефакт →
  обязательный rebuild + NothingToDo; value mismatch → Conflict (источник
  не трогается, rebuild нет); CAS write + post-write proof; rebuild failure
  → conditional compensation (ALT — блок байт-в-байт, Debian — drop-in;
  пустой drop-in пересоздаётся exclusive create; concurrent drift не
  перезаписывается) + компенсирующий rebuild, journal остаётся активным.
  Apply (`Grub.cpp`): Prepared только при needsChange; reconcile
  (DRIFT→fail, BEFORE→discard+RolledBack, AFTER→commit Applied); value
  change → release через тот же undo-механизм; lifecycle matrix по
  failure/success и resulting state; общий `grubBackendMutex()`
  (shared apply+rollback); rebuild через VerifiedProcessExecutor,
  пустой env, 60s.

## Accepted architecture / invariants

- Ownership-release: rollback никогда не восстанавливает pre-FIC значение
  и не хранит snapshots; журнал доказывает только (key, appliedValue).
- Обязательная пересборка grub.cfg при каждом rollback, включая
  NothingToDo (crash-after-source-rollback инвариант).
- Новые GRUB-политики никогда не становятся rollback-Supported
  автоматически — только через явное расширение whitelist в
  `RollbackExecutor.cpp` + journal integration.
- Документация: `docs/rollback.md` — раздел «GRUB rollback (OSS/Grub)»,
  enrollment whitelist, `UndoRemoveGrubManagedSetting` в Undo actions.

## Completed

- `GrubManagedBlock.{h,cpp}`, `GrubRollback.{h,cpp}` (новые);
  `GrubConfiguration.{h,cpp}`, `Grub.cpp`, `GrubManagedConfig.cpp`,
  `MutationRecord.h`, `MutationJournal.cpp` (backend "grub",
  remove_grub_managed_setting), `RollbackExecutor.{h,cpp}`,
  `PlatformExecutableResolver` integration.
- Тесты: `GrubPolicyTests` (переписана середина: parser блока, ALT editor,
  foreign preservation/relocation, fail-closed ambiguous inputs,
  rebuild-failure compensation, Debian drop-in editing); новый
  `tests/fic/modules/oss/grub/GrubRollbackJournalTests.cpp` (apply/rollback
  lifecycle + Prepared recovery A/B/C для обеих топологий, value change,
  NothingToDo/Conflict, rebuild-failure compensation, rebuild call counts);
  `MutationJournalTests` (+grub payload round-trip, +6 malformed fail-closed);
  `RollbackExecutorTests` (enrollment matrix обновлён: OSS/Grub Supported;
  legacy-disable тест переведён на NotEnrolled модуль).
- `tests/CMakeLists.txt`: новый target `grub_rollback_journal_tests`;
  `ssh_apply_rollback_tests` дособлян GRUB-исходники (линковка
  RollbackExecutor).

## Changed areas

- `fic/src/modules/oss/grub/`, `fic/src/rollback/`,
  `docs/rollback.md`, `docs/HANDOFF.md`,
  `tests/CMakeLists.txt`,
  `tests/fic/modules/oss/grub/`, `tests/fic/rollback/`.

## Validation

- Full build `build-check` (-DFIC_TARGET_PLATFORM=ubuntu-24.04): exit 0.
- Full CTest: **100% passed, 0 failed out of 97** (pre-existing skip
  `command_hash_batch_tests`).
- `grub_rollback_journal_tests`, `grub_policy_tests`,
  `mutation_journal_tests`, `rollback_executor_tests`, `ssh_apply_rollback_tests`:
  PASS.
- `git diff --check`: clean.

## Remaining

- Коммит GRUB ownership-release rollback.
- Sanitizer build всего дерева не выполнялся (профиль в проекте отсутствует).
- В `GrubRollbackJournalTests` fake rebuild executable регистрируется в
  CommandHashStore прямой записью hash-файла (жёстко захардкоженный sha256
  `#!/bin/sh\nexit 0\n`) — `saveHash` требует chown под root.
