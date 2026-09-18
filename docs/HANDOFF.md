# FIC: передача контекста

## Current base

- Ветка `main`, HEAD `b5b67b0` (реализация GRUB ownership-release rollback).
- Рабочее дерево содержит незакоммиченный hardening по 16-пунктовому
  review-спеку (см. Current task).

## Current task

- **GRUB rollback hardening** (P0/P1/P2), незакоммичено, production-код и
  тесты завершены:
  - **P0** — `validateGrubRebuildInputs()` перед КАЖДОЙ пересборкой
    grub.cfg: Debian apply (already-set, post-write, compensating),
    `GrubRollback.cpp` (все rollback-варианты), mandatory reconciliation
    rebuild. Существующие base/shared defaults должны быть безопасны
    (regular, не group/world-writable, безопасная цепочка каталогов);
    отсутствие — допустимо. `GrubConfiguration::rebuild()` теперь
    non-const и сам валидирует shared inputs.
  - **P1** — typed probe `probeGrubTargetFile()`
    (`GrubTargetKind{Missing,Regular,Unsafe,Error}`): unsafe-артефакт
    (symlink/dir/FIFO) на managed-пути = Conflict без rebuild (раньше
    трактовался как Missing/NothingToDo); single-snapshot CAS:
    `GrubConfiguration::loadedState_` (AtomicTargetState через
    `readSnapshot()`: O_NOFOLLOW|O_NONBLOCK, 1 MB bound, fstat+lstat
    re-proof), CAS против snapshot'а load(); journal reconciliation:
    `classifyGrubManagedJournalState()` (Before/After/Drift/Invalid) +
    post-rebuild re-proof в `finishGrubJournalReconciliation`
    (Drift/Invalid → fail closed, запись остаётся активной, новый Prepared
    не создаётся).
  - **P2** — ALT EOF-сепаратор как FIC-owned сериализация:
    `assembleAtEof` всегда добавляет ровно один `\n` перед BEGIN для
    непустого foreign; `foreignBytes` снимает его при декодировании только
    когда блок в EOF → foreign без завершающего `\n` (`"FOO=bar"`)
    восстанавливается byte-exact.
  - Test seam: `setGrubSharedPreWriteHookForTests()` /
    `fireGrubSharedPreWriteHookForTests()` (GrubConfiguration.{h,cpp};
    fires непосредственно перед CAS write в ALT apply и `undoSharedBlock`).

## Accepted architecture / invariants

- Ownership-release: rollback никогда не восстанавливает pre-FIC значение
  и не хранит snapshots; журнал доказывает только (key, appliedValue).
- Обязательная пересборка grub.cfg при каждом rollback, включая
  NothingToDo (crash-after-source-rollback инвариант); всегда на
  провалидированных входах.
- Авторитетное описание инвариантов (validated rebuild inputs, typed
  probe, single-snapshot CAS, reconciliation re-proof, EOF-сепаратор):
  `docs/rollback.md`, раздел «GRUB rollback (OSS/Grub)».
- Новые GRUB-политики никогда не становятся rollback-Supported
  автоматически — только через явное расширение whitelist в
  `RollbackExecutor.cpp` + journal integration.

## Completed

- Все правки P0/P1/P2 в `fic/src/modules/oss/grub/{Grub.cpp,
  GrubConfiguration.h/cpp, GrubManagedBlock.h/cpp, GrubManagedConfig.h/cpp,
  GrubRollback.cpp}`.
- Тесты: обновлены под новое поведение (EOF-сепаратор во всех
  byte-exact ожиданиях; relocation добавляет сепаратор; канонический
  apply-формат содержит blank line перед блоком); добавлены регрессионные
  тесты A–E в `GrubRollbackJournalTests.cpp` (A: Debian reconciliation с
  unsafe base defaults — rebuild 0, запись Prepared; B/C: stale-read CAS
  race через hook для ALT apply и rollback — external bytes byte-exact,
  rebuild 0; D: symlink/каталог на managed-пути ALT+Debian → Conflict, не
  NothingToDo, rebuild 0; E: drift после mandatory rebuild (скрипт
  переписывает источник) → fail closed, запись активна — ALT + Debian) и
  тест F (byte-exact round-trip foreign без/с завершающим `\n`) в
  `GrubPolicyTests.cpp`.
- `docs/rollback.md`: новые инварианты задокументированы.

## Changed areas

- `fic/src/modules/oss/grub/`, `docs/rollback.md`, `docs/HANDOFF.md`,
  `tests/fic/modules/oss/grub/{GrubPolicyTests.cpp,
  GrubRollbackJournalTests.cpp}`.

## Validation

- Full build `build-check` (-DFIC_TARGET_PLATFORM=ubuntu-24.04): exit 0.
- Full CTest: **100% passed, 0 failed out of 97** (pre-existing skip
  `command_hash_batch_tests`).
- Targeted: `grub_policy_tests`, `grub_rollback_journal_tests`,
  `mutation_journal_tests`, `rollback_executor_tests`,
  `ssh_apply_rollback_tests`, `platform_profile_tests` — PASS.
- `git diff --check`: clean.

## Remaining

- Коммит GRUB rollback hardening (вместе с базовой реализацией b5b67b0
  либо отдельным коммитом поверх).
- Sanitizer build не выполнялся (профиль в проекте отсутствует) — не
  заявлять как выполненный.
- В `GrubRollbackJournalTests` кастомные rebuild-скрипты (drift/marker)
  регистрируются в CommandHashStore через helper `seedRebuildExecutable()`
  (`sha256sum` + append в hash-файл); фиксированный скрипт
  `#!/bin/sh\nexit 0\n` — захардкоженный sha256 `306c6ca7…`. `saveHash`
  требует chown под root.
- Известное поведение (by design): при relocation блока foreign-область
  сохраняется byte-exact, но перед блоком в EOF добавляется
  FIC-owned сепаратор `\n` (лишняя пустая строка возможна, если foreign
  уже заканчивается `\n`).
