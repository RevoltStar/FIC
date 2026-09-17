# FIC: передача контекста

## Current base

- Ветка `main`, базовый commit `393ab36` (ownership-release семантика SSH
  rollback). Рабочее дерево содержит follow-up: безусловная проверка
  provenance journal payload в apply (незакоммичено).

## Current task

- Переход SSH rollback на ownership-release семантику: rollback освобождает
  текущую FIC-owned область управления, а не реконструирует прошлое состояние
  файла.

## Accepted architecture / invariants

- **Managed blocks / transaction**: все FIC-мутации sshd_config идут через
  FIC-managed block + `runSshConfigTransaction` (CAS write, durability,
  postcondition, hooks). `SshConfigFileHandler::setValue` — осознанный stub.
- **Строгая grammar (fail closed)**: внутри `FIC_SSH_BLOCK` — только
  `FIC_POLICY_BEGIN/END` sub-blocks; внутри policy sub-block — ровно одна
  active directive; внутри `FIC_DISABLED` — только один `FIC_DISABLED_LINE`.
  Нарушение = Malformed → Conflict, файл не изменяется.
- **Ownership-release rollback (новый контракт, docs/rollback.md —
  authoritative)**: rollback убирает только существующие доказанные
  FIC-owned артефакты. Journal payload (`disabledMutationIds`) — proof of
  permission, НЕ backup manifest. Провенанс — subset-семантика
  (`checkSshDisabledProvenance` → `SshDisabledProvenanceCheck::safeToRelease()`),
  проверяется в `analyzeOwnership()` БЕЗУСЛОВНО (malformed payload fail
  closed даже при полном отсутствии FIC-артефактов — compliance fast-path не
  должен скрыть corruption):
  каждый существующий wrapper обязан быть доказан payload'ом
  (`unknownIds`/`fileDuplicate`/`payloadMalformed` → Conflict); payload id с
  исчезнувшим wrapper'ом — `releasedIds` (информационно, НЕ ошибка);
  реконструкция отсутствующих wrapper'ов запрещена. Нет блока и wrapper'ов →
  `NothingToDo` + runtime reconciliation. Ручная правка directive-строки
  блока (≠ `appliedValue`) → Conflict. Byte-exact restoration — свойство
  нормального сценария, не общий контракт при внешних изменениях.
- **Value change**: предыдущее состояние откатывается той же
  ownership-release семантикой внутри apply; `NothingToDo` старого отката
  трактуется как «уже освобождено»; новое значение применяется к фактическому
  текущему конфигу.
- Malformed FIC-маркеры классифицируются как `Conflict`
  (`SshConfigFileHandler::lastLoadMarkerMalformed()`), не как Failed.
- **Journal load lifecycle / virgin bootstrap** (docs/rollback.md —
  authoritative): без изменений.

## Completed

- `SshManagedBlock.*`: `SshDisabledProvenanceCheck` переведён с set-equality
  на subset/ownership-release (`ok()` → `safeToRelease()`, `missingIds` →
  `releasedIds`, только диагностика).
- `SshRollback.cpp`: subset-проверка провенанса; комментарии обновлены.
- `Ssh.cpp`: `analyzeOwnership` через `safeToRelease()`; value-change
  принимает `nothingToDo` старого rollback как released.
- `MutationRecord.h`: комментарий `disabledMutationIds` = proof of permission.
- Тесты `SshApplyRollbackTests.cpp` (29): partial disappearance → Success
  (A restored, B не реконструируется); total disappearance → NothingToDo;
  known+unknown wrapper → Conflict; manually modified block → Conflict;
  value change с частично исчезнувшим wrapper'ом; value change после полной
  внешней очистки. `RollbackExecutorTests`: malformed markers → Conflict.
- `docs/rollback.md`: SSH undo bullet переписан под `UndoRemoveSshManagedPolicy`
  + ownership-release (EN + RU); «Active value changes» и NothingToDo-пассаж
  обновлены; старое описание `UndoRestoreSshDirective` удалено.

## Changed areas

- `fic/src/modules/net/ssh/` (`Ssh.cpp`, `SshManagedBlock.*`, `SshRollback.*`)
- `fic/src/rollback/MutationRecord.h` (комментарий)
- `tests/fic/modules/net/ssh/SshApplyRollbackTests.cpp`
- `docs/rollback.md`, `docs/HANDOFF.md`

## Validation

- Full build `build-check` (ubuntu-24.04): exit 0.
- Full CTest: 96/96 passed (1 pre-existing skip `command_hash_batch_tests`).
- `ssh_apply_rollback_tests`: 29 PASS / 0 FAIL; `rollback_executor_tests`,
  `mutation_journal_tests`, `ssh_runtime_tests`: exit 0.
- `bash scripts/run-development-checks.sh fast`: exit 0.
- `git diff --check`: passed.

## Remaining

- Residual TOCTOU между re-proof и fsync — known MVP limitation.
- Раздел «Результат отката» про legacy-ENABLE install (`Unsupported` по
  присутствию директивы в global section) не пересматривался — написать при
  следующей задачи по disable-пути.
- Рабочее дерево содержит незакоммиченный diff — требуется review и коммит.