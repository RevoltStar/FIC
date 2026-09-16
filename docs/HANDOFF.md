# FIC: передача контекста

## Current base

- Ветка `main`, базовый commit `d518cb0`.
- Изменения текущей SSH rollback-задачи находятся в рабочем дереве и не
  закоммичены.

## Current task

- Persistent rollback для SSH-политик `NET/SshEdit`
  (`ssh_port`, `ssh_max_auth_tries`, `ssh_root_login`, `ssh_pubkey_auth`)
  через typed `UndoRestoreSshDirective`: reverse delta global section shared
  `sshd_config`, без drop-in миграции и без full-file snapshot.

## Accepted architecture / invariants

- Main `sshd_config` — shared ресурс, не FIC-owned. Mutation хранит только
  exact reverse delta строк global section, которые реально изменил
  `SshConfigFileHandler::setValue()` (замены, комментарии дубликатов,
  вставленные строки).
- Fingerprint global section (FNV-1a 64, начало файла до первого `Match`)
  вычисляется в памяти ДО записи на диск (`planSetValue`) и сохраняется в
  journal. Rollback выполняется только при совпадении fingerprint; иначе
  `Conflict` без записи. Любое несвязанное изменение global section —
  `Conflict` (консервативный MVP); изменения после `Match` и во внешних
  include не мешают rollback и не восстанавливаются.
- Apply flow: effective-проверка через `SshRuntime::policyValueCompliance`
  (Compliant → без мутации, записи и reload; Unknown → fail closed) → план
  → `Prepared` в journal (существующая активная запись переиспользуется,
  исходный baseline не перезаписывается) → atomic write → verify → reload →
  commit. Apply-time restore при провале verify/reload: restore + `sshd -T`
  + reload restored; новый `Prepared` удаляется только при полном успешном
  restore. Commit failure → apply false, `Prepared` остаётся.
- Rollback executor: fingerprint check → reverse edits (с конца) → atomic
  write → `sshd -T` → reload if active; при провале — restore pre-rollback
  содержимого, `Failed`, запись остаётся активной.
- Legacy (нет journal-записей): директива присутствует в global section →
  `Unsupported` (disable запрещён); отсутствует → `NothingToDo`. Ранее
  отработанная (`RolledBack`) запись этой политики → `NothingToDo`.
- Enrollment `NET/SshEdit` — только explicit whitelist; неизвестная политика
  → `Unsupported`.
- Sudoers effective-precedence-model limitation (предыдущая задача):
  диагностическое ограничение, не связано с SSH.

## Completed

- `MutationBackend::Ssh`, `UndoRestoreSshDirective` + сериализация
  `restore_ssh_directive` (fail closed: пустые поля, невалидные/не
  возрастающие line indices, inconsistent backend/action → journal load
  failure).
- `SshConfigFileHandler::planSetValue/applyReverseEdits/
  globalSectionFingerprint`; `setValue` переписан через план.
- `SshRuntime`: `policyValueCompliance` (Compliant/NonCompliant/Unknown) и
  `validateConfiguration` на общем пути парсинга `sshd -T`.
- Новый `SshRollback.{h,cpp}` (`undoSshDirectiveMutation`,
  `restoreSshConfigContent`); `Ssh::apply` переписан (journal integration,
  §8–§14 ТЗ); `RollbackExecutor` SSH-ветки + `deps.sshOptions` +
  production wiring; `Ssh::managedResource()`; resourceHint в
  `main_function.cpp`.
- Документация: `docs/rollback.md`.

## Changed areas

- `fic/src/rollback/` (`MutationRecord.h`, `MutationJournal.cpp`,
  `RollbackExecutor.{h,cpp}`)
- `fic/src/modules/net/ssh/` (`Ssh.{h,cpp}`, `SshConfigFile.{h,cpp}`,
  `SshRuntime.{h,cpp}`, новый `SshRollback.{h,cpp}`)
- `fic/src/daemon/main_function.cpp`
- `tests/fic/rollback/`, `tests/fic/modules/net/ssh/SshApplyRollbackTests.cpp`
  (новый), `tests/CMakeLists.txt`
- `docs/rollback.md`

## Validation

- Targeted: `rollback_executor_tests` 40/40, `mutation_journal_tests` 21/21,
  `ssh_apply_rollback_tests` 9/9, `ssh_runtime_tests` — passed.
- Full CMake build (`build-check`, ubuntu-24.04): 100%, exit 0.
- Full CTest: 96/96 passed (1 pre-existing env-dependent skip:
  `command_hash_batch_tests`).
- `git diff --check`: passed.

## Remaining

- Изменения не закоммичены; diff чист и в scope задачи, готов к коммиту.
- Консервативность fingerprint: любое несвязанное изменение global section
  даёт `Conflict` (осознанное ограничение MVP, three-way merge не
  реализовывался). Перезапись fingerprint при refresh-apply не выполняется —
  structural drift между apply'ами → будущий `Conflict`.
- Native интеграционной проверки с реальным sshd не выполнялось (sandbox);
  только fake-runner unit tests.
