# FIC: передача контекста

## Current base

- Ветка `main`, HEAD `f845fc0290ffe5008259eb3b3348e561686d687e`.
- Рабочее дерево содержит незакоммиченные изменения текущей задачи.

## Current task

- SSSD/Kerberos rollback follow-up: убрать persistent writer из same-value
  `Reused` пути и закрыть no-replace race у SSSD proof-bound removal.

## Accepted architecture / invariants

- Существующие `MutationJournal + RollbackExecutor + typed UndoAction`.
- `source absent` доказывает только release, не завершение rollback; `RolledBack`
  допустим после успешной runtime-реконсиляции.
- Directory entry после removal/recreate считается durable только после
  `fsync` родительского каталога. Неудачный барьер — не обычный success.
- FIC-owned SSSD drop-in и structured Kerberos edit остаются без изменений
  архитектуры; package/purge не затронуты.
- `Reused` означает повторную read-only проверку source, без setter/writer;
  SSSD при этом по-прежнему реконсилирует runtime.
- SSSD rename-away и восстановление staged foreign объекта не заменяют
  уже существующий target; без `RENAME_NOREPLACE` операция fail closed.

## Completed

- Удаление и exclusive recreate подтверждают directory fsync через общий
  helper `AtomicFileWriter` с deterministic test seam.
- Compensation выставляет owner/mode через fd до write/fsync/close.
- Apply-path для absent source переиспользует `undoSssdManagedSetting()`
  независимо от active record status и только после него закрывает запись.
- Добавлены regression tests для directory fsync failure и apply-recovery
  `Prepared`/`Applied`/`RollbackFailed`.
- SSSD и Kerberos `Reused` теперь не заходят в persistent writer; drift после
  первого proof остаётся нетронутым и завершает apply ошибкой.
- SSSD staging/restore переведены на `RENAME_NOREPLACE`; B+C race и
  занятый staging path сохраняют foreign объекты.
- Новые regression tests покрывают оба drift-after-proof пути (в том числе
  Kerberos `Prepared → Applied`), staging collision и B→C race.

## Changed areas

- `fic-common/fic-core/{include,src}/fs/AtomicFileWriter.*`;
- `fic/src/modules/identity_access/sssd/{SssdConfiguration.cpp,policies/SssdOfflineCredentialsExpirationPolicy.cpp}`;
- `tests/fic/modules/identity_access/IdentityConcretePoliciesTests.cpp`;
- `docs/rollback.md`, `docs/HANDOFF.md`.
- `fic/src/modules/identity_access/kerberos/policies/KerberosTicketLifetimePolicy.{h,cpp}`.

## Validation

- Configure: `cmake -S . -B /tmp/fic-sssd-rollback-build
  -DFIC_TARGET_PLATFORM=ubuntu-24.04` — PASS.
- `identity_concrete_policies_tests` build и CTest — PASS после всех правок.
- Full build — PASS.
- Full CTest вне sandbox: 97/97 PASS, `command_hash_batch_tests` —
  штатный skip. В sandbox ранее два integration-теста падали из-за
  Unix-socket bind / недоверенного test-root.
- `git diff --check` — PASS.
- Старый `build-fix` read-only; используем `/tmp/fic-sssd-rollback-build`.

## Remaining

- Native privileged SSSD runtime не запускался (только tests с fake runner).
