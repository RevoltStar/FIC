# FIC: передача контекста

## Current base

- Ветка `main`, HEAD `372475300d467b3bae823c6d5dd27fd1c103a0f7`.
- Рабочее дерево содержит незакоммиченные изменения текущей задачи.

## Current task

- SSSD rollback: устранение durability gaps у удаления drop-in и его
  компенсационного восстановления, descriptor-based metadata, обязательная
  runtime-реконсиляция при active journal record + source absent в apply.

## Accepted architecture / invariants

- Существующие `MutationJournal + RollbackExecutor + typed UndoAction`.
- `source absent` доказывает только release, не завершение rollback; `RolledBack`
  допустим после успешной runtime-реконсиляции.
- Directory entry после removal/recreate считается durable только после
  `fsync` родительского каталога. Неудачный барьер — не обычный success.
- FIC-owned SSSD drop-in и structured Kerberos edit остаются без изменений
  архитектуры; package/purge не затронуты.

## Completed

- Удаление и exclusive recreate подтверждают directory fsync через общий
  helper `AtomicFileWriter` с deterministic test seam.
- Compensation выставляет owner/mode через fd до write/fsync/close.
- Apply-path для absent source переиспользует `undoSssdManagedSetting()`
  независимо от active record status и только после него закрывает запись.
- Добавлены regression tests для directory fsync failure и apply-recovery
  `Prepared`/`Applied`/`RollbackFailed`.

## Changed areas

- `fic-common/fic-core/{include,src}/fs/AtomicFileWriter.*`;
- `fic/src/modules/identity_access/sssd/{SssdConfiguration.cpp,policies/SssdOfflineCredentialsExpirationPolicy.cpp}`;
- `tests/fic/modules/identity_access/IdentityConcretePoliciesTests.cpp`;
- `docs/rollback.md`, `docs/HANDOFF.md`.

## Validation

- Configure: `cmake -S . -B /tmp/fic-sssd-rollback-build
  -DFIC_TARGET_PLATFORM=ubuntu-24.04` — PASS.
- `identity_concrete_policies_tests` build и CTest — PASS после всех правок.
- Full build — PASS.
- Full CTest в sandbox: 95/97; два integration-теста упали из-за запрета
  Unix-socket bind / недоверенного test-root. Полный повтор вне sandbox:
  97/97 PASS, `command_hash_batch_tests` — штатный skip.
- `git diff --check` — PASS.
- Старый `build-fix` read-only; используем `/tmp/fic-sssd-rollback-build`.

## Remaining

- Сверить итоговый diff перед завершением.
- Native privileged SSSD runtime не запускался (только tests с fake runner).
