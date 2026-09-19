# FIC: передача контекста

## Current base

- Ветка `main`, HEAD — коммит «Hardering-изменения для GRUB №8»
  (`b89f2bd`); текущая задача — SSSD/Kerberos rollback (см. ниже) —
  НЕ ЗАКОММИЧЕНА, рабочее дерево содержит изменения.

## Current task

- **Rollback для SSSD и Kerberos** — полная journal-backed rollback-
  интеграция двух политик Identity Access обычным lifecycle
  (apply → MutationJournal; disable → rollbackPolicyBeforeDisable →
  RollbackExecutor → typed undo → status=DISABLE). Package
  uninstall/purge/packaging НЕ затронуты. `Policy::rollback()` не
  добавлялся.
  1. **SSSD — FIC-owned drop-in**: `sssd_offline_credentials_expiration`
     больше не редактирует foreign `/etc/sssd/sssd.conf` (byte-for-byte
     неизменен). Все FIC-owned настройки живут в drop-in
     `/etc/sssd/conf.d/zzzz-fic.conf` (root, 0600, atomic, reject
     symlink/non-regular; `ManagedSnippetChange` в `SssdConfiguration.cpp`
     поддерживает create/write/remove с CAS). Конфликтующий later snippet →
     apply fail closed, чужие файлы не меняются. Effective verification
     через `inspectManagedSnippet()`; runtime через существующий
     `SssdRuntime` (restart + postcondition до `Applied`).
  2. **SSSD rollback**: `UndoRemoveSssdManagedSetting{section, option,
     appliedValue}`, backend `MutationBackend::Sssd`, `undoSssdManagedSetting()`
     в `SssdRollback.{h,cpp}` — ownership-release (AFTER/BEFORE/DRIFT;
     пустой drop-in удаляется CAS-verified unlink; restart активного SSSD;
     foreign значения не хранятся и не восстанавливаются).
  3. **Kerberos — reversible structured edit**: root `/etc/krb5.conf`
     `[libdefaults]/ticket_lifetime`; новые `inspectRootScalar()` и
     `prepareRootScalarMutation()` в `KerberosConfiguration` (CAS через
     `PreparedFileChange`, full-graph reparse в verifier, safe removal
     provably-empty FIC-created section).
  4. **Kerberos rollback**: `UndoRestoreKerberosScalar{section, relation,
     appliedValue, beforeKind(Missing/Present), beforeRawLine,
     sectionExistedBefore}`, backend `MutationBackend::Kerberos`,
     `undoKerberosScalar()` в `KerberosRollback.{h,cpp}` — inverse delta
     (восстановление точной raw-строки / удаление relation+empty section),
     whole-file snapshot не используется; drift (include-определение,
     дубликат, admin 2h) → Conflict.
  5. **Apply-интеграция** обеих политик: journal reconciliation до мутации
     (crash-release разрешение, value-change ownership release →
     `RolledBack` → fresh Prepared; drift → fail closed), Prepared до
     мутации, commit Applied после postcondition. Если значение уже
     effective через foreign конфигурацию и FIC ничего не меняет — записи
     не создаётся. Одна активная logical identity на политику.
  6. **RollbackExecutor**: enrollment whitelist строго
     IDENTITY_ACCESS/SSSD/sssd_offline_credentials_expiration и
     IDENTITY_ACCESS/KERBEROS/kerberos_ticket_lifetime → Supported;
     соседи — Unsupported, прочие IDENTITY_ACCESS — NotEnrolled; deps
     `sssdOptions`/`kerberosOptions`, production wiring, dispatch, ветви
     `checkUnrecordedOwnership`. `main_function.cpp` передаёт resourceHint
     `pam/offline_credentials_expiration` /
     `libdefaults/ticket_lifetime`.
  7. **Journal**: структурная сериализация/валидация обоих payload
     (writer+loader parity), resource == `<section>/<option|relation>`,
     CR/LF/NUL-запреты, before-kind consistency.
  8. Docs: `docs/rollback.md` — разделы «SSSD rollback» и «Kerberos
     rollback» + два новых undo action.

## Accepted architecture / invariants

- SSSD: FIC-owned drop-in `/etc/sssd/conf.d/zzzz-fic.conf`; foreign
  `sssd.conf` не изменяется вообще (apply и rollback); ownership-release
  rollback, foreign значения не хранятся.
- Kerberos: foreign main config structured edit (`[libdefaults]/
  ticket_lifetime`); journal хранит точный target before-state (raw line);
  rollback использует inverse delta + CAS; whole-file snapshot не
  используется; чужие include-файлы не редактируются; duplicate/include-
  определение target — fail closed.
- Enrolled: только `sssd_offline_credentials_expiration` и
  `kerberos_ticket_lifetime`; любые другие SSSD/Kerberos политики —
  Unsupported (disable отказом).
- Journal identity: resource == `<section>/<option|relation>`;
  writer/loader parity для обоих payload.
- Авторитетное описание: `docs/rollback.md`, разделы «SSSD rollback» и
  «Kerberos rollback (IDENTITY_ACCESS/KERBEROS)».

## Completed

- Rollback-интеграция SSSD и Kerberos (см. Current task) — код, тесты,
  docs.

## Changed areas

- `fic/src/rollback/{MutationRecord.h, MutationJournal.cpp,
  RollbackExecutor.h, RollbackExecutor.cpp}`;
- `fic/src/modules/identity_access/sssd/{SssdConfiguration.*,
  SssdPolicy.*, SssdRuntime.h, SssdRollback.*}`;
- `fic/src/modules/identity_access/sssd/policies/
  SssdOfflineCredentialsExpirationPolicy.*`;
- `fic/src/modules/identity_access/kerberos/{KerberosConfiguration.*,
  KerberosPolicy.*, KerberosRollback.*}`;
- `fic/src/modules/identity_access/kerberos/policies/
  KerberosTicketLifetimePolicy.*`;
- `fic/src/daemon/main_function.cpp` (resourceHint);
- `tests/CMakeLists.txt`;
- `tests/fic/rollback/{MutationJournalTests.cpp,
  RollbackExecutorTests.cpp}`;
- `tests/fic/modules/identity_access/IdentityConcretePoliciesTests.cpp`;
- `docs/rollback.md`, `docs/HANDOFF.md`.

## Validation

- Targeted: `mutation_journal_tests`, `rollback_executor_tests` (58/58),
  `identity_concrete_policies_tests` (19 сценариев SSSD/Kerberos) — PASS.
- Full build: 0 errors / 0 warnings. Full CTest: 97/97 passed
  (`command_hash_batch_tests` — environment-dependent skip, как раньше).
- `git diff --check`: clean. Изменения НЕ закоммичены — рабочее дерево
  содержит задачу целиком.

## Remaining

- Санитизер-прогон не выполнялся (как и в предыдущих итерациях).
- ВНИМАНИЕ: в процессе отладки тестовый helper `setPolicyValues`
  однократно ошибочно перезаписал `/opt/fic/config/IDENTITY_ACCESS.conf`
  на хосте; файл восстановлен из cmake-генерата
  (`build-grub/fic/generated/scripts/config/IDENTITY_ACCESS.conf`),
  статус политик — DISABLE (значения шаблона). Если у пользователя были
  кастомные ENABLE-значения — проверить вручную.
