# FIC: передача контекста

## Current base

- Ветка `main`, HEAD `149ea3438d0b6b69da4fc419f64d749d1afdd751`.
- Рабочее дерево содержит незакоммиченные изменения текущей задачи.

## Current task

- SSSD rollback: не закрывать активную provenance при absent managed source,
  если foreign replacement мог остаться под `.fic-removing-*` после crash.

## Accepted architecture / invariants

- `MutationJournal + RollbackExecutor + typed UndoAction` без изменения
  journal payload или автоматического восстановления foreign artifact.
- Absent source означает доказанный release только при отсутствии staging
  artifacts для точного managed path и успешной runtime-реконсиляции.
- Ошибка проверки каталога и найденный artifact — fail closed; ни apply,
  ни disable не переводят запись в `RolledBack`.

## Completed

- Общий `undoSssdManagedSetting()` перед absent-source reconciliation
  проверяет exact managed basename через защищённое перечисление directory fd.
- Regression моделирует failed directory fsync, допустимое post-crash
  состояние с B в staging, journal reopen, retry apply и disable; оба
  сохраняют provenance и не запускают runtime reconciliation.
- Похожий artifact для другого basename не блокирует законный retry.
- Контракт уточнён в `docs/rollback.md`.

## Changed areas

- `fic/src/modules/identity_access/sssd/{SssdConfiguration.{h,cpp},SssdRollback.{h,cpp}}`;
- `tests/fic/modules/identity_access/IdentityConcretePoliciesTests.cpp`;
- `docs/rollback.md`, `docs/HANDOFF.md`.

## Validation

- `cmake --build /tmp/fic-sssd-rollback-build -j4` — PASS.
- `identity_concrete_policies_tests` — PASS.
- Full CTest вне sandbox — 97/97 PASS; `command_hash_batch_tests` — штатный skip.
- `git diff --check` — PASS.

## Remaining

- Native privileged SSSD runtime не запускался (только tests с fake runner).
