# FIC: передача контекста

## Current base

- Ветка `main`, HEAD `ce1c9fee78f68debc97aac9058ef650d3a94952d`.
- Изменения текущей задачи не закоммичены.

## Current task

- Исправление lifecycle recovery и shared-profile ownership в PAM rollback после `ce1c9fe`.

## Accepted architecture / invariants

- `MutationJournal + RollbackExecutor + typed UndoDisablePamCapability`; rollback освобождает только доказанную FIC-owned topology, без snapshots PAM-файлов.
- Поддержаны только `enable_authentication_lockout`, `enable_password_history`, `enable_password_quality`. PAM option policies и `StaticVerifyOnly` не получают provenance.
- Prepared пишется до native mutation; structural и durability proof предшествуют Applied. Indeterminate состояние сохраняет активную provenance и fail closed.
- `PamAuthUpdate` отключает только FIC activation identifiers. ALT использует существующие managed topology disable paths; password-history lock order: topology, затем transaction.
- Prepared strategy transition хранит exact previous/target strategies и previous error; recovery разрешает persisted операцию до сравнения с новым desired.
- Shared distro `pwquality` не доказывает владение именем профиля. Для release нужен durable `confirmed_native_ownership` после собственного writer; intent-only Prepared/RollbackFailed остаётся fail closed.

## Completed

- External/mismatching topology и чистые preflight failures отклоняются до journal prepare.
- Prepared BEFORE/AFTER стратегии восстанавливается по сохранённым A/B независимо от нового desired; exact drift остаётся fail closed.
- `pwquality` с заранее выбранным distro profile — no-op без журнала; FIC activation получает отдельное durable writer confirmation перед Applied.
- ALT password-history Disabled BEFORE proof не требует будущего history storage.
- Добавлены regression tests и обновлён `docs/rollback.md`.

## Changed areas

- `fic/src/modules/identity_access/pam/`, `fic/src/rollback/`, `fic/src/platform/`;
- `tests/fic/modules/identity_access/pam/`, `tests/fic/rollback/`, `tests/fic/platform/`;
- `docs/rollback.md`, `docs/HANDOFF.md`.

## Validation

- `cmake --build /tmp/fic-pam-rollback-build -j2` и повторная сборка затронутых targets — PASS.
- Full non-root CTest вне sandbox: 96 passed, 1 штатный skip (`command_hash_batch_tests`), 0 failures.
- `git diff --check` — PASS.

## Remaining

- Native privileged PAM runtime и multi-platform package/install validation не выполнялись; fake/native-manager tests не заменяют такой E2E.
- Crash после native включения общего `pwquality`, но до durable writer confirmation оставляет intent-only Prepared: автоматический release запрещён из-за невозможности отличить его от admin selection; нужна ручная reconciliation.
