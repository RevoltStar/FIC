# FIC: передача контекста

## Current base

- Ветка `main`, HEAD `e41b4e1108e6d3384923d643e270b5e34038331f`.
- Изменения текущей задачи не закоммичены.

## Current task

- Persistent journal-backed rollback для трёх `IDENTITY_ACCESS/PAM` capability activation policies.

## Accepted architecture / invariants

- `MutationJournal + RollbackExecutor + typed UndoDisablePamCapability`; rollback освобождает только доказанную FIC-owned topology, без snapshots PAM-файлов.
- Поддержаны только `enable_authentication_lockout`, `enable_password_history`, `enable_password_quality`. PAM option policies и `StaticVerifyOnly` не получают provenance.
- Prepared пишется до native mutation; structural и durability proof предшествуют Applied. Indeterminate состояние сохраняет активную provenance и fail closed.
- `PamAuthUpdate` отключает только FIC activation identifiers. ALT использует существующие managed topology disable paths; password-history lock order: topology, затем transaction.

## Completed

- Добавлены PAM backend/payload с writer/loader validation и explicit enrollment.
- Apply и rollback интегрированы с журналом; same-value apply не вызывает writer, стратегия faillock меняется с сохранением MutationId.
- Добавлены native ownership/postcondition/durability checks и regression tests, включая отказ journal commit после native mutation.
- Обновлён `docs/rollback.md`.

## Changed areas

- `fic/src/modules/identity_access/pam/`, `fic/src/rollback/`, `fic/src/daemon/main_function.cpp`;
- `tests/fic/modules/identity_access/pam/`, `tests/fic/rollback/`, `tests/CMakeLists.txt`;
- `docs/rollback.md`, `docs/HANDOFF.md`.

## Validation

- `cmake -S . -B /tmp/fic-pam-rollback-build -DFIC_TARGET_PLATFORM=ubuntu-24.04 -DBUILD_TESTING=ON` — PASS.
- `cmake --build /tmp/fic-pam-rollback-build -j2` и повторная сборка затронутых targets — PASS.
- Full non-root CTest вне sandbox: 97/97 без failures; `command_hash_batch_tests` штатно skipped.
- `git diff --check` — PASS.

## Remaining

- Native privileged PAM runtime и multi-platform package/install validation не выполнялись; covered fake/native-manager tests не заменяют такой E2E.
