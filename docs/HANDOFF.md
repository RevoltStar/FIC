# FIC: передача контекста

## Current base

- Ветка `main`, HEAD `a329d0bfd297405b963fac920a3746e368b3b117`.
- Изменения текущей задачи не закоммичены.

## Current task

- Устранение ABA-дефекта shared `pwquality` ownership и ужесточение writer/loader parity для PAM strategy provenance.

## Accepted architecture / invariants

- `MutationJournal + RollbackExecutor + typed UndoDisablePamCapability`; rollback освобождает только доказанную FIC-owned topology, без snapshots PAM-файлов.
- Поддержаны только `enable_authentication_lockout`, `enable_password_history`, `enable_password_quality`. PAM option policies и `StaticVerifyOnly` не получают provenance.
- Prepared пишется до native mutation; structural и durability proof предшествуют Applied. Indeterminate состояние сохраняет активную provenance и fail closed.
- Ownership для `PamAuthUpdate` доказывается только FIC-specific activation identifiers. Journal доказывает lifecycle мутации, но не превращает shared distro identifier в FIC-owned resource.
- PasswordQuality на Debian/Ubuntu использует `fic-pwquality`; distro `pwquality` является external compliant topology и никогда не передаётся FIC в `--disable`.
- `PamAuthUpdate` отключает только FIC activation identifiers. ALT использует существующие managed topology disable paths; password-history lock order: topology, затем transaction.
- Prepared strategy transition хранит exact previous/target strategies и previous error; reused transition обязан содержать обе разные стратегии. Один validator применяется writer и loader.
- Старые journal-записи с activation domain `pwquality` не мигрируются в `fic-pwquality`: profile-domain mismatch остаётся fail closed и требует ручной reconciliation.

## Completed

- Добавлен неактивный package profile `/usr/share/pam-configs/fic-pwquality`; maintainer scripts регистрируют/удаляют его вместе с другими FIC profiles, но никогда не активируют автоматически.
- Debian/Ubuntu platform profiles переведены с shared `pwquality` на FIC-owned `fic-pwquality`.
- Удалены `activationOwnershipRequiresJournal`, `confirmedNativeOwnership` и `setJournalProvenance`: shared-profile ownership больше не кодируется journal boolean.
- Rollback PasswordQuality удаляет только exact `fic-pwquality`; disappearance FIC marker + внешний distro `pwquality` трактуется как released FIC topology без мутации внешней selection.
- Добавлены ABA regressions и проверка legacy shared-domain Conflict.
- PAM journal validator отклоняет reused strategy transition без `previousStrategy`; loader и writer используют тот же invariant.
- Обновлены rollback/architecture/packaging docs и platform/packaging static checks.

## Changed areas

- `fic/src/modules/identity_access/pam/`, `fic/src/rollback/`, `fic/src/platform/`;
- `packaging/deb/` и `packaging/deb/pam-configs/`;
- `tests/fic/modules/identity_access/pam/`, `tests/fic/rollback/`, `tests/fic/platform/`, `tests/integration/packaging/`;
- `fic/README.md`, `docs/architecture-diagrams.md`, `docs/rollback.md`, `docs/HANDOFF.md`, `packaging/deb/README.md`.

## Validation

- `cmake --build /tmp/fic-pam-rollback-build -j2` — успешно; затронутые targets также собраны отдельно.
- `ctest --test-dir /tmp/fic-pam-rollback-build --output-on-failure -j2` вне sandbox — 97/97 без failures, один штатный skip (`command_hash_batch_tests`). В sandbox два unrelated integration tests не прошли из-за ограничений окружения; вне sandbox оба прошли.
- `python3 tests/integration/packaging/PamPackagingChecks.py .` — успешно; `git diff --check` — успешно.
- Отдельно нужен Debian/Ubuntu package/install test с реальным `pam-auth-update` для сценариев distro `pwquality`, FIC `fic-pwquality` и ABA replacement.

## Remaining

- Native privileged PAM runtime и multi-platform package/install validation должны быть выполнены после применения патча.
- Старые активные journal-записи PasswordQuality с `activation_identifiers=["pwquality"]` намеренно требуют ручной reconciliation; автоматическое преобразование в `fic-pwquality` запрещено.
