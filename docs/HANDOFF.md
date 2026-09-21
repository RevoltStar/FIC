# FIC: передача контекста

## Current base

- Ветка `main`, HEAD `2be63d7f7963affae1040c1fa44b3eee1ef8b22c`, изменения
  поверх него коммитом не зафиксированы.

## Current task

- Узкий follow-up hardening Debian/Ubuntu permanent PAM hook lifecycle:
  строгий stop-proof в `prerm remove`, witness-aware read-only journal
  proof в pre-attach валидаторе, ужесточение journal identity proof.

## Accepted architecture / invariants

- **prerm remove**: `systemctl disable --now` (best-effort) всех FIC
  сервисов + bounded wait, затем обязательный финальный строгий
  `systemctl is-active` proof на каждый unit (`fic.service`,
  `fic-device.service`, `fic-notify.service`) БЕЗ `|| true`. Если unit
  всё ещё active — diagnostic с именем unit + `exit 1`;
  `pam-auth-update --package --remove` НЕ вызывается, hooks остаются
  подключёнными. Timeout остановки = failure удаления пакета, а не
  разрешение продолжать.
- **Journal persistent-state proof**: новый read-only API
  `MutationJournal::validatePersistentStateReadOnly()` — та же
  witness-aware state table, что и `initializeOrLoad()`, те же security
  checks, но НОЛЬ файловых мутаций (без bootstrap/witness creation/
  migration/repair). State table:
  - J missing + W missing (virgin) → FAIL;
  - J missing + W valid → FAIL (provenance loss);
  - J missing + W invalid → FAIL (anomaly);
  - J valid + W missing → **FAIL CLOSED** (pending migration: runtime
    принимает это состояние только записью witness; выбранное поведение —
    fail closed, миграцию завершать нормальным daemon lifecycle, из
    postinst witness не создаётся);
  - J valid + W invalid → FAIL (anomaly);
  - J valid + W valid → строгая загрузка, records доступны для proof.
- **Journal ownership proof** (active slots): exact mutation id, active
  status (`Prepared`/`Applied`/`RollbackFailed`; `RolledBack` FAIL),
  backend=PAM, capability=`enable_authentication_lockout`, topology
  `PamAuthUpdate`, exact activation domain текущего профиля, exact policy
  identity (`IDENTITY_ACCESS`/`PAM`/`enable_authentication_lockout`),
  resource `capability/enable_authentication_lockout` и `targetStrategy`
  == exact физическая стратегия слотов (`status.activeStrategy`,
  каноническое имя из `pamFaillockStrategyName`). Плохая стратегия
  (физическая `preauth_required` vs journal `authsucc`) — FAIL.
- Валидатор строго read-only: не создаёт/не правит journal и witness,
  не трогает slots, не запускает pam-auth-update, не делает rollback.
  Journal/witness логика централизована в `MutationJournal` (parser не
  дублируется в валидаторе).
- Production writer journal отвергает wrong policy identity записи, а
  loader их не загружает — wrong-identity сценарии в тестах покрыты
  прямыми schema-shaped JSON фикстурами (fail closed на read-only
  load), не через production `prepareMutation`.

## Completed

- `fic/src/rollback/MutationJournal.{h,cpp}` — read-only
  `validatePersistentStateReadOnly()` + контрактные сценарии в
  `tests/fic/rollback/MutationJournalTests.cpp` (5 новых).
- `fic/src/modules/identity_access/pam/PamSlotAttachValidator.{h,cpp}` —
  witness-aware read-only journal proof вместо raw `load()`; policy
  identity, resource identity и exact `targetStrategy` ==
  `status.activeStrategy` в ownership proof.
- `packaging/deb/build-fic-debian12-deb.sh` — финальный is-active proof
  после bounded wait в prerm remove (unit-имя в диагностике, `exit 1`,
  без `|| true`).
- `tests/fic/modules/identity_access/pam/PamSlotAttachValidatorTests.cpp`
  — новые сценарии: J missing + W valid FAIL, malformed witness FAIL,
  missing witness (pending migration) FAIL + witness не создан, wrong
  module/submodule/policy/resource FAIL, wrong targetStrategy FAIL;
  read-only fingerprint на virgin-FAIL пути.
- `tests/integration/packaging/PamPackagingChecks.py` — статические
  проверки prerm stop-proof и порядка daemon start в postinst;
  поведенческие: prerm timeout path (fake systemctl всегда active +
  fake sleep → non-zero exit, ни одного pam-auth-update, unit в
  diagnostic) и postinst configure tail (fake binaries, PATH только из
  fakes; success: validate → --package → --enable hooks → daemon start;
  failure validator: non-zero, нет pam-auth-update, нет daemon start).
- Документация: `docs/pam-owned-faillock-slots.md` (3 invariants + state
  table + prerm timeout behavior), `packaging/deb/README.md`.

## Changed areas

- `fic/src/rollback/`, `fic/src/modules/identity_access/pam/`;
- `packaging/deb/` (builder + README);
- `tests/fic/rollback/`, `tests/fic/modules/identity_access/pam/`,
  `tests/integration/packaging/PamPackagingChecks.py`;
- `docs/pam-owned-faillock-slots.md`, `docs/HANDOFF.md`.

## Validation

- `cmake --build build-check -j4` (full) — RC 0, 0 warnings/errors.
- `ctest --test-dir build-check -R 'pam_slot_attach_validator_tests|
  mutation_journal_tests|pam_packaging_static_checks'` — 3/3 passed.
- Полный `ctest --test-dir build-check` — 97/98 passed: 1 pre-existing
  skip (`command_hash_batch_tests`), 1 pre-existing failure
  (`passwdqc_config_file_tests` — известное падение окружения,
  воспроизведено на чистом дереве ранее, к этому diff не относится).
- `python3 tests/integration/packaging/PamPackagingChecks.py .` — passed
  (включая новые поведенческие prerm timeout и postinst configure tests).
- `bash -n packaging/deb/build-fic-debian12-deb.sh` — успешно.
- `git diff --check` — успешно.

## Remaining

- Real host apply / настоящий `dpkg`/`apt` lifecycle не выполнялись
  (запрещены validation policy); ordering доказан unit + behavioral
  tests с fakes. Docker-фикстура install→active→remove→reinstall —
  отдельная задача.
- Pre-existing failure `passwdqc_config_file_tests` в окружении —
  отдельная задача.
- Migration contract «existing journal + missing witness» задокументирован
  как fail closed (witness создаёт только daemon lifecycle); если
  понадобится безопасный maintenance-путь миграции из postinst — это
  осознанное расширение, сейчас отсутствует.
