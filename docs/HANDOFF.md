# FIC: передача контекста

## Current base

- Ветка `main`, HEAD `1ec0f1ca536fdbfc84401ffb668cb70b7114c232`, изменения
  поверх него коммитом не зафиксированы.

## Current task

- Узкий hardening Debian/Ubuntu package lifecycle permanent PAM hooks при
  remove/reinstall (без перестройки PAM architecture, без изменений ALT
  backend и без возврата legacy `pam-auth-update` ownership).

## Accepted architecture / invariants

- Package removal first stops all FIC PAM writers and only then detaches
  permanent hooks; package installation/reinstallation never attaches
  permanent hooks until existing FIC slot state is proven canonical-neutral
  or journal-bound owned state.
- `prerm remove`: `systemctl disable --now` всех FIC сервисов + ожидание
  неактивности ДО `pam-auth-update --package --remove`. Upgrade semantics не
  изменены (блок исполняется только для `remove`).
- `postinst configure`: read-only
  `fic --maintenance validate-pam-slots-before-attach` выполняется ДО
  `pam-auth-update --package` и ДО `pam-auth-update --enable
  fic-faillock-hook-*`; при FAIL — `exit 1` до подключения hooks и до старта
  daemon, без «починки»/удаления слотов.
- Валидатор (`PamSlotAttachValidator`) строго read-only: не переписывает
  slots, не создаёт/не мутирует journal (raw `load()`, не
  `initializeOrLoad`), не запускает `pam-auth-update`, не делает rollback.
  PASS = canonical neutral все четыре слота ИЛИ полный consistent active
  topology + journal record (`Prepared`/`Applied`/`RollbackFailed`) с exact
  mutation id, backend=PAM, capability=`enable_authentication_lockout`,
  topology=PamAuthUpdate, activation domain == текущему платформенному
  домену (`activationIdentifiers`). Всё остальное — fail closed.
- Классификация slots не дублируется: валидатор переиспользует публичный
  `PamAuthUpdateTopologyManager::inspect()` (managed-slot grammar остаётся
  в topology manager).
- Permanent hook selection остаётся package infrastructure; policy владеет
  только strict `/etc/pam.d/fic-faillock-*` slots.

## Completed

- `fic/src/modules/identity_access/pam/PamSlotAttachValidator.{h,cpp}` —
  read-only pre-attach validation (верdict safe/unsafe + detail).
- `fic/src/main.cpp` — maintenance-команда
  `validate-pam-slots-before-attach` (root-only, печатает `safe to attach`
  либо fail-closed диагностик, exit 1).
- `packaging/deb/build-fic-debian12-deb.sh` — reorder prerm remove (stop →
  remove) и pre-attach validation в postinst configure (до обоих
  pam-auth-update вызовов, с понятным сообщением и `exit 1`).
- `tests/fic/modules/identity_access/pam/PamSlotAttachValidatorTests.cpp`
  (16 сценариев: fresh neutral PASS, neutral+empty journal PASS, active+exact
  journal PASS (Applied и Prepared), active без journal FAIL, active+пустой
  journal FAIL, wrong mutation id FAIL, RolledBack FAIL, foreign
  capability/domain/backend FAIL, mixed ids FAIL, partial strategy FAIL,
  missing slot FAIL, malformed marker FAIL, modified body FAIL, read-only
  byte-for-byte на PASS и FAIL) + регистрация `pam_slot_attach_validator_tests`
  в `tests/CMakeLists.txt`.
- `tests/integration/packaging/PamPackagingChecks.py` — структурные регрессии
  ordering (prerm stop-before-remove, postinst validate-before-attach, валидация
  внутри configure-ветки, `exit 1` при FAIL) и поведенческая регрессия:
  сгенерированный prerm запускается с fake `systemctl`/`pam-auth-update` и
  реально проверяется порядок вызовов.
- Документация: `docs/pam-owned-faillock-slots.md` (новый раздел Package
  lifecycle invariants, включая reinstall с сохранёнными conffiles),
  `packaging/deb/README.md` (pre-attach validation + remove ordering).

## Changed areas

- `fic/src/main.cpp`, `fic/src/modules/identity_access/pam/`;
- `packaging/deb/` (builder + README);
- `tests/fic/modules/identity_access/pam/`, `tests/CMakeLists.txt`,
  `tests/integration/packaging/PamPackagingChecks.py`;
- `docs/pam-owned-faillock-slots.md`, `docs/HANDOFF.md`.

## Validation

- `cmake -S . -B build-check -DFIC_TARGET_PLATFORM=ubuntu-24.04` — успешно.
- Полный `cmake --build build-check -j4` — RC 0, 0 warnings/errors.
- Полный `ctest --test-dir build-check --output-on-failure` — 97/98 passed,
  1 pre-existing skip (`command_hash_batch_tests`) и 1 failure
  (`passwdqc_config_file_tests`: «pwquality policy did not retain its
  topology-dependent state»), воспроизведённый на чистом дереве без этого
  diff (git stash + rebuild) — предсуществующее падение окружения, к данной
  задаче отношения не имеет.
- `ctest -R 'pam_slot_attach_validator_tests|pam_auth_update_topology_tests|
  pam_packaging_static_checks|mutation_journal_tests'` — 4/4 passed.
- `python3 tests/integration/packaging/PamPackagingChecks.py .` — passed
  (включая поведенческую prerm-регрессию с fake systemctl/pam-auth-update).
- `bash -n packaging/deb/build-fic-debian12-deb.sh` — успешно.
- `git diff --check` — успешно.

## Remaining

- Real host apply / настоящий `apt install`/`dpkg` lifecycle и живой
  `pam-auth-update` не выполнялись (запрещены validation policy);
  ordering доказан статической + поведенческой регрессией с fakes.
- Integration/shell fixture полного цикла install→active→remove→reinstall с
  настоящим dpkg не создавалась (unit + packaging-регрессии покрывают
  ordering и provenance validation); при необходимости — отдельная задача
  с Docker-окружением.
- Валидатор fail-closed для missing slot conffile (администратор удалил
  conffile): postinst будет падать до ручного восстановления — это
  осознанное fail-closed поведение, задокументировано.
- Предсуществующее падение `passwdqc_config_file_tests` в текущем окружении
  (не связано с этой задачей) — упомянуто для следующего агента.
