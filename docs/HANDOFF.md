# FIC: передача контекста

Этот файл хранит актуальный снимок незавершенной работы. Обязательные правила и
границы компонентов находятся в `AGENTS.md`.

## Текущий снимок

- Обновлено: 2026-08-02.
- Ветка: `main`.
- Базовый commit: `268b147cf3b7cfec9b1e56f7f74a0a7a352e8663`.
- Текущая задача: PAM-политика применения истории паролей для root.
- Реализация завершена, изменения рабочей копии не зафиксированы commit.

## Сделано

- Добавлена политика `IDENTITY_ACCESS/PAM`
  `password_history_enforce_for_root`, управляющая беззначным флагом
  `enforce_for_root` активного `pam_pwhistory`.
- Значение политики — `yes` или `no`, default — `yes`, начальный статус —
  `DISABLE`. `yes` добавляет флаг в канонический `pwhistory.conf`, `no` удаляет
  все его активные определения.
- `PamOptionPolicy` расширен typed-режимом `Assignment`/`Flag`, поэтому status
  политики остаётся состоянием управления FIC, а значение `no` является
  явным требованием удалить флаг.
- `PamOptionFile` безопасно читает, добавляет и удаляет valueless flags,
  сохраняет соседние assignments и комментарии, отказывает на malformed
  формах вроде `enforce_for_root=yes`, использует существующую атомарную запись
  и rollback при непрошедшей postcondition.
- `PamProviderInspector` проверяет flag overrides: альтернативный `conf=` и
  valued flag отклоняются; bare-аргумент `enforce_for_root` совместим с `yes`,
  но блокирует применение `no` до записи.
- Политика зарегистрирована в `PolicyMap`; добавлены seed-конфиг, RU/EN
  локализации, README, архитектурная диаграмма и static checks.
- Добавлены unit-тесты flag parser/editor/override и end-to-end тест применения
  `yes`, затем `no` на временном PAM-дереве.

## Измененные файлы

- `fic/src/modules/identity_access/submodules/pam/policies/`
  `PamPasswordHistoryEnforceForRootPolicy.{h,cpp}`;
- `fic/src/modules/identity_access/submodules/pam/PamOptionFile.{h,cpp}`;
- `fic/src/modules/identity_access/submodules/pam/PamOptionPolicy.{h,cpp}`;
- `fic/src/modules/identity_access/submodules/pam/PamProviderInspector.{h,cpp}`;
- `fic/src/core/main_function.{h,cpp}`;
- `fic/src/scripts/config/IDENTITY_ACCESS.conf`;
- `fic/src/scripts/lang/{ru,en}.lang`;
- `tests/CMakeLists.txt`;
- `tests/identity_access/PamConfigurationTests.cpp`;
- `tests/identity_access/IdentityPolicyHierarchyTests.cpp`;
- `tests/platform/static_checks.py`;
- `fic/README.md`, `docs/architecture-diagrams.md`, `docs/HANDOFF.md`.

## Выполненные проверки

- Конфигурация профиля ALT p11:
  `cmake -S . -B build-check -DFIC_TARGET_PLATFORM=alt-p11
  -DFIC_PRODUCT_VERSION=2.0.0-dev` — успешно.
- Сборка целей `fic`, `pam_configuration_tests` и
  `identity_policy_hierarchy_tests` — успешно.
- `ctest --test-dir build-check --output-on-failure`: 27 из 27 без ошибок;
  host-dependent `ipc_transport_tests`, `admin_socket_tests` и
  `command_hash_batch_tests` корректно SKIP.
- `python3 tests/platform/static_checks.py .` — успешно.
- `git diff --check` — успешно.
- Реальный PAM apply и изменение `/etc/security/pwhistory.conf` не выполнялись:
  тесты используют только временное PAM-дерево под `/tmp`.

## Что осталось

- Обязательной незавершенной работы по реализации нет.
- При необходимости отдельной runtime-валидации проверить в изолированной VM
  каждого поддерживаемого профиля реальную смену пароля root с повторным
  использованием предыдущего пароля при `yes` и `no`.

## Риски и решения

- Политика не включает и не мигрирует provider: `pam_pwhistory` должен уже быть
  корректно и единообразно включен во всех существующих password-службах.
  `pam_unix remember=`, другой `conf=` или небезопасные provider/config файлы
  приводят к fail-closed отказу.
- Если bare-флаг `enforce_for_root` задан прямо в аргументах
  `pam_pwhistory.so`, значение `no` не может его перекрыть и намеренно
  отклоняется без изменения канонического файла.
- `status=DISABLE` не означает значение `no`: disable прекращает управление и
  не откатывает ранее записанный флаг, что соответствует общей семантике FIC.
- Формат policy-конфигурации и IPC не изменились; schema/API версии не
  увеличивались, migration и compatibility aliases не добавлялись.
