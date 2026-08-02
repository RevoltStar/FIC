# FIC: передача контекста

Этот файл хранит актуальный снимок незавершенной работы. Обязательные правила и
границы компонентов находятся в `AGENTS.md`.

## Текущий снимок

- Обновлено: 2026-08-02.
- Ветка: `main`.
- Базовый commit: `5a6571f` (`Добавляем политику
  password_history_enforce_for_root`).
- Текущая задача: PAM-политика блокировки root после неуспешных
  аутентификаций.
- Реализация завершена, изменения рабочей копии не зафиксированы commit.

## Сделано

- Добавлена политика `IDENTITY_ACCESS/PAM`
  `failed_authentication_enforce_for_root`, управляющая беззначным флагом
  `even_deny_root` активного `pam_faillock`.
- Значение политики — `yes` или `no`, default — `yes`, начальный статус —
  `DISABLE`. `yes` добавляет флаг в канонический `faillock.conf`, `no` удаляет
  все его активные определения.
- Политика переиспользует typed-режим `PamOptionPolicy::Flag`, существующую
  атомарную запись, проверку PAM topology/provider и fail-closed обработку
  аргументов, перекрывающих управляемый флаг.
- Учтена семантика `pam_faillock`: `root_unlock_time` сам подразумевает
  `even_deny_root`. При значении `no` активный `root_unlock_time` в
  `faillock.conf` или аргументах PAM считается конфликтом; применение
  отклоняется до записи вместо удаления независимой настройки администратора
  или ложного сообщения об отключенной блокировке root.
- Для этого `PamOptionPolicy`, `PamOptionFile` и `PamProviderInspector`
  расширены общим списком options, конфликтующих с disabled-состоянием флага.
- Политика зарегистрирована в `PolicyMap`; добавлены seed-конфиг, RU/EN
  локализации, README, архитектурная диаграмма и static checks.
- Добавлены unit-тесты конфликтов `root_unlock_time` в конфиге/аргументах PAM
  и end-to-end тесты применения `yes`, затем `no`, включая fail-closed случай.

## Измененные файлы

- `fic/src/modules/identity_access/submodules/pam/policies/`
  `PamFailedAuthenticationEnforceForRootPolicy.{h,cpp}`;
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

- Сборка целей `fic`, `pam_configuration_tests` и
  `identity_policy_hierarchy_tests` в существующем `build-check` с профилем
  `alt-p11` — успешно.
- `ctest --test-dir build-check --output-on-failure`: 27 из 27 без ошибок;
  host-dependent `ipc_transport_tests`, `admin_socket_tests` и
  `command_hash_batch_tests` корректно SKIP.
- `python3 tests/platform/static_checks.py .` — успешно.
- `git diff --check` — успешно.
- Реальный PAM apply, аутентификация root и изменение
  `/etc/security/faillock.conf` не выполнялись: тесты используют только
  временные PAM-деревья под `/tmp`.

## Что осталось

- Обязательной незавершенной работы по реализации нет.
- При необходимости runtime-валидации проверить в изолированной VM каждого
  поддерживаемого профиля накопление ошибок и блокировку root при `yes`, а
  также отсутствие блокировки при `no`.

## Риски и решения

- Политика не включает и не мигрирует provider: `pam_faillock` должен уже быть
  корректно и единообразно включен во всех существующих authentication-
  службах. Другой provider, альтернативный `conf=` или небезопасные
  provider/config файлы приводят к fail-closed отказу.
- При значении `no` прямой PAM-аргумент `even_deny_root` и параметр
  `root_unlock_time` не удаляются автоматически и блокируют применение.
- `status=DISABLE` не означает значение `no`: disable прекращает управление и
  не откатывает ранее записанный флаг, что соответствует общей семантике FIC.
- Политика управляет применением существующих `deny`, `fail_interval` и
  `unlock_time` к root, но не включает сами политики порога и длительности.
- Формат policy-конфигурации и IPC не изменились; schema/API версии не
  увеличивались, migration и compatibility aliases не добавлялись.
