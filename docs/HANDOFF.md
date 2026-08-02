# FIC: передача контекста

Этот файл хранит актуальный снимок незавершенной работы. Обязательные правила и
границы компонентов находятся в `AGENTS.md`.

## Текущий снимок

- Обновлено: 2026-08-02.
- Ветка: `main`.
- Базовый commit: `8443065e33b7f7688d81c1f860c71a70ddc2ffc1`.
- Текущая задача: PAM-политика периода подсчёта неуспешных аутентификаций.
- Реализация завершена, изменения рабочей копии не зафиксированы commit.

## Сделано

- Добавлена политика `IDENTITY_ACCESS/PAM`
  `failed_authentication_counting_period`, которая управляет параметром
  `fail_interval` активного `pam_faillock` через существующий
  `PamOptionPolicy`.
- Значение задаётся в секундах, допустимый диапазон — `1..86400`, значение по
  умолчанию — `900`, начальный статус — `DISABLE`.
- Политика использует существующий fail-closed preflight: проверяет effective
  PAM-граф, полную topology `pam_faillock`, владельца и права provider/config
  файлов, канонический `faillock.conf` и конфликтующие аргументы
  `fail_interval=` в PAM-правилах.
- Политика зарегистрирована в `PolicyMap`; добавлены seed-конфиг, русская и
  английская локализации, README и архитектурная диаграмма.
- Тесты проверяют metadata/default/range политики, конфликтующий и совпадающий
  PAM override, обновление повторных `fail_interval` и сохранение связанных
  `deny`/`unlock_time` и комментариев.

## Измененные файлы

- `fic/src/modules/identity_access/submodules/pam/policies/`
  `PamFailedAuthenticationCountingPeriodPolicy.{h,cpp}`;
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
- Реальный PAM apply и изменение `/etc/security/faillock.conf` не выполнялись:
  такие проверки изменяют состояние хоста и должны запускаться только в
  изолированном тестовом окружении.

## Что осталось

- Обязательной незавершенной работы по реализации нет.
- При необходимости отдельной runtime-валидации проверить в VM каждого
  поддерживаемого профиля, что ошибки вне малого тестового `fail_interval` не
  достигают `deny`, а порог ошибок внутри окна приводит к блокировке; после
  проверки сбросить test tally через `faillock --reset`.

## Риски и решения

- Политика не включает и не мигрирует PAM provider: `pam_faillock` должен уже
  быть корректно и единообразно включен во всех существующих целевых службах.
  `pam_tally`/`pam_tally2`, неполная topology или конфликтующий аргумент
  `fail_interval=` приводят к отказу до записи.
- Изменение `fail_interval` намеренно не сбрасывает существующие tally-записи;
  их возраст интерпретирует сам `pam_faillock` при последующих аутентификациях.
- Отключение политики останавливает последующее принудительное применение, но
  не откатывает уже записанный `fail_interval`, что соответствует текущей
  общей семантике disable в FIC.
- Формат policy-конфигурации и IPC не изменились; schema/API версии не
  увеличивались, migration и compatibility aliases не добавлялись.
