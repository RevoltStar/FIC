# FIC: передача контекста

Этот файл хранит актуальный снимок незавершенной работы. Обязательные правила и
границы компонентов находятся в `AGENTS.md`.

## Текущий снимок

- Обновлено: 2026-08-02.
- Ветка: `main`.
- Базовый commit: `c05a8c8` (`Реализация политики
  failed_authentication_enforce_for_root`).
- Текущая задача: SYSCTL-политика отключения Magic SysRq.
- Реализация завершена, изменения рабочей копии не зафиксированы commit.

## Сделано

- Добавлена fixed-policy `SYSCTL/global_kernel_protection`
  `kernel_sysrq_disable`.
- Политика использует существующий `Sysctl` pipeline и устанавливает
  persistent и live-значение `kernel.sysrq = 0`: анализирует effective
  procps-ng конфигурацию, при необходимости обновляет managed-блок FIC в конце
  `/etc/sysctl.conf`, затем пишет и проверяет `/proc/sys/kernel/sysrq`.
- Политика зарегистрирована в `PolicyMap`; начальный статус — `DISABLE`,
  служебное fixed-значение в seed-конфиге — `ENABLE`.
- В RU/EN descriptions явно указано ограничение: при наличии параметра ядра
  `sysrq_always_enabled` политика не имеет эффекта. Наличие этого
  предупреждения и контракт `kernel.sysrq = 0` закреплены static checks.
- Обновлены README и архитектурная диаграмма.

## Измененные файлы

- `fic/src/modules/sysctl/submodules/globalkernelprotection/`
  `SYSCTL_sysrq_disable.{h,cpp}`;
- `fic/src/core/main_function.{h,cpp}`;
- `fic/src/scripts/config/SYSCTL.conf`;
- `fic/src/scripts/lang/{ru,en}.lang`;
- `tests/platform/static_checks.py`;
- `fic/README.md`;
- `docs/architecture-diagrams.md`;
- `docs/HANDOFF.md`.

## Выполненные проверки

- Конфигурация `build-check` с профилем `alt-p11` и версией `2.0.0-dev` —
  успешно.
- Сборка целей `fic` и `sysctl_configuration_tests` — успешно.
- Целевые `platform_profile_static_checks` и
  `sysctl_configuration_tests` — успешно.
- `ctest --test-dir build-check --output-on-failure`: 27 из 27 без ошибок;
  host-dependent `ipc_transport_tests`, `admin_socket_tests` и
  `command_hash_batch_tests` корректно SKIP.
- `python3 tests/platform/static_checks.py .` — успешно.
- `git diff --check` — успешно.
- Реальный `/etc/sysctl.conf` и `/proc/sys/kernel/sysrq` не изменялись; тесты
  общего sysctl runtime используют временное дерево под `/tmp`.

## Что осталось

- Обязательной незавершенной работы по реализации нет.
- При необходимости runtime-валидации выполнить policy apply в изолированной
  VM и отдельно проверить ядро с параметром загрузки `sysrq_always_enabled`.

## Риски и решения

- `sysrq_always_enabled` имеет более высокий семантический приоритет: даже
  подтвержденное значение `kernel.sysrq = 0` не отключает Magic SysRq. По
  требованию задачи политика сообщает об этом в description, но не анализирует
  командную строку ядра и не меняет bootloader.
- Если `/proc/sys/kernel/sysrq` отсутствует, недоступен для безопасной записи
  или не возвращает `0` после записи, общий `Sysctl` pipeline завершает
  применение ошибкой. Persistent managed-значение при runtime-ошибке может
  остаться подготовленным — это существующий задокументированный контракт
  SYSCTL-политик.
- `status=DISABLE` прекращает управление и не удаляет ранее записанную строку
  из managed-блока, что соответствует общей семантике FIC.
- Формат policy-конфигурации и IPC не изменились; schema/API версии не
  увеличивались, migration и compatibility aliases не добавлялись.
