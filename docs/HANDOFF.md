# FIC: передача контекста

Этот файл хранит актуальный снимок незавершенной работы. Обязательные правила и
границы компонентов находятся в `AGENTS.md`.

## Текущий снимок

- Обновлено: 2026-08-13.
- Ветка: `main`.
- Базовый commit: `af87518`.
- Текущая задача: устранение baseline-рассинхронов platform profile и release
  contract после добавления третьей цели `systemd-resolved` и Ubuntu 26.04.
- Реализация и проверки завершены; изменения рабочей копии не зафиксированы
  commit.

## Сделано

- `PlatformProfileTests.cpp` теперь ожидает для Debian 12/13 и Ubuntu
  24.04/26.04 все три допустимые цели `/etc/resolv.conf`, включая
  `/usr/lib/systemd/resolv.conf`. Проверка ALT p11 по-прежнему требует пустой
  `allowedFinalSymlinkTargets`.
- Статическая проверка production-профилей также требует третью цель.
- Архитектурная документация синхронизирована с набором из трёх целей
  `systemd-resolved`.
- Release contract, тест и GitHub release gate синхронизированы с матрицей из
  пяти платформ и 25 пакетов.
- В release process добавлена Ubuntu 26.04 и исправлено ожидаемое число
  артефактов с 20 на 25.
- Поиск по исходникам и документации не выявил других legacy assumptions о
  прежнем числе release artifacts или неполном наборе целей `systemd-resolved`.
- FIREWALL-код в рамках задачи не изменялся.

## Основные изменённые файлы

- `tests/platform/PlatformProfileTests.cpp`;
- `tests/platform/static_checks.py`;
- `packaging/release/build-release.sh`;
- `tests/version/release-contract-test.sh`;
- `.github/workflows/release-gate.yml`;
- `docs/architecture-diagrams.md`;
- `docs/release-process.md`;
- этот файл.

## Выполненные проверки

- `platform_profile_tests` переконфигурирован, собран и успешно выполнен для
  `debian-12`, `debian-13`, `ubuntu-24.04`, `ubuntu-26.04` и `alt-p11`.
- `cmake --build /tmp/fic-firewall-build -j2` — полная сборка успешно.
- `release_contract_tests` — 1/1 passed.
- Полный `ctest --test-dir /tmp/fic-firewall-build --output-on-failure` — 33/33
  без ошибок; `ipc_transport_tests`, `admin_socket_tests` и
  `command_hash_batch_tests` штатно пропущены как host-dependent.
- `git diff --check` — успешно.

## Ограничения и оставшиеся проверки

- Реальные Docker-сборки пяти наборов DEB/RPM не запускались: release contract
  проверен синтетическим тестом, без создания package artifacts.
- CMake при конфигурации выдаёт существующие deprecation warnings для
  `cmake_minimum_required`; ошибок конфигурации или сборки нет.
