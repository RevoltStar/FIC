# FIC 2.0: передача контекста

Этот файл хранит актуальный снимок незавершенной работы. Обязательные правила и
границы компонентов находятся в `AGENTS.md`.

## Текущий снимок

- Обновлено: 2026-07-30.
- Ветка: `main`.
- Базовый commit: `110e4b6`.
- Текущая задача: адаптивные ограничения ресурсов для всех package build
  scripts после диагностики зависаний хоста.
- Реализация и локальные проверки завершены, изменения не зафиксированы commit.

## Сделано

- Добавлен общий `packaging/lib/build-resources.sh`:
  - учитывает доступные CPU, `MemAvailable` и cgroup v1/v2 limits;
  - резервирует хосту 2 GiB RAM и один-два CPU;
  - выделяет один C++ job на 2 GiB оставшейся памяти, максимум восемь jobs;
  - поддерживает явный `BUILD_JOBS` и остальные documented overrides;
  - понижает CPU/I/O priority сборочного процесса;
  - формирует совместимые с Podman и Docker CPU/RAM/swap limits.
- Общая политика подключена ко всем 12 скриптам в `packaging/deb/` и
  `packaging/rpm/`, включая legacy Debian 10/11, поддерживаемые Debian 12/13,
  Ubuntu 24.04 и ALT p11.
- Все CMake package builders теперь передают явное
  `--parallel "$BUILD_JOBS"`.
- Все container wrappers:
  - ограничивают CPU и RAM как image build, так и package container;
  - по умолчанию задают равные memory и memory-plus-swap limits, поэтому
    container swap равен нулю;
  - передают рассчитанный `BUILD_JOBS` внутрь контейнера.
- Добавлены `.containerignore` и `.dockerignore`, исключающие `.git`, служебные
  каталоги Codex, `build*` и `dist` из build context.
- Добавлен `packaging_build_resource_tests`; platform static checks теперь
  запрещают обход общей политики любым package builder.
- Параметры и overrides документированы в `packaging/deb/README.md` и
  `packaging/rpm/README.md`.

## Выбранные параметры

На хосте с 12 CPU и примерно 8 GiB доступной RAM автоматический расчёт выбрал:

- `BUILD_JOBS=2`;
- `CONTAINER_CPUS=2`;
- container memory около 5.9 GiB;
- container swap `0`;
- nice `10`, best-effort I/O priority `7`.

Значения рассчитываются заново перед каждой сборкой. Для других хостов
parallelism ограничивается минимумом из CPU budget, memory budget и cap 8.

## Выполненные проверки

- `bash -n` для общего helper, всех package scripts и нового теста: успешно.
- `tests/packaging/build-resources-test.sh`: успешно.
- `tests/platform/static_checks.py` и `tests/paths/static_checks.py`: успешно.
- `git diff --check`: успешно.
- Полная конфигурация и сборка:

  ```bash
  cmake -S . -B build-check-resources -DFIC_TARGET_PLATFORM=alt-p11
  cmake --build build-check-resources -j2
  ```

  Все цели собраны успешно.
- `ctest --test-dir build-check-resources --output-on-failure`: 14 тестов,
  12 passed; root-only `admin_socket_tests` и `command_hash_batch_tests`
  штатно skipped.
- Podman image build с рассчитанными flags использовал cache и завершился
  успешно.
- Одноразовый container probe подтвердил:
  - `cpu.max=200000 100000` (2 CPU);
  - `memory.max=6277824512` (5987 MiB);
  - `memory.swap.max=0`.
- `shellcheck` отсутствует на хосте и не запускался.
- Полные `.deb`/`.rpm` package builds не запускались: они тяжёлые, а
  компиляция, image build, resource flags и packaging tests проверены отдельно.

## Что осталось

- При следующей реальной ALT p11 package build проверить отзывчивость рабочего
  стола и сравнить PSI memory/I/O counters до и после сборки.
- Если конкретный CI runner требует иной баланс, задать documented overrides
  (`BUILD_JOBS`, `CONTAINER_CPUS`, `CONTAINER_MEMORY_MB`,
  `CONTAINER_MEMORY_SWAP_MB`) без изменения скриптов.
