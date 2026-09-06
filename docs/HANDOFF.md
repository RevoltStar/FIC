# FIC: передача контекста

## Current base

- Ветка: `main`.
- Родитель текущей правки: `1fa3665`.

## Current task

- Добавить локальные Git hooks и GitHub CI для fast/full developer checks.

## Accepted architecture / invariants

- CTest labels являются единственным контрактом классификации тестов:
  `unit`, `static`, `integration`, `root`.
- `pre-commit` запускает `unit|static`; `pre-push` и основной CI запускают весь
  non-root suite.
- Локальный reusable build directory не конфигурируется hooks автоматически.
- Required GitHub status check для branch protection: `build-and-test`.

## Completed

- Добавлены `.githooks/pre-commit`, `.githooks/pre-push`, общий runner и
  идемпотентный setup script для `core.hooksPath`.
- Все 72 CTest размечены: 49 unit, 15 static, 8 integration; единственный
  root-only test также имеет label integration.
- Добавлен CI для clean configure, полного non-root build/test, compiler
  warnings и ASan/UBSan unit tests.
- Исправлен устаревший GUI source-text check, ожидавший старое имя аргумента.
- README дополнен краткой секцией `Development checks`.

## Changed areas

- `.githooks/`, `scripts/`, `.github/workflows/ci.yml`.
- `tests/CMakeLists.txt` и один GUI static check.
- `README.md`.

## Validation

- Fresh Ubuntu 24.04 configure и full build: passed.
- Hook runner `fast`: 64/64 passed.
- Hook runner `full`: 71/71 non-root tests passed.
- Warning-enabled full build: passed; существующие warnings не превращены в
  `-Werror`.
- ASan/UBSan full build и 49/49 unit tests со строгими runtime options: passed.
- `bash -n`: passed; PyYAML workflow parse: passed.
- Setup script проверен из вложенного каталога; local Git config восстановлен.

## Remaining

- Root-only `command_hash_batch_tests` намеренно не запускается hooks/обычным CI.
- `shellcheck` и `actionlint` в текущем окружении отсутствуют.
- Для локальной сборки использован pkg-config stub libsystemd: development
  package отсутствует на host; CI устанавливает `libsystemd-dev` явно.
- Администратор репозитория должен включить `build-and-test` как required check
  в branch protection для `main`.
