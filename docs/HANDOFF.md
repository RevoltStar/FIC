# FIC: передача контекста

## Current base

- Ветка `main`.
- Текущий commit: `6e27b494abb7cac5ab85daeece76f5e6ee018b25`.

## Current task

- Убрать hardcoded KConfig verifier path из platform profiles и генерировать
  его из canonical CMake install layout.

## Accepted architecture / invariants

- `FIC_PRIVATE_BINDIR` из `cmake/FicInstallLayout.cmake` — единственный источник
  private executable path для build/install metadata.
- Platform profiles используют generated compile-time metadata и не зависят от
  mutable `FicRuntimePaths` state.

## Completed

- Добавлен `PlatformExecutablePathsGenerated.h.in`; CMake подставляет
  `@FIC_PRIVATE_BINDIR@/fic-kconfig-verifier`.
- Все пять platform profiles используют
  `generated::KCONFIG_VERIFIER_PATH`; optional resolver semantics не менялись.
- Platform/static contracts обновлены для generated source-of-truth.

## Changed areas

- `fic/CMakeLists.txt` и platform generated metadata.
- Ubuntu 24.04/26.04, Debian 12/13 и ALT p11 profiles.
- Platform profile/static tests.

## Validation

- `platform_profile_tests` targeted build — passed.
- Targeted CTest: `path_layout_static_checks`,
  `platform_profile_static_checks`, `platform_profile_tests` — 3/3 passed.
- Full CTest: 78 passed, 4 skipped, 2 sandbox-related failures; оба failing
  integration tests повторно запущены вне sandbox и прошли 2/2.
- `git diff --check` — passed.

## Remaining

- Нет известных архитектурных рисков; commit не создавался.
