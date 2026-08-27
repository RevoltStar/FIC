# FIC: передача контекста

## Current base

- Ветка: `main`.
- Базовый commit задачи: `e1309057f6f8be0401dd7b17e0507fc017623b57`.

## Current task

- Исправление применения `DAC:systemcommandlock` на Debian 13, где штатный
  `/usr/sbin/ip` является symlink на `/usr/bin/ip`.

## Accepted architecture / invariants

- Общая fail-closed обработка policy paths с `O_NOFOLLOW` сохраняется.
- Допустимые конечные symlink targets задаются явно и только в платформенном
  профиле для конкретного policy path.

## Completed

- В Debian 13 profile для `/usr/sbin/ip` разрешён точный target `/usr/bin/ip`.
- Platform profile test закрепляет это правило и полный allowlist проверенных
  command symlink exceptions.

## Changed areas

- `fic/src/platform/profiles/Debian13Profile.cpp`.
- `tests/fic/platform/PlatformProfileTests.cpp`.

## Validation

- Чистая configure для `debian-13` во временном build dir с configure-only
  `libsystemd.pc` stub — успешно.
- `platform_profile_tests` — 1/1 успешно.
- `mode_and_owner_tests` — 1/1 успешно.
- Чистая configure для `ubuntu-26.04` с тем же stub и
  `platform_profile_tests` — 1/1 успешно.
- `git diff --check` — успешно.

## Remaining

- Изменения не закоммичены.
- Новая сборка не развёртывалась на удалённую Debian 13 машину; повторный
  runtime apply не выполнялся.
