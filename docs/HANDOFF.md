# FIC: передача контекста

## Current base

- Ветка `main`, базовый commit `c1d1601`.
- Изменения текущей GRUB-задачи находятся в рабочем дереве и не закоммичены.

## Current task

- Разделить GRUB topology: Debian/Ubuntu используют FIC-owned
  `/etc/default/grub.d/zzzz-fic.cfg`, ALT p11 сохраняет shared
  `/etc/sysconfig/grub2`.

## Accepted architecture / invariants

- `GrubPlatformConfig` явно задаёт `OwnedDefaultsDropIn` либо
  `SharedDefaultsFile`; topology не выводится из пустых path.
- Debian/Ubuntu больше не изменяют `/etc/default/grub`. `GrubManagedConfig`
  владеет всем `zzzz-fic.cfg`, принимает только три GRUB key и fail closed на
  неизвестном, duplicate, malformed или dynamic shell-содержимом.
- Перед mutation проверяются безопасная topology и отсутствие видимого
  применимого `*.cfg`, идущего после `zzzz-fic.cfg` в C-locale byte order.
- Idempotent apply не переписывает source-файл, но всегда запускает rebuild.
- После неуспешного rebuild исходный managed-файл восстанавливается (или новый
  удаляется), затем запускается compensating rebuild; DISABLE cleanup не
  добавлен.
- ALT сохраняет текущие `/etc/sysconfig/grub2` и
  `grub-mkconfig -o /etc/grub.cfg`: локальный builder не содержит GRUB tooling,
  поэтому изменение этого distro contract без native ALT evidence не принято.

## Completed

- Добавлены явный platform topology и строгий `GrubManagedConfig` на базе
  `ConfigFileHandler`/`AtomicFileWriter`.
- Сохранён существующий shared-file parser/editor ALT.
- Добавлены проверки ownership/mode/type/parent directories, symlink,
  concurrent mutation, canonical quoting и post-write verification.
- Добавлены regression tests для owned CRUD/idempotence, ordering, strict
  parser, escaping, unsafe input/metadata, compensation и ALT shared path.
- Обновлены platform/static contracts и GRUB-документация.

## Changed areas

- `fic/src/modules/oss/grub/`
- `fic/src/platform/` и platform profiles
- `fic-common/fic-core/include/fic/core/config/ConfigFileHandler.h`
- `tests/fic/modules/oss/grub/`, `tests/fic/platform/`, `tests/CMakeLists.txt`
- `fic/README.md`, `docs/architecture-diagrams.md`

## Validation

- Debian 13 clean full build в `fic-deb-builder:debian13`: passed.
- Non-root CTest (`-LE root`, без двух tests, требующих отсутствующий в образе
  `git`): 92/92 passed.
- `path_layout_static_checks` и `release_contract_tests` отдельно на host:
  passed.
- ALT p11 standalone `fic-platform` и `fic` build: passed.
- Targeted `grub_policy_tests`, `platform_profile_tests` и
  `platform_profile_static_checks`: passed.
- `g++ -fsyntax-only` для GRUB implementation/tests: passed.
- `git diff --check`: passed.

## Remaining

- Нужен native ALT p11 integration test, подтверждающий, что штатный
  `grub-mkconfig -o /etc/grub.cfg` с очищенным environment читает
  `/etc/sysconfig/grub2`; в builder GRUB tooling не установлен.
- Реальный GRUB rebuild и изменение host boot configuration намеренно не
  выполнялись.
