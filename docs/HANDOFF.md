# FIC: передача контекста

## Current base

- Ветка: `main`.
- Родитель текущей правки: `42b1609`.

## Current task

- Покрыть реальное ALT p11 TCB credential storage политикой DAC.

## Accepted architecture / invariants

- TCB topology задаётся typed metadata только в ALT p11 profile.
- Каталоги пользователей обнаруживаются динамически; recursive chmod запрещён.
- Сначала открывается и проверяется вся topology, затем применяются изменения
  через pinned descriptors; symlink, hardlink, неизвестные объекты и races
  приводят к fail-closed результату.
- Access bits не расширяются; SGID account directory обязателен для TCB runtime.

## Completed

- Подтверждена реальная ALT p11 topology: `/etc/tcb` `root:shadow 0710`,
  account dirs `<account>:auth 2710`, `shadow`/`shadow-` `0640`,
  `shadow.lock` `0600`; backup/lock files optional.
- Политика охватывает существующие и новые account directories.
- Исправлена legacy `/etc/shadow` metadata ALT: `root:root 0400`.

## Changed areas

- ALT DAC profile metadata и profile validation.
- Descriptor-safe TCB topology handling в built-in file policy.
- Общий `ModeAndOwner` hook для дополнительных уже открытых правил.
- Mode/profile tests и архитектурная документация.

## Validation

- ALT builder: `mode_and_owner_tests` — passed прямым запуском (образ не
  содержит `ctest`).
- `platform_profile_tests` — passed для Debian 12/13, Ubuntu 24.04/26.04 и
  ALT p11; ALT target `fic` built successfully.
- Покрыты отсутствующие optional entries, новый account, stricter mode,
  owner/mode remediation, missing required file, symlink и hardlink rejection.
- Реальный ALT p11 package/container experiment выполнен с `useradd` и сменой
  пароля; metadata подтверждена до реализации.

## Remaining

- После этого коммита остаётся задача 6 из пользовательского списка.
