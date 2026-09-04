# FIC: передача контекста

## Current base

- Ветка: `main`.
- Родитель текущей правки: `21a8efb`.

## Current task

- Не позволять built-in DAC file policies расширять существующие permissions.

## Accepted architecture / invariants

- `ModeEnforcement` выбирается явно: built-in правила используют
  `MaximumAllowed`, custom policy — `Exact`.
- Maximum-mode применяется ко всей маске `07777`, включая SUID/SGID/sticky.
- Owner/group остаются exact и проверяются после descriptor-based mutation.

## Completed

- Built-in compliance означает `(actual & ~allowed) == 0`.
- Remediation применяет `actual & allowed`, только удаляя лишние bits.
- Более строгие modes и отсутствующие разрешённые special bits не изменяются;
  custom mode по-прежнему приводится к точному значению.

## Changed areas

- `fic/src/modules/dac/mode_and_owner`: explicit mode semantics.
- Обе built-in ModeAndOwner policies и RU/EN restriction text.
- `ModeAndOwnerTests` и архитектурная документация.

## Validation

- ALT p11 builder container: `mode_and_owner_tests` built and passed для всех
  пяти target profiles: Debian 12/13, Ubuntu 24.04/26.04, ALT p11.
- Покрыты tightening, already-stricter, group/other bits, SUID/SGID, owner/group,
  `systemcommandlock` и custom exact semantics.

## Remaining

- Host CMake по-прежнему не имеет `libsystemd`; validation выполнена в
  изолированном ALT builder image.
- После этого коммита остаются задачи 4-6 из пользовательского списка.
