# FIC: передача контекста

## Current base

- Ветка: `main`.
- Закоммичено: `1d3937b` (target-specific DAC contracts для
  provider-managed symlink targets).
- Незакоммиченная правка поверх `1d3937b`: только
  `tests/fic/modules/dac/ModeAndOwnerTests.cpp`.

## Current task

- Test-only follow-up: ключевой regression для target-specific DAC contract
  сделан безусловным (mode-based, без root и без `systemd-resolve`).

## Accepted architecture / invariants

- Все инварианты предыдущей задачи (см. commit `1d3937b`) сохранены;
  production-код в этой правке не менялся.

## Completed

- В `ModeAndOwnerTests.cpp` добавлен безусловный mode-based regression:
  logical rule `0600` vs provider target contract `0644` при совпадающих
  owner/group (`currentOwner()`/`currentGroup()`). Старая реализация
  (rule-stats для provider target) отклоняет actual `0644`; новая принимает
  без мутации.
- Root-only блок с `systemd-resolve` (owner/group покрытия: другой
  owner/group → SUCCESS, wrong group → FAIL без chgrp, stricter mode,
  не-regular target) сохранён без изменений как дополнительное покрытие.
- Проверено на симулированной старой реализации (временная подстановка
  rule-permissions в provider path): regression падает с «expected maximum
  mode 0600, actual 0644»; после отката временной правки — проходит.
  Временных изменений в git не осталось.

## Changed areas

- `tests/fic/modules/dac/ModeAndOwnerTests.cpp`.

## Validation

- `mode_and_owner_tests`: build ok, exit 0 при non-root запуске
  (uid доменного пользователя, `systemd-resolve` на хосте отсутствует —
  `getent` exit 2), новый regression выполняется и проходит.
- Full build `/tmp/fic-dev-build`: success; full CTest: 73/73 passed.
- `tests/fic/platform/static_checks.py`, `tests/common/static_checks.py`:
  exit 0. `git diff --check`: clean.
- Build по-прежнему использует stub libsystemd в `/tmp/fic-dev-tree/*`
  (вне git, `PKG_CONFIG_PATH=/tmp/fic-dev-tree/pkgconfig`).

## Remaining

- Не проверялось: запуск под root/на дистро с `systemd-resolve`
  (root-only покрытия остались под `geteuid()==0` guards).
- Коммит не создавать без отдельного явного запроса пользователя.

